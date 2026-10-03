//! A cap on the upstream connections a node holds open.
//!
//! The cap is enforced where connections are made: a connector wrapper that
//! refuses to open one more connection than allowed, and counts every
//! connection for as long as its socket lives. Requests that find a pooled
//! connection are unaffected; only opening a new one can be refused.

use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

type BoxError = Box<dyn Error + Send + Sync>;

/// The connect error returned when the cap is reached.
#[derive(Debug)]
pub struct ConnectionLimitReached {
    max: usize,
}

impl fmt::Display for ConnectionLimitReached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "upstream connection limit of {} reached", self.max)
    }
}

impl Error for ConnectionLimitReached {}

/// How many upstream connections are open, and how many may be.
#[derive(Debug)]
pub struct ConnectionLimit {
    open: AtomicUsize,
    max: Option<usize>,
}

impl ConnectionLimit {
    /// A limit of `max` connections; `None` counts without limiting.
    pub fn new(max: Option<usize>) -> Arc<Self> {
        Arc::new(ConnectionLimit {
            open: AtomicUsize::new(0),
            max,
        })
    }

    /// Connections currently open or being opened.
    pub fn open(&self) -> usize {
        self.open.load(Ordering::Relaxed)
    }

    /// The configured cap, if any.
    pub fn max(&self) -> Option<usize> {
        self.max
    }

    /// Reserve room for one more connection, held until the slot is dropped.
    fn reserve(self: &Arc<Self>) -> Result<Slot, ConnectionLimitReached> {
        let already_open = self.open.fetch_add(1, Ordering::Relaxed);
        let slot = Slot(self.clone());
        match self.max {
            // Dropping the slot gives the reservation back.
            Some(max) if already_open >= max => Err(ConnectionLimitReached { max }),
            _ => Ok(slot),
        }
    }
}

/// One connection's share of the limit.
#[derive(Debug)]
struct Slot(Arc<ConnectionLimit>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connector that opens connections through `inner` as long as the limit
/// allows.
#[derive(Clone)]
pub struct LimitedConnector<C> {
    inner: C,
    limit: Arc<ConnectionLimit>,
}

impl<C> LimitedConnector<C> {
    pub fn new(inner: C, limit: Arc<ConnectionLimit>) -> Self {
        LimitedConnector { inner, limit }
    }
}

impl<C> tower_service::Service<Uri> for LimitedConnector<C>
where
    C: tower_service::Service<Uri>,
    C::Future: Send + 'static,
    C::Error: Into<BoxError>,
{
    type Response = Counted<C::Response>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        let slot = match self.limit.reserve() {
            Ok(slot) => slot,
            Err(reached) => return Box::pin(async move { Err(reached.into()) }),
        };
        let connecting = self.inner.call(destination);
        Box::pin(async move {
            let io = connecting.await.map_err(Into::into)?;
            Ok(Counted { io, _slot: slot })
        })
    }
}

/// An upstream connection that counts against the limit while it lives.
pub struct Counted<T> {
    io: T,
    _slot: Slot,
}

impl<T: Connection> Connection for Counted<T> {
    fn connected(&self) -> Connected {
        self.io.connected()
    }
}

impl<T: Read + Unpin> Read for Counted<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: Write + Unpin> Write for Counted<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserves_up_to_the_limit_and_no_further() {
        let limit = ConnectionLimit::new(Some(2));

        let first = limit.reserve();
        let second = limit.reserve();
        let third = limit.reserve();

        assert!(first.is_ok() && second.is_ok());
        assert!(third.is_err());
        assert_eq!(limit.open(), 2);
    }

    #[test]
    fn a_closed_connection_makes_room_again() {
        let limit = ConnectionLimit::new(Some(1));
        let only = limit.reserve().unwrap();

        drop(only);

        assert_eq!(limit.open(), 0);
        assert!(limit.reserve().is_ok());
    }

    #[test]
    fn without_a_maximum_connections_are_only_counted() {
        let limit = ConnectionLimit::new(None);

        let slots: Vec<_> = (0..1000).map(|_| limit.reserve().unwrap()).collect();

        assert_eq!(limit.open(), slots.len());
    }
}
