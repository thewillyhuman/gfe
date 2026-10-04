//! A cap on the upstream connections a node holds open.
//!
//! The cap is enforced where connections are made: a connector wrapper that
//! refuses to open one more connection than allowed, and counts every
//! connection for as long as its socket lives. Requests that find a pooled
//! connection are unaffected; only opening a new one can be refused.

use gfe_limits::{ConcurrencyLimit, Permit};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper::Uri;
use hyper_util::client::legacy::connect::{Connected, Connection};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
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

/// A connector that opens connections through `inner` as long as the limit
/// allows.
#[derive(Clone)]
pub struct LimitedConnector<C> {
    inner: C,
    limit: Arc<ConcurrencyLimit>,
}

impl<C> LimitedConnector<C> {
    pub fn new(inner: C, limit: Arc<ConcurrencyLimit>) -> Self {
        LimitedConnector { inner, limit }
    }

    /// Room for one more connection, held for as long as it lives.
    fn reserve(&self) -> Result<Permit, ConnectionLimitReached> {
        self.limit
            .try_acquire()
            .map_err(|reached| ConnectionLimitReached { max: reached.max })
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
        let slot = match self.reserve() {
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
    _slot: Permit,
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
    fn a_connector_at_its_limit_says_what_the_limit_is() {
        let connector = LimitedConnector::new((), ConcurrencyLimit::new(Some(1)));
        let _open = connector.reserve().unwrap();

        let refused = connector.reserve().unwrap_err();

        assert_eq!(
            refused.to_string(),
            "upstream connection limit of 1 reached"
        );
    }
}
