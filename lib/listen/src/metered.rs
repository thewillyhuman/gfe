//! Counting the bytes that flow through a stream.
//!
//! [`Metered`] wraps any `AsyncRead + AsyncWrite` and counts, as they flow,
//! the bytes read from it and written to it. The counts are kept apart from
//! the stream ([`Meter`]), so that whoever accounts for a connection can
//! read them after the stream has been handed on, or dropped.
//!
//! Wrapped around an accepted TCP stream, underneath any TLS, it counts the
//! bytes on the wire. It does not interpret them, time them, or say how the
//! stream ended: that is for the code that serves the connection.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The two counts of a [`Metered`] stream, shared with every [`Meter`].
#[derive(Debug, Default)]
struct Counts {
    read: AtomicU64,
    written: AtomicU64,
}

/// A handle on the counts of a [`Metered`] stream. Cheap to clone; every
/// clone reads the same counts, for as long as it is kept.
#[derive(Debug, Clone)]
pub struct Meter(Arc<Counts>);

impl Meter {
    /// Bytes read from the stream so far.
    pub fn bytes_read(&self) -> u64 {
        self.0.read.load(Ordering::Relaxed)
    }

    /// Bytes written to the stream so far: accepted by the stream, which is
    /// not to say delivered to the peer.
    pub fn bytes_written(&self) -> u64 {
        self.0.written.load(Ordering::Relaxed)
    }
}

/// A stream that counts the bytes read from and written to it. Reads and
/// writes pass through unchanged.
#[derive(Debug)]
pub struct Metered<S> {
    inner: S,
    counts: Arc<Counts>,
}

impl<S> Metered<S> {
    /// `inner`, with both counts at zero.
    pub fn new(inner: S) -> Self {
        Metered {
            inner,
            counts: Arc::default(),
        }
    }

    /// A handle on the counts, which can be read while the stream is in use
    /// and after it is gone.
    pub fn meter(&self) -> Meter {
        Meter(Arc::clone(&self.counts))
    }

    /// The wrapped stream. What is read or written through it directly is
    /// not counted.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// The wrapped stream, mutably. What is read or written through it
    /// directly is not counted.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// The wrapped stream; the counts stop at what they are, and stay
    /// readable through any [`Meter`] kept.
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn count_written(&self, result: &Poll<io::Result<usize>>) {
        if let Poll::Ready(Ok(written)) = result {
            self.counts
                .written
                .fetch_add(*written as u64, Ordering::Relaxed);
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = (buf.filled().len() - before) as u64;
            self.counts.read.fetch_add(read, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.count_written(&result);
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.count_written(&result);
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "metered_test.rs"]
mod tests;
