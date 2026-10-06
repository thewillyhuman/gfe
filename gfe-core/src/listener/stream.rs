//! A client connection as Pingora reads and writes it: [`ClientStream`],
//! over a plain or a TLS socket, implementing Pingora's `IO` traits.
//!
//! Underneath TLS, [`Metered`] counts the bytes on the wire as they flow and
//! remembers how the connection ended on the client's side (end of stream,
//! reset, timed out by TCP keepalive, other error). Pingora does not say why
//! it stopped serving a connection, so this, with what the edge itself did
//! ([`StreamState::cut`]), is what the close reason is derived from.

use crate::listener::activity::Expiry;
use async_trait::async_trait;
use gfe_observability::Counter;
use netkit_tls::TlsInfo;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::raw_connect::ProxyDigest;
use pingora_core::protocols::tls::SslDigest;
use pingora_core::protocols::{
    ALPN, GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType,
};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::server::TlsStream;

/// What an HTTP/2 client sends first on a connection (RFC 9113 §3.4).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// How the client's side of a connection ended, as far as the socket tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireEnd {
    /// The client closed its side (or TLS ended with it).
    Eof,
    /// The connection was reset or broken under a read or a write.
    Reset,
    /// The kernel gave the peer up: TCP keepalive (or retransmissions) went
    /// unanswered.
    TimedOut,
    /// Any other failure, TLS-level ones included.
    Error,
}

impl WireEnd {
    fn of(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof => WireEnd::Reset,
            io::ErrorKind::TimedOut => WireEnd::TimedOut,
            _ => WireEnd::Error,
        }
    }
}

/// What one connection's stream observed, shared with whoever accounts for
/// the connection and enforces its timeouts.
#[derive(Debug, Default)]
pub(crate) struct StreamState {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// The first sign of the end seen on the wire; later ones are
    /// consequences of it.
    end: OnceLock<WireEnd>,
    /// The error that ended the connection, for the log.
    error: OnceLock<String>,
    /// Why the edge ended the connection or asked it to end, if it did.
    expiry: OnceLock<Expiry>,
    /// Whether the connection speaks HTTP/2 (by ALPN, or by its preface).
    h2: AtomicBool,
    cut: Mutex<Cut>,
}

#[derive(Debug, Default)]
struct Cut {
    cut: bool,
    /// The reader to wake when the connection is cut.
    reader: Option<Waker>,
}

impl StreamState {
    /// Bytes read from the client's socket, TLS included.
    pub(crate) fn bytes_in(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }

    /// Bytes written to the client's socket, TLS included.
    pub(crate) fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    /// How the client's side ended, if the stream has seen it.
    pub(crate) fn end(&self) -> Option<WireEnd> {
        self.end.get().copied()
    }

    /// The error that ended the connection, if one did.
    pub(crate) fn error(&self) -> Option<&str> {
        self.error.get().map(String::as_str)
    }

    /// Why the edge ended the connection, or asked it to, if it did.
    pub(crate) fn expiry(&self) -> Option<Expiry> {
        self.expiry.get().copied()
    }

    /// Whether the connection speaks HTTP/2.
    pub(crate) fn is_h2(&self) -> bool {
        self.h2.load(Ordering::Relaxed)
    }

    /// Note that the edge asked the application to end the connection (an
    /// HTTP/2 `GOAWAY`) for `expiry`; it is still read.
    pub(crate) fn ask_to_leave(&self, expiry: Expiry) {
        let _ = self.expiry.set(expiry);
    }

    /// End the connection for `expiry`: every read from now on that would
    /// wait fails with `TimedOut` instead. Data already received is still
    /// read, and writes are untouched, so a response being written is not
    /// cut short. To the application this looks like a client that went
    /// silent: an HTTP/1 server waiting for a request head closes the
    /// connection quietly.
    pub(crate) fn cut(&self, expiry: Expiry) {
        let _ = self.expiry.set(expiry);
        let reader = {
            let mut cut = self.cut.lock().unwrap_or_else(PoisonError::into_inner);
            cut.cut = true;
            cut.reader.take()
        };
        if let Some(reader) = reader {
            reader.wake();
        }
    }

    /// Ready once the connection has been cut; until then, `cx` is woken
    /// when it is.
    fn poll_cut(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut cut = self.cut.lock().unwrap_or_else(PoisonError::into_inner);
        if cut.cut {
            return Poll::Ready(());
        }
        cut.reader = Some(cx.waker().clone());
        Poll::Pending
    }

    fn ended(&self, end: WireEnd) {
        let _ = self.end.set(end);
    }

    fn failed(&self, error: &io::Error) {
        if self.end.set(WireEnd::of(error)).is_ok() {
            let _ = self.error.set(error.to_string());
        }
    }
}

/// The error a read gets once its connection has been cut.
fn cut_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "connection ended by the edge")
}

/// A socket that counts the bytes read from and written to it, and notes
/// how it ended. Wrapped around the TCP stream, underneath TLS, so it counts
/// bytes on the wire.
#[derive(Debug)]
pub(crate) struct Metered<S> {
    inner: S,
    state: Arc<StreamState>,
    read_total: Counter,
    written_total: Counter,
}

impl<S> Metered<S> {
    /// `inner`, counted in `state` and in the two counters (the listener's
    /// `gfe_bytes_in_total` and `gfe_bytes_out_total`).
    pub(crate) fn new(
        inner: S,
        state: Arc<StreamState>,
        read_total: Counter,
        written_total: Counter,
    ) -> Self {
        Metered {
            inner,
            state,
            read_total,
            written_total,
        }
    }

    pub(crate) fn get_ref(&self) -> &S {
        &self.inner
    }

    pub(crate) fn state(&self) -> &Arc<StreamState> {
        &self.state
    }

    fn count_written(&self, result: &Poll<io::Result<usize>>) {
        match result {
            Poll::Ready(Ok(written)) => {
                let written = *written as u64;
                self.state.bytes_out.fetch_add(written, Ordering::Relaxed);
                self.written_total.inc_by(written);
            }
            Poll::Ready(Err(e)) => self.state.failed(e),
            Poll::Pending => {}
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
        let wanted = buf.remaining() > 0;
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        match &result {
            Poll::Ready(Ok(())) => {
                let read = (buf.filled().len() - before) as u64;
                if read == 0 && wanted {
                    self.state.ended(WireEnd::Eof);
                }
                self.state.bytes_in.fetch_add(read, Ordering::Relaxed);
                self.read_total.inc_by(read);
            }
            Poll::Ready(Err(e)) => self.state.failed(e),
            Poll::Pending => {}
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
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if let Poll::Ready(Err(e)) = &result {
            self.state.failed(e);
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The application protocol a client selected by ALPN, in Pingora's terms.
/// Only the two the node offers are mapped; anything else is left to the
/// HTTP/1 default rather than taken for a custom protocol.
fn alpn(protocol: Option<&[u8]>) -> Option<ALPN> {
    match protocol {
        Some(b"h2") => Some(ALPN::H2),
        Some(b"http/1.1") => Some(ALPN::H1),
        _ => None,
    }
}

#[derive(Debug)]
enum Inner {
    Plain(Box<Metered<L4Stream>>),
    Tls(Box<TlsStream<Metered<L4Stream>>>),
}

/// A client connection, plain or TLS, as handed to a Pingora application.
///
/// Reads wait for the client unless the edge has [cut](StreamState::cut)
/// the connection. On a plain connection it supports peeking, which Pingora
/// needs to tell an HTTP/2 client (prior knowledge) from an HTTP/1 one. On a
/// TLS connection it reports the protocol the client chose by ALPN and a
/// TLS digest: Pingora tells TLS from cleartext by that digest.
#[derive(Debug)]
pub(crate) struct ClientStream {
    inner: Inner,
    state: Arc<StreamState>,
    ssl_digest: Option<Arc<SslDigest>>,
}

impl ClientStream {
    /// A cleartext connection.
    pub(crate) fn plain(wire: Metered<L4Stream>) -> Self {
        ClientStream {
            state: Arc::clone(wire.state()),
            inner: Inner::Plain(Box::new(wire)),
            ssl_digest: None,
        }
    }

    /// A TLS connection whose handshake negotiated `tls`.
    pub(crate) fn tls(stream: TlsStream<Metered<L4Stream>>, tls: &TlsInfo) -> Self {
        let state = Arc::clone(stream.get_ref().0.state());
        if tls.alpn.as_deref() == Some("h2") {
            state.h2.store(true, Ordering::Relaxed);
        }
        let digest = SslDigest::new(
            tls.cipher.clone(),
            tls.version.to_string(),
            None,
            None,
            Vec::new(),
        );
        ClientStream {
            inner: Inner::Tls(Box::new(stream)),
            state,
            ssl_digest: Some(Arc::new(digest)),
        }
    }

    fn l4(&self) -> &L4Stream {
        match &self.inner {
            Inner::Plain(wire) => wire.get_ref(),
            Inner::Tls(stream) => stream.get_ref().0.get_ref(),
        }
    }
}

impl AsyncRead for ClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = match &mut self.inner {
            Inner::Plain(wire) => Pin::new(wire).poll_read(cx, buf),
            Inner::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        };
        match &result {
            // Data already received wins over a cut: it is what the client
            // sent before the deadline.
            Poll::Pending if self.state.poll_cut(cx).is_ready() => Poll::Ready(Err(cut_error())),
            // A TLS-level failure, which the wire underneath cannot see.
            Poll::Ready(Err(e)) => {
                self.state.failed(e);
                result
            }
            _ => result,
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            Inner::Plain(wire) => Pin::new(wire).poll_write(cx, buf),
            Inner::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            Inner::Plain(wire) => Pin::new(wire).poll_write_vectored(cx, bufs),
            Inner::Tls(stream) => Pin::new(stream.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            Inner::Plain(wire) => wire.is_write_vectored(),
            Inner::Tls(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Inner::Plain(wire) => Pin::new(wire).poll_flush(cx),
            Inner::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            Inner::Plain(wire) => Pin::new(wire).poll_shutdown(cx),
            Inner::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

impl Drop for ClientStream {
    /// Tell a TLS client that the node is closing (`close_notify`) when the
    /// connection is given up without having been shut down, which is what
    /// Pingora does when the client closed its side first, and what a cut
    /// connection gets.
    ///
    /// Without it the client cannot tell an orderly end from a connection
    /// cut short, and one that waits for the answer to its own
    /// `close_notify` reports an error. It also keeps the client's port
    /// reusable at once: a client that has already closed its socket answers
    /// the alert with a reset, instead of holding the port in `TIME_WAIT`.
    ///
    /// One attempt, without waiting: a socket whose buffer is full (the
    /// client is not reading) is closed without the goodbye.
    fn drop(&mut self) {
        if let Inner::Tls(stream) = &mut self.inner {
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let _ = Pin::new(stream.as_mut()).poll_shutdown(&mut cx);
        }
    }
}

#[async_trait]
impl Shutdown for ClientStream {
    async fn shutdown(&mut self) {
        if let Err(e) = AsyncWriteExt::shutdown(self).await {
            tracing::debug!(error = %e, "shutting down a client connection");
        }
    }
}

impl UniqueID for ClientStream {
    fn id(&self) -> UniqueIDType {
        self.l4().id()
    }
}

impl Ssl for ClientStream {
    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.ssl_digest.clone()
    }

    fn selected_alpn_proto(&self) -> Option<ALPN> {
        match &self.inner {
            Inner::Plain(_) => None,
            Inner::Tls(stream) => alpn(stream.get_ref().1.alpn_protocol()),
        }
    }
}

impl GetTimingDigest for ClientStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.l4().get_timing_digest()
    }
}

impl GetProxyDigest for ClientStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        None
    }
}

impl GetSocketDigest for ClientStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.l4().get_socket_digest()
    }
}

#[async_trait]
impl Peek for ClientStream {
    /// Peek at the first bytes of a plain connection, which Pingora does to
    /// look for the HTTP/2 preface. Waits like a read does, until the bytes
    /// arrive or the connection is cut, but only for as long as what arrived
    /// could still be the preface: Pingora's own peek waits for all of
    /// `buf`, which hangs a client whose whole request is shorter (an
    /// `HTTP/1.0` health probe). What was not read stays zero, so a short
    /// peek never equals the preface. Not supported over TLS, where ALPN
    /// says what the client speaks.
    ///
    /// The bytes are put back underneath the meter, which counts them when
    /// they are read for good.
    async fn try_peek(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        let Inner::Plain(wire) = &mut self.inner else {
            return Ok(false);
        };
        let state = Arc::clone(&self.state);
        let l4 = &mut wire.inner;
        let mut filled = 0;
        let mut ended = None;
        while filled < buf.len() && H2_PREFACE.starts_with(&buf[..filled]) {
            let read = tokio::select! {
                read = tokio::io::AsyncReadExt::read(l4, &mut buf[filled..]) => read,
                () = std::future::poll_fn(|cx| state.poll_cut(cx)) => Err(cut_error()),
            };
            match read {
                Ok(0) => {
                    ended = Some(WireEnd::Eof);
                    break;
                }
                Ok(read) => filled += read,
                Err(e) => {
                    // Whatever arrived before the failure is still the
                    // client's: put it back for the reads that follow.
                    l4.rewind(&buf[..filled]);
                    if state.expiry().is_none() {
                        state.failed(&e);
                    }
                    return Err(e);
                }
            }
        }
        l4.rewind(&buf[..filled]);
        buf[filled..].fill(0);
        if let Some(end) = ended {
            state.ended(end);
        }
        if &buf[..] == H2_PREFACE {
            state.h2.store(true, Ordering::Relaxed);
        }
        Ok(true)
    }
}

#[cfg(test)]
#[path = "stream_test.rs"]
mod tests;
