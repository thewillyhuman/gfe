//! What the functional tests of `netkit_http::server` share: options, a
//! few handlers, a way to serve one end of a pipe, and the clients that
//! talk to it (raw bytes for HTTP/1.1, hyper or raw frames for HTTP/2).
#![allow(dead_code, reason = "each test file uses a part of it")]

pub mod raw_h2;

use bytes::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use netkit_http::body::{Body, BodyExt, BoxBody, BoxError, Frame, Incoming, full};
use netkit_http::server::{self, Closed, Handler, Options};
use netkit_http::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
pub const DRAIN_IDLE_GRACE: Duration = Duration::from_secs(3);

/// Options whose timers are told apart by their lengths.
pub fn options() -> Options {
    Options {
        header_timeout: HEADER_TIMEOUT,
        idle_timeout: IDLE_TIMEOUT,
        keep_alive_timeout: KEEP_ALIVE_TIMEOUT,
        drain_idle_grace: DRAIN_IDLE_GRACE,
        max_header_bytes: server::MIN_HEADER_BYTES,
        max_concurrent_streams: 100,
    }
}

/// A handler made of a closure.
pub struct Handle<F>(pub F);

impl<F, R> Handler for Handle<F>
where
    F: Fn(Request<Incoming>) -> R + Send + Sync + 'static,
    R: Future<Output = Response<BoxBody>> + Send,
{
    fn handle(&self, request: Request<Incoming>) -> impl Future<Output = Response<BoxBody>> + Send {
        (self.0)(request)
    }
}

/// Answers every request with `200 hello`.
pub fn hello() -> Arc<impl Handler> {
    Arc::new(Handle(|_request| async { Response::new(full("hello")) }))
}

/// Assert that `elapsed` is `expected`, give or take the time it takes a
/// connection to wind down.
pub fn assert_about(elapsed: Duration, expected: Duration) {
    assert!(
        elapsed >= expected && elapsed < expected + Duration::from_secs(1),
        "took {elapsed:?}, expected {expected:?}"
    );
}

/// A connection being served, and how to drain it.
pub struct Serving {
    pub drain: watch::Sender<bool>,
    pub closed: JoinHandle<Closed>,
}

impl Serving {
    /// Ask the connection to drain.
    pub fn drain(&self) {
        self.drain.send_replace(true);
    }

    /// How the connection ended, waiting for it to end.
    pub async fn closed(self) -> Closed {
        self.closed.await.expect("serving panicked")
    }
}

/// Serve `io` with `handler` and `options` on a task of its own.
pub fn spawn_serve<S, H>(io: S, handler: Arc<H>, options: Options) -> Serving
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler,
{
    let (drain, drain_rx) = watch::channel(false);
    let closed = tokio::spawn(server::serve(io, handler, options, drain_rx));
    Serving { drain, closed }
}

/// One end of a pipe, the other served with `handler` and `options`.
pub fn serve_pipe<H: Handler>(handler: Arc<H>, options: Options) -> (DuplexStream, Serving) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    (client, spawn_serve(server, handler, options))
}

/// An HTTP/1.1 response read off the wire.
#[derive(Debug)]
pub struct RawResponse {
    /// The status line and headers, as sent, without the blank line.
    pub head: String,
    pub body: Vec<u8>,
}

impl RawResponse {
    /// Whether the head carries `name: value`, ignoring case.
    pub fn has_header(&self, name: &str, value: &str) -> bool {
        let wanted = format!("{name}: {value}").to_ascii_lowercase();
        self.head
            .lines()
            .any(|line| line.to_ascii_lowercase() == wanted)
    }
}

/// Read one HTTP/1.1 response whose body has a `Content-Length` (or is
/// chunked, in which case the body is left unread).
pub async fn read_response<R: AsyncRead + Unpin>(io: &mut R) -> RawResponse {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = io.read_u8().await.expect("connection closed within a head");
        head.push(byte);
    }
    let head = String::from_utf8(head[..head.len() - 4].to_vec()).expect("head not utf-8");
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("bad content-length"))
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    io.read_exact(&mut body)
        .await
        .expect("connection closed within a body");
    RawResponse { head, body }
}

/// Send a `GET /` and read its response.
pub async fn get<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S) -> RawResponse {
    io.write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    read_response(io).await
}

/// Whether the peer closed `io` with nothing more sent.
pub async fn is_closed<R: AsyncRead + Unpin>(io: &mut R) -> bool {
    let mut rest = Vec::new();
    matches!(io.read_to_end(&mut rest).await, Ok(0) | Err(_))
}

/// An HTTP/2 client over `io`, its connection driven on a task of its own.
pub async fn h2_client<S>(io: S) -> hyper::client::conn::http2::SendRequest<BoxBody>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .expect("http/2 handshake");
    tokio::spawn(connection);
    sender
}

/// A `GET /` for an HTTP/2 client.
pub fn h2_get() -> Request<BoxBody> {
    Request::builder()
        .uri("http://test/")
        .body(netkit_http::body::empty())
        .unwrap()
}

/// A body whose frames are sent through a channel, as the sender sees fit.
pub struct ChannelBody(pub mpsc::Receiver<Frame<Bytes>>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0.poll_recv(cx).map(|frame| frame.map(Ok))
    }
}

/// A body sent frame by frame through the returned sender; it ends when the
/// sender is dropped.
pub fn channel_body() -> (mpsc::Sender<Frame<Bytes>>, BoxBody) {
    let (sender, receiver) = mpsc::channel(8);
    (sender, ChannelBody(receiver).boxed())
}
