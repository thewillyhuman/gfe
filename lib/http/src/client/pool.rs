//! The pooled client: connections to servers kept open between requests
//! and reused, HTTP/1.1 or HTTP/2 as the scheme and the request call for,
//! under one cap on the connections open at once.
//!
//! The pool itself is hyper-util's; nothing of it shows outside this
//! module, so that it can be replaced without touching a caller.

use super::dial::{ConnectError, Dialer, Lookup, Stream, Tls};
use super::failure::Failure;
use crate::body::{BoxBody, Incoming};
use http::uri::{PathAndQuery, Scheme as UriScheme};
use http::{Request, Response, Uri, Version, header};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use netkit_dns::{Cache, SystemResolver};
use netkit_rate_limiting::{ConcurrencyLimit, Permit};
use netkit_tls::Alpn;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// How a server is spoken to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// HTTP/1.1 in the clear.
    Http,
    /// Over TLS: HTTP/2 for a request that needs it, HTTP/1.1 otherwise.
    Https,
    /// HTTP/2 in the clear, with prior knowledge: the server is known to
    /// speak it.
    H2c,
}

/// HTTP/2 keep-alive: a connection with requests in flight that has been
/// silent for `idle` is pinged, and closed, failing those requests, if the
/// ping is not answered within `timeout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepAlive {
    pub idle: Duration,
    pub timeout: Duration,
}

/// What a [`Client`] is built from.
#[derive(Debug, Clone)]
pub struct Options {
    /// The most idle connections kept open per server (scheme and
    /// authority); 0 keeps none, so that every request opens a connection.
    pub idle_per_host: usize,
    /// How long a connection may stay idle before it is closed. `None`:
    /// until the server closes it.
    pub idle_timeout: Option<Duration>,
    /// How long opening a connection may take: the address lookup, TCP and
    /// TLS together. `None`: until the operating system gives up, which
    /// can take minutes.
    pub connect_timeout: Option<Duration>,
    /// Liveness checking of HTTP/2 connections. `None`: a connection that
    /// dies silently is not noticed while a request waits on it.
    pub http2_keep_alive: Option<KeepAlive>,
    /// The most connections open at once, over all servers, counted from
    /// the moment one starts being opened until it closes. `None`: no cap.
    pub max_connections: Option<usize>,
    /// Who `https` servers are trusted to be, and who we say we are.
    pub tls: netkit_tls::Connector,
    /// How long the address of a named host is trusted before it is looked
    /// up again.
    pub address_ttl: Duration,
}

/// A pooled client. Cheap to clone; clones share the pool and the cap.
#[derive(Clone)]
pub struct Client {
    /// `http`, and `https` for requests that do not need HTTP/2.
    http1: legacy::Client<ServerConnector, BoxBody>,
    /// `h2c`, and `https` for requests that need HTTP/2.
    http2: legacy::Client<ServerConnector, BoxBody>,
    /// Counts, and caps, the connections of both together.
    connections: Arc<ConcurrencyLimit>,
}

impl Client {
    /// A client for `options`, looking names up through the system's
    /// resolver.
    pub fn new(options: Options) -> Client {
        let lookup = Arc::new(Cache::new(SystemResolver, options.address_ttl));
        Client::with_lookup(options, lookup)
    }

    /// A client looking names up through `lookup`; `options.address_ttl`
    /// is `lookup`'s business.
    pub(crate) fn with_lookup(options: Options, lookup: Arc<dyn Lookup>) -> Client {
        let dialer = Arc::new(Dialer::new(lookup, options.connect_timeout));
        let connections = ConcurrencyLimit::new(options.max_connections);
        let connector = |alpn| ServerConnector {
            dialer: dialer.clone(),
            tls: options.tls.clone(),
            alpn,
            connections: connections.clone(),
        };

        let mut builder = legacy::Client::builder(TokioExecutor::new());
        builder
            .pool_max_idle_per_host(options.idle_per_host)
            .pool_idle_timeout(options.idle_timeout)
            // The pool's own timer closes idle connections as they expire;
            // without it they are only noticed when the server is used
            // again. `timer` is HTTP/2's.
            .pool_timer(TokioTimer::new())
            .timer(TokioTimer::new());
        if let Some(keep_alive) = options.http2_keep_alive {
            builder
                .http2_keep_alive_interval(keep_alive.idle)
                .http2_keep_alive_timeout(keep_alive.timeout);
        }
        let http1 = builder.build(connector(Alpn::Http11));
        let http2 = builder.http2_only(true).build(connector(Alpn::H2));
        Client {
            http1,
            http2,
            connections,
        }
    }

    /// Send `request` to the server at `authority` (`host:port`, or `host`
    /// for the scheme's default port) and wait for the response head.
    ///
    /// The HTTP version follows `scheme` and the request: `http` always
    /// goes out over HTTP/1.1 and `h2c` over HTTP/2 with prior knowledge;
    /// to `https`, a request whose version is HTTP/2 needs HTTP/2, which
    /// TLS (ALPN) must settle on or the request fails with
    /// [`FailureKind::Tls`](super::FailureKind::Tls), and any other goes
    /// out over HTTP/1.1. Connections are pooled per scheme and authority,
    /// and an HTTP/2 connection carries many requests at once.
    ///
    /// The request's `Host` header names the host the request is for, and
    /// reaches the server over HTTP/1.1 (when there is none, `authority`
    /// is sent). Over HTTP/2 the server is named by `:authority`, which is
    /// `authority`, and `Host` is dropped so as not to contradict it.
    ///
    /// The request goes to `authority` whatever its target says: only the
    /// target's path and query are kept (`/` when it has none), so that an
    /// absolute or odd target cannot send it to another server.
    ///
    /// A pooled connection may have been closed by the server in the
    /// meantime; a request that fails because of it before any of it was
    /// sent is sent again on another connection. Nothing else is retried.
    pub async fn send(
        &self,
        scheme: Scheme,
        authority: &str,
        mut request: Request<BoxBody>,
    ) -> Result<Response<Incoming>, Failure> {
        let path_and_query = request
            .uri()
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/"));
        let needs_http2 = request.version() == Version::HTTP_2;
        let (client, uri_scheme, over_http1) = match scheme {
            Scheme::Http => (&self.http1, UriScheme::HTTP, true),
            Scheme::Https if needs_http2 => (&self.http2, UriScheme::HTTPS, false),
            Scheme::Https => (&self.http1, UriScheme::HTTPS, true),
            Scheme::H2c => (&self.http2, UriScheme::HTTP, false),
        };
        if over_http1 {
            // hyper refuses an HTTP/2 request on an HTTP/1.1 connection.
            *request.version_mut() = Version::HTTP_11;
        } else {
            request.headers_mut().remove(header::HOST);
        }
        // Built from its parts, so that no request target can run into the
        // authority and change the server the request goes to.
        let uri = Uri::builder()
            .scheme(uri_scheme)
            .authority(authority)
            .path_and_query(path_and_query)
            .build()
            .map_err(Failure::other)?;
        *request.uri_mut() = uri;

        client.request(request).await.map_err(|error| {
            let connecting = error.is_connect();
            Failure::new(Box::new(error), connecting)
        })
    }

    /// The connections open, or being opened, now, over all servers.
    pub fn open_connections(&self) -> usize {
        self.connections.in_use()
    }

    /// The cap on open connections, if any.
    pub fn max_connections(&self) -> Option<usize> {
        self.connections.max()
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("open_connections", &self.open_connections())
            .field("max_connections", &self.max_connections())
            .finish_non_exhaustive()
    }
}

/// Opens connections for the pool: TLS for `https`, offering `alpn`, under
/// the cap.
#[derive(Clone)]
struct ServerConnector {
    dialer: Arc<Dialer>,
    tls: netkit_tls::Connector,
    alpn: Alpn,
    connections: Arc<ConcurrencyLimit>,
}

impl tower_service::Service<Uri> for ServerConnector {
    type Response = Pooled;
    type Error = ConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Pooled, ConnectError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), ConnectError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        // Taken before anything is done, and held for as long as the
        // connection lives.
        let permit = self.connections.try_acquire();
        let this = self.clone();
        Box::pin(async move {
            let permit = permit?;
            let https = destination.scheme() == Some(&UriScheme::HTTPS);
            let tls = https.then_some(Tls {
                connector: &this.tls,
                alpn: this.alpn,
            });
            let host = destination.host().unwrap_or_default();
            let port = destination
                .port_u16()
                .unwrap_or(if https { 443 } else { 80 });
            let stream = this.dialer.open(host, port, tls).await?;
            Ok(Pooled {
                io: TokioIo::new(stream),
                _permit: permit,
            })
        })
    }
}

/// A pooled connection, counted against the cap while it lives.
struct Pooled {
    io: TokioIo<Stream>,
    _permit: Permit,
}

impl Connection for Pooled {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl Read for Pooled {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl Write for Pooled {
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
#[path = "pool_test.rs"]
mod tests;
