//! Opening a connection to a server: its address looked up, TCP connected
//! with `TCP_NODELAY`, then TLS if asked for, all under one deadline.
//!
//! Which HTTP version runs over the connection, and whether it may be
//! opened at all (the connection cap), is decided by the callers of
//! [`Dialer::open`].

use netkit_dns::{Cache, Resolve, SystemResolver};
use netkit_rate_limiting::LimitReached;
use netkit_tls::{Alpn, ClientTlsStream, Connector};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Where the address of a host comes from. Object-safe, so that what holds
/// a [`Dialer`] does not carry the resolver in its type.
pub(crate) trait Lookup: Send + Sync + 'static {
    /// The address to connect to for `host:port`.
    fn address<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<SocketAddr>> + Send + 'a>>;
}

impl<R: Resolve> Lookup for Cache<R> {
    fn address<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<SocketAddr>> + Send + 'a>> {
        Box::pin(Cache::address(self, host, port, Instant::now()))
    }
}

/// Every lookup goes to the system, and the first address is used.
impl Lookup for SystemResolver {
    fn address<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = io::Result<SocketAddr>> + Send + 'a>> {
        Box::pin(async move {
            self.resolve(host, port)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address"))
                })
        })
    }
}

/// TLS for one connection: who to trust, and the one protocol to offer.
#[derive(Clone, Copy)]
pub(crate) struct Tls<'a> {
    pub(crate) connector: &'a Connector,
    pub(crate) alpn: Alpn,
}

/// Why a connection could not be opened. Each message names the server;
/// the error underneath, if any, is the source and is not repeated.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConnectError {
    /// Opening one more connection would exceed the cap.
    #[error("no connection opened")]
    Limit(#[from] LimitReached),
    /// The host's address could not be looked up.
    #[error("resolving {host}:{port}")]
    Resolve {
        host: String,
        port: u16,
        source: io::Error,
    },
    /// The connection, TLS included, took longer than the connect timeout.
    #[error("connecting to {host}:{port}: no connection after {after:?}")]
    TimedOut {
        host: String,
        port: u16,
        after: Duration,
    },
    /// TCP failed: refused, unreachable, reset.
    #[error("connecting to {address}")]
    Tcp {
        address: SocketAddr,
        source: io::Error,
    },
    /// The TLS handshake failed, at the TLS level or under it
    /// ([`netkit_tls::is_tls_error`] tells which).
    #[error("TLS handshake with {server_name}")]
    Tls {
        server_name: String,
        source: io::Error,
    },
    /// The server did not agree to speak the one protocol that was offered.
    #[error("TLS handshake with {server_name}: the server did not agree to speak {offered:?}")]
    Alpn { server_name: String, offered: Alpn },
}

/// A connection to a server, in the clear or over TLS.
pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(Box<ClientTlsStream<TcpStream>>),
}

/// Opens connections to servers.
pub(crate) struct Dialer {
    lookup: Arc<dyn Lookup>,
    connect_timeout: Option<Duration>,
}

impl Dialer {
    /// A dialer looking addresses up through `lookup` and giving up on a
    /// connection not open after `connect_timeout` (`None`: when the
    /// operating system gives up, which can take minutes).
    pub(crate) fn new(lookup: Arc<dyn Lookup>, connect_timeout: Option<Duration>) -> Dialer {
        Dialer {
            lookup,
            connect_timeout,
        }
    }

    /// A connection to `host:port`, over TLS when `tls` is given, with
    /// `host` as the server name. `host` may be an IPv6 address in
    /// brackets, as it appears in a URI. The deadline covers the lookup,
    /// TCP and TLS together.
    pub(crate) async fn open(
        &self,
        host: &str,
        port: u16,
        tls: Option<Tls<'_>>,
    ) -> Result<Stream, ConnectError> {
        let host = unbracketed(host);
        let opening = self.open_now(host, port, tls);
        match self.connect_timeout {
            None => opening.await,
            Some(after) => tokio::time::timeout(after, opening)
                .await
                .unwrap_or_else(|_| {
                    Err(ConnectError::TimedOut {
                        host: host.to_string(),
                        port,
                        after,
                    })
                }),
        }
    }

    async fn open_now(
        &self,
        host: &str,
        port: u16,
        tls: Option<Tls<'_>>,
    ) -> Result<Stream, ConnectError> {
        let address =
            self.lookup
                .address(host, port)
                .await
                .map_err(|source| ConnectError::Resolve {
                    host: host.to_string(),
                    port,
                    source,
                })?;
        let tcp = TcpStream::connect(address)
            .await
            .and_then(|tcp| tcp.set_nodelay(true).map(|()| tcp))
            .map_err(|source| ConnectError::Tcp { address, source })?;
        let Some(tls) = tls else {
            return Ok(Stream::Plain(tcp));
        };
        let (stream, negotiated) = tls
            .connector
            .connect(host, &[tls.alpn], tcp)
            .await
            .map_err(|source| ConnectError::Tls {
                server_name: host.to_string(),
                source,
            })?;
        // A server without ALPN settles on nothing, which HTTP/1.1 takes
        // as its own; HTTP/2 must have been agreed to.
        let agreed = match tls.alpn {
            Alpn::H2 => negotiated == Some(Alpn::H2),
            Alpn::Http11 => negotiated != Some(Alpn::H2),
        };
        if !agreed {
            return Err(ConnectError::Alpn {
                server_name: host.to_string(),
                offered: tls.alpn,
            });
        }
        Ok(Stream::Tls(Box::new(stream)))
    }
}

/// `host` without the brackets an IPv6 address has in a URI.
pub(crate) fn unbracketed(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(tcp) => Pin::new(tcp).poll_read(cx, buf),
            Stream::Tls(tls) => Pin::new(tls.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(tcp) => Pin::new(tcp).poll_write(cx, buf),
            Stream::Tls(tls) => Pin::new(tls.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(tcp) => Pin::new(tcp).poll_write_vectored(cx, bufs),
            Stream::Tls(tls) => Pin::new(tls.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Stream::Plain(tcp) => tcp.is_write_vectored(),
            Stream::Tls(tls) => tls.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(tcp) => Pin::new(tcp).poll_flush(cx),
            Stream::Tls(tls) => Pin::new(tls.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(tcp) => Pin::new(tcp).poll_shutdown(cx),
            Stream::Tls(tls) => Pin::new(tls.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
#[path = "dial_test.rs"]
mod tests;
