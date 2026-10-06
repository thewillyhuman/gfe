//! One connection to one server, opened on demand and closed when dropped:
//! for one-off exchanges such as health probes, where a pool would only
//! hide what is being checked.
//!
//! There is no pool, no retry and no cap here, and no timeout beyond the
//! connect timeout: the caller bounds the whole exchange with its own, and
//! every future here is safe to drop.

use super::dial::{Dialer, Stream, Tls, unbracketed};
use super::failure::Failure;
use crate::body::{BoxBody, Incoming};
use http::uri::{Authority, PathAndQuery, Scheme as UriScheme};
use http::{HeaderValue, Request, Response, Uri, Version, header};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use netkit_dns::SystemResolver;
use netkit_tls::Alpn;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// The HTTP version a [`Connection`] speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// HTTP/1.1; over TLS, `http/1.1` is offered by ALPN.
    Http11,
    /// HTTP/2: with prior knowledge in the clear; over TLS, `h2` is offered
    /// by ALPN and must be agreed to.
    Http2,
}

/// How a [`Connection`] is opened.
#[derive(Debug, Clone)]
pub struct ConnectionOptions {
    pub protocol: Protocol,
    /// TLS with this connector, the host being the server name; `None`
    /// speaks in the clear.
    pub tls: Option<netkit_tls::Connector>,
    /// How long opening the connection may take: the address lookup, TCP
    /// and TLS together. `None`: until the operating system gives up.
    pub connect_timeout: Option<Duration>,
}

/// One connection to one server, not pooled. Closed when dropped, at once:
/// a response body still being read then ends with an error.
#[derive(Debug)]
pub struct Connection {
    sender: Sender,
    scheme: UriScheme,
    authority: Authority,
    /// Drives the connection; aborted on drop, which closes it.
    driver: JoinHandle<()>,
}

#[derive(Debug)]
enum Sender {
    Http11(http1::SendRequest<BoxBody>),
    Http2(http2::SendRequest<BoxBody>),
}

impl Connection {
    /// Open a connection to `host:port` speaking `options.protocol`. The
    /// address of `host` is looked up anew through the system's resolver,
    /// so that a server that moved is found where it is now. An IPv6
    /// address may come with or without brackets.
    pub async fn open(
        host: &str,
        port: u16,
        options: &ConnectionOptions,
    ) -> Result<Connection, Failure> {
        let authority = authority(host, port).map_err(Failure::other)?;
        let alpn = match options.protocol {
            Protocol::Http11 => Alpn::Http11,
            Protocol::Http2 => Alpn::H2,
        };
        let tls = options
            .tls
            .as_ref()
            .map(|connector| Tls { connector, alpn });
        let scheme = if tls.is_some() {
            UriScheme::HTTPS
        } else {
            UriScheme::HTTP
        };
        let dialer = Dialer::new(Arc::new(SystemResolver), options.connect_timeout);
        let stream = dialer
            .open(host, port, tls)
            .await
            .map_err(|error| Failure::new(Box::new(error), true))?;
        let (sender, driver) = handshake(options.protocol, stream)
            .await
            .map_err(|error| Failure::new(Box::new(error), true))?;
        Ok(Connection {
            sender,
            scheme,
            authority,
            driver,
        })
    }

    /// Send `request` and wait for the response head.
    ///
    /// The request goes to the server this connection is open to whatever
    /// its target says: only the target's path and query are kept (`/`
    /// when it has none). Over HTTP/1.1 the request's `Host` names the
    /// host it is for, the connection's `host:port` when there is none;
    /// over HTTP/2 `:authority` is the connection's, and `Host` is
    /// dropped.
    pub async fn send(
        &mut self,
        mut request: Request<BoxBody>,
    ) -> Result<Response<Incoming>, Failure> {
        let path_and_query = request
            .uri()
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/"));
        let sent = match &mut self.sender {
            Sender::Http11(sender) => {
                *request.version_mut() = Version::HTTP_11;
                *request.uri_mut() = Uri::from(path_and_query);
                let host =
                    HeaderValue::from_str(self.authority.as_str()).map_err(Failure::other)?;
                request.headers_mut().entry(header::HOST).or_insert(host);
                sender.ready().await.map_err(sending)?;
                sender.send_request(request).await
            }
            Sender::Http2(sender) => {
                *request.version_mut() = Version::HTTP_2;
                request.headers_mut().remove(header::HOST);
                *request.uri_mut() = Uri::builder()
                    .scheme(self.scheme.clone())
                    .authority(self.authority.clone())
                    .path_and_query(path_and_query)
                    .build()
                    .map_err(Failure::other)?;
                sender.ready().await.map_err(sending)?;
                sender.send_request(request).await
            }
        };
        sent.map_err(sending)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// A failure once the connection is open.
fn sending(error: hyper::Error) -> Failure {
    Failure::new(Box::new(error), false)
}

/// Start speaking `protocol` over `stream`, the connection driven by a task
/// of its own.
async fn handshake(
    protocol: Protocol,
    stream: Stream,
) -> Result<(Sender, JoinHandle<()>), hyper::Error> {
    let io = TokioIo::new(stream);
    match protocol {
        Protocol::Http11 => {
            let (sender, connection) = http1::handshake(io).await?;
            let driver = tokio::spawn(async move {
                // How it ended is what the next `send` reports.
                let _ = connection.await;
            });
            Ok((Sender::Http11(sender), driver))
        }
        Protocol::Http2 => {
            let (sender, connection) = http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .handshake(io)
                .await?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok((Sender::Http2(sender), driver))
        }
    }
}

/// `host:port` as a URI authority, with brackets around an IPv6 address.
fn authority(host: &str, port: u16) -> Result<Authority, http::uri::InvalidUri> {
    let host = unbracketed(host);
    if host.contains(':') {
        format!("[{host}]:{port}").parse()
    } else {
        format!("{host}:{port}").parse()
    }
}

#[cfg(test)]
#[path = "connection_test.rs"]
mod tests;
