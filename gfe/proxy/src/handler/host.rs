//! Which host a request is for, and the requests GFE refuses because that
//! cannot be told or must not be served on their connection.
//!
//! Hosts are compared as hosts: case and an agreeing or absent port do not
//! make two names differ. Which route the host takes is not decided here.

use crate::handler::respond::Refusal;
use netkit_http::header::HOST;
use netkit_http::uri::Authority;
use netkit_http::{HeaderMap, Uri, Version};
use netkit_tls::CertStore;

/// Why a request's host cannot be used to route it. GFE answers such a
/// request itself.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HostError {
    /// The request target's authority and the `Host` header name different
    /// hosts; `target` is the former.
    Conflict { target: String },
    /// Nothing names the host: no authority in the target, no valid `Host`
    /// header and no SNI.
    Missing,
    /// `host` is not served by the certificate the client accepted for the
    /// connection's SNI.
    Misdirected { host: String },
}

impl HostError {
    /// How GFE answers the request.
    pub(crate) fn refusal(&self) -> Refusal {
        match self {
            HostError::Conflict { .. } => Refusal::HostConflict,
            HostError::Missing => Refusal::HostMissing,
            HostError::Misdirected { .. } => Refusal::Misdirected,
        }
    }

    /// The host the request is logged under.
    pub(crate) fn into_host(self) -> String {
        match self {
            HostError::Conflict { target } => target,
            HostError::Missing => String::new(),
            HostError::Misdirected { host } => host,
        }
    }
}

/// The host a request is for, lowercased and without its port: the request
/// target's authority (HTTP/2 `:authority`, HTTP/1 absolute form), else the
/// `Host` header, else the SNI.
///
/// A request carrying both an authority and a `Host` header is refused
/// unless they name the same host, and the same port when both carry one:
/// otherwise it would be routed by one and forwarded with the other.
///
/// A request that names no host at all is refused, except over HTTP/1.0,
/// which has no `Host` header to require: that one is for no host in
/// particular (the empty host), and only a catch-all route matches it.
pub(crate) fn request_host(
    uri: &Uri,
    headers: &HeaderMap,
    version: Version,
    sni: Option<&str>,
) -> Result<String, HostError> {
    let header = headers.get(HOST).map(|value| {
        value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<Authority>().ok())
    });
    match (uri.authority(), header) {
        (Some(target), Some(header)) => {
            let agree = header.is_some_and(|header| {
                header.host().eq_ignore_ascii_case(target.host())
                    && match (header.port_u16(), target.port_u16()) {
                        (Some(a), Some(b)) => a == b,
                        _ => true,
                    }
            });
            let target = target.host().to_ascii_lowercase();
            if agree {
                Ok(target)
            } else {
                Err(HostError::Conflict { target })
            }
        }
        (Some(target), None) => Ok(target.host().to_ascii_lowercase()),
        (None, Some(Some(header))) => Ok(header.host().to_ascii_lowercase()),
        (None, Some(None)) => Err(HostError::Missing),
        (None, None) => match sni {
            Some(sni) => Ok(sni.to_ascii_lowercase()),
            None if version == Version::HTTP_10 => Ok(String::new()),
            None => Err(HostError::Missing),
        },
    }
}

/// On a TLS connection, a request for another host than the SNI is served
/// only if the certificate the client accepted for the SNI is also the one
/// for `host`: that client is reusing the connection for a name it trusts
/// the connection for (HTTP/2 connection coalescing). Anything else could
/// reach a tenant over another tenant's certificate.
pub(crate) fn covered_by_sni(
    sni: Option<&str>,
    host: String,
    certificates: &CertStore,
) -> Result<String, HostError> {
    match sni {
        Some(sni)
            if !sni.eq_ignore_ascii_case(&host) && !certificates.same_certificate(sni, &host) =>
        {
            Err(HostError::Misdirected { host })
        }
        _ => Ok(host),
    }
}

#[cfg(test)]
#[path = "host_test.rs"]
mod tests;
