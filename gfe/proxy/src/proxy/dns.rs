//! The address of a backend whose `host` is a name.
//!
//! Pingora connects to a socket address, and GFE builds the peer of every
//! request afresh, so a name would otherwise be looked up per request.
//! Answers are cached for [`TTL`]; when a refresh fails the last answer is
//! kept, so that a resolver outage does not take down backends whose
//! addresses have not changed. IP literals are never looked up. The first
//! address of an answer is used.

use dashmap::DashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// How long a lookup is trusted.
pub(crate) const TTL: Duration = Duration::from_secs(10);

/// Looks names up. The system resolver in production; a test can count and
/// script lookups.
pub(crate) trait Resolve: Send + Sync + 'static {
    /// The addresses `host` has, with `port`.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send;
}

/// The system resolver, through `tokio::net::lookup_host` (which runs the
/// blocking lookup on Tokio's blocking pool).
#[derive(Debug, Default)]
pub(crate) struct SystemResolver;

impl Resolve for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// One answer: the address, and when it was looked up.
#[derive(Debug, Clone, Copy)]
struct Entry {
    address: SocketAddr,
    looked_up: Instant,
}

/// Backend addresses by `(host, port)`, looked up through `R`.
#[derive(Debug)]
pub(crate) struct DnsCache<R = SystemResolver> {
    resolver: R,
    entries: DashMap<(String, u16), Entry>,
}

impl<R: Resolve> DnsCache<R> {
    /// An empty cache in front of `resolver`.
    pub(crate) fn new(resolver: R) -> Self {
        DnsCache {
            resolver,
            entries: DashMap::new(),
        }
    }

    /// The address of `host:port` as of `now`: an IP literal as it is, a
    /// name from the cache while its answer is fresh, else looked up. A
    /// failed lookup falls back on the last answer, however old; with none,
    /// it is an error.
    pub(crate) async fn address(
        &self,
        host: &str,
        port: u16,
        now: Instant,
    ) -> io::Result<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let key = (host.to_string(), port);
        let cached = self.entries.get(&key).map(|entry| *entry.value());
        if let Some(entry) = cached
            && now.saturating_duration_since(entry.looked_up) < TTL
        {
            return Ok(entry.address);
        }
        // No guard of the map is held across the lookup.
        let looked_up = self
            .resolver
            .resolve(host, port)
            .await
            .and_then(|addresses| {
                addresses.into_iter().next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address"))
                })
            });
        match (looked_up, cached) {
            (Ok(address), _) => {
                self.entries.insert(
                    key,
                    Entry {
                        address,
                        looked_up: now,
                    },
                );
                Ok(address)
            }
            (Err(error), Some(stale)) => {
                tracing::warn!(%host, port, %error, "backend lookup failed, using the last answer");
                Ok(stale.address)
            }
            (Err(error), None) => Err(error),
        }
    }
}

#[cfg(test)]
#[path = "dns_test.rs"]
mod tests;
