//! A rustls [`ResolvesServerCert`] backed by an atomically swappable
//! [`CertStore`], so certificate rotation never interrupts in-flight
//! handshakes.

use crate::CertStore;
use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// SNI-based certificate resolver. Reads the current [`CertStore`] with a
/// single atomic load per handshake. A miss fails the handshake (rustls
/// answers with a fatal alert) and is counted.
pub struct SniResolver {
    store: ArcSwap<CertStore>,
    /// Bumped on every miss; read through [`SniResolver::miss_count`].
    misses: AtomicU64,
}

impl SniResolver {
    pub fn new(store: CertStore) -> Self {
        SniResolver {
            store: ArcSwap::from_pointee(store),
            misses: AtomicU64::new(0),
        }
    }

    /// Atomically replace the certificate store (called on config or
    /// certificate reload). Handshakes already past certificate selection,
    /// and established connections, are not affected.
    pub fn swap(&self, store: CertStore) {
        self.store.store(Arc::new(store));
    }

    /// The current store (for expiry metrics, diagnostics).
    pub fn current(&self) -> Arc<CertStore> {
        self.store.load_full()
    }

    /// Total SNI resolution misses since startup.
    pub fn miss_count(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Resolve `sni` against the current store, counting a miss.
    fn resolve_sni(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let resolved = self.store.load().resolve(sni);
        if resolved.is_none() {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        resolved
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver")
            .field("misses", &self.miss_count())
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_sni(client_hello.server_name())
    }
}

#[cfg(test)]
#[path = "resolver_test.rs"]
mod tests;
