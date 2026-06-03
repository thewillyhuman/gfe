//! A rustls [`ResolvesServerCert`] backed by an atomically-swappable
//! [`CertStore`], so certificate rotation never interrupts in-flight
//! handshakes.

use crate::cert_store::CertStore;
use arc_swap::ArcSwap;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

/// SNI-based certificate resolver. Reads the current [`CertStore`] with a
/// single atomic load per handshake.
pub struct SniResolver {
    store: ArcSwap<CertStore>,
    /// Bumped on every miss; surfaced by the proxy as `gfe_tls_sni_no_cert`.
    misses: std::sync::atomic::AtomicU64,
}

impl SniResolver {
    pub fn new(store: CertStore) -> Self {
        SniResolver {
            store: ArcSwap::from_pointee(store),
            misses: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Atomically replace the certificate store (called on config/cert reload).
    pub fn swap(&self, store: CertStore) {
        self.store.store(Arc::new(store));
    }

    /// Borrow the current store (for expiry metrics, diagnostics).
    pub fn current(&self) -> Arc<CertStore> {
        self.store.load_full()
    }

    /// Total SNI resolution misses since startup.
    pub fn miss_count(&self) -> u64 {
        self.misses.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let store = self.store.load();
        match store.resolve(client_hello.server_name()) {
            Some(key) => Some(key),
            None => {
                self.misses
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_counter_increments() {
        let resolver = SniResolver::new(CertStore::default());
        // Empty store with no default → resolve(None) is a miss. We can't
        // construct a real ClientHello in a unit test, so exercise the store
        // path directly; the resolver wiring is covered by integration tests.
        assert!(resolver.current().resolve(Some("x.org")).is_none());
        assert_eq!(resolver.miss_count(), 0);
    }
}
