//! ACME support — the http-01 challenge store served by the proxy.
//!
//! GFE answers ACME `http-01` challenges at
//! `/.well-known/acme-challenge/<token>` on its plaintext HTTP listener by
//! returning the key authorization stored here. An ACME ordering driver (e.g.
//! `instant-acme`) populates this store before asking the CA to validate, then
//! removes the entry afterwards, writes the issued certificate to the cert
//! files, and triggers a config reload so the new certificate is served.
//!
//! The challenge store and its serving path are implemented and tested here;
//! the CA-ordering driver is a documented integration point (it requires a live
//! ACME endpoint to exercise and is intentionally not run in unit tests).

use dashmap::DashMap;

/// Path prefix the proxy intercepts for http-01 challenges.
pub const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// A concurrent token → key-authorization store for ACME http-01 challenges.
#[derive(Default)]
pub struct ChallengeStore {
    map: DashMap<String, String>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        ChallengeStore {
            map: DashMap::new(),
        }
    }

    /// Register a challenge token → key authorization (called before asking the
    /// CA to validate).
    pub fn set(&self, token: impl Into<String>, key_authorization: impl Into<String>) {
        self.map.insert(token.into(), key_authorization.into());
    }

    /// Look up the key authorization for a token.
    pub fn get(&self, token: &str) -> Option<String> {
        self.map.get(token).map(|e| e.value().clone())
    }

    /// Remove a challenge (called after validation completes).
    pub fn remove(&self, token: &str) {
        self.map.remove(token);
    }

    /// Given a full request path, return the key authorization if it is an
    /// http-01 challenge request with a known token.
    pub fn resolve_path(&self, path: &str) -> Option<String> {
        path.strip_prefix(ACME_CHALLENGE_PREFIX)
            .and_then(|token| self.get(token))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_known_challenge() {
        let store = ChallengeStore::new();
        store.set("tok123", "tok123.keyauth");
        assert_eq!(
            store.resolve_path("/.well-known/acme-challenge/tok123"),
            Some("tok123.keyauth".to_string())
        );
        assert_eq!(
            store.resolve_path("/.well-known/acme-challenge/unknown"),
            None
        );
        assert_eq!(store.resolve_path("/other/path"), None);

        store.remove("tok123");
        assert!(store
            .resolve_path("/.well-known/acme-challenge/tok123")
            .is_none());
    }
}
