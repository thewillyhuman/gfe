//! The SNI → certificate map, built from the dynamic config and swapped
//! atomically on reload (see [`SniResolver`](crate::SniResolver)).

use crate::TlsError;
use crate::loader::load_cert_files;
use gfe_config::CertEntry;
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::Arc;

/// The name [`CertStore::expiries`] and errors give the default certificate.
const DEFAULT_NAME: &str = "<default>";

/// An immutable certificate store resolving an SNI name to signing material.
/// The empty store resolves nothing.
#[derive(Debug, Default)]
pub struct CertStore {
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// `(suffix, key)` for `*.suffix` patterns; suffix keeps the leading dot
    /// (`.example.org`). Ordered longest-suffix-first.
    wildcard: Vec<(String, Arc<CertifiedKey>)>,
    default: Option<Arc<CertifiedKey>>,
    /// `(sni-display-name, not_after_unix)` pairs for expiry metrics.
    expiries: Vec<(String, i64)>,
}

impl CertStore {
    /// Build a certificate store from the dynamic config's certificate
    /// entries, loading each referenced PEM file. Fails on the first entry
    /// that cannot be loaded, naming its SNI names, or on a second default.
    pub fn build(entries: &[CertEntry]) -> Result<Self, TlsError> {
        let mut store = CertStore::default();
        let mut default_file = None;
        for entry in entries {
            let loaded = load_cert_files(&entry.cert_file, &entry.key_file).map_err(|error| {
                TlsError::Entry {
                    names: entry_names(entry),
                    error: Box::new(error),
                }
            })?;
            let key = loaded.certified_key;

            if entry.default {
                if let Some(first) = default_file {
                    return Err(TlsError::TwoDefaults {
                        first,
                        second: entry.cert_file.clone(),
                    });
                }
                default_file = Some(entry.cert_file.clone());
                store.default = Some(key.clone());
                store
                    .expiries
                    .push((DEFAULT_NAME.into(), loaded.not_after_unix));
            }

            for sni in &entry.sni {
                let name = sni.to_ascii_lowercase();
                store.expiries.push((name.clone(), loaded.not_after_unix));
                if let Some(suffix) = name.strip_prefix('*') {
                    // "*.example.org" → suffix ".example.org"
                    store.wildcard.push((suffix.to_string(), key.clone()));
                } else {
                    store.exact.insert(name, key.clone());
                }
            }
        }
        store
            .wildcard
            .sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));
        Ok(store)
    }

    /// Resolve a certificate for the given SNI: an exact name first, then a
    /// single-label wildcard, then the default (also when SNI is absent).
    /// Returns `None` only when nothing matches and no default is configured.
    pub fn resolve(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = sni {
            let name = name.to_ascii_lowercase();
            if let Some(k) = self.exact.get(&name) {
                return Some(k.clone());
            }
            for (suffix, k) in &self.wildcard {
                if wildcard_suffix_matches(suffix, &name) {
                    return Some(k.clone());
                }
            }
        }
        self.default.clone()
    }

    /// Whether `a` and `b` resolve, as SNI names, to the same certificate
    /// entry (the default one included). A client may then reuse one TLS
    /// connection for both names (HTTP/2 connection coalescing). Names that
    /// resolve to nothing share no certificate.
    pub fn same_certificate(&self, a: &str, b: &str) -> bool {
        match (self.resolve(Some(a)), self.resolve(Some(b))) {
            (Some(a), Some(b)) => Arc::ptr_eq(&a, &b),
            _ => false,
        }
    }

    /// `(sni-name, not_after_unix)` pairs, for `gfe_cert_expiry_timestamp`:
    /// one per configured SNI name (lowercased, wildcards as written), plus
    /// `<default>` for the default certificate, in config order.
    pub fn expiries(&self) -> &[(String, i64)] {
        &self.expiries
    }

    /// Number of SNI bindings: exact names, wildcards, and the default.
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len() + usize::from(self.default.is_some())
    }

    /// Whether the store resolves nothing at all.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty() && self.default.is_none()
    }
}

/// How errors name an entry: by its SNI names, or as the default.
fn entry_names(entry: &CertEntry) -> Vec<String> {
    if entry.sni.is_empty() {
        vec![DEFAULT_NAME.to_string()]
    } else {
        entry.sni.clone()
    }
}

/// Match a host against a wildcard suffix (`.example.org`): the host must be a
/// single extra label followed by the suffix.
fn wildcard_suffix_matches(suffix: &str, host: &str) -> bool {
    match host.strip_suffix(suffix) {
        Some(label) => !label.is_empty() && !label.contains('.'),
        None => false,
    }
}

#[cfg(test)]
#[path = "cert_store_test.rs"]
mod tests;
