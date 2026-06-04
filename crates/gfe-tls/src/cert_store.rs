//! The SNI → certificate map, built from the dynamic config and swapped
//! atomically on reload.

use crate::loader::load_cert_files;
use gfe_types::{CertEntry, GfeError};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::Arc;

/// An immutable certificate store resolving an SNI name to signing material.
#[derive(Default)]
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
    /// entries, loading each referenced PEM file.
    pub fn build(entries: &[CertEntry]) -> Result<Self, GfeError> {
        let mut store = CertStore::default();
        let mut default_seen = false;
        for entry in entries {
            let loaded = load_cert_files(&entry.cert_file, &entry.key_file)?;
            let key = loaded.certified_key;

            if entry.default {
                if default_seen {
                    return Err(GfeError::Validation(
                        "more than one default certificate configured".into(),
                    ));
                }
                default_seen = true;
                store.default = Some(key.clone());
                store
                    .expiries
                    .push(("<default>".into(), loaded.not_after_unix));
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

    /// Resolve a certificate for the given SNI (or the default when SNI is
    /// absent / unmatched). Returns `None` only when nothing matches and no
    /// default is configured.
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

    /// `(sni-name, not_after_unix)` pairs, for `gfe_cert_expiry_timestamp`.
    pub fn expiries(&self) -> &[(String, i64)] {
        &self.expiries
    }

    /// Number of distinct certificates' SNI bindings (exact + wildcard).
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len() + usize::from(self.default.is_some())
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty() && self.default.is_none()
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
mod tests {
    use super::*;
    use crate::loader::self_signed;
    use std::io::Write;

    fn write_temp(bytes: &[u8], suffix: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("gfe-test-{}-{suffix}", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    fn entry(sni: Vec<&str>, default: bool, tag: &str) -> CertEntry {
        let names = if sni.is_empty() {
            vec!["placeholder.local".to_string()]
        } else {
            sni.iter()
                .map(|s| s.trim_start_matches("*.").to_string())
                .collect()
        };
        let (cert, key) = self_signed(names);
        CertEntry {
            sni: sni.iter().map(|s| s.to_string()).collect(),
            default,
            cert_file: write_temp(&cert, &format!("{tag}.crt")),
            key_file: write_temp(&key, &format!("{tag}.key")),
        }
    }

    #[test]
    fn resolves_exact_wildcard_default() {
        let store = CertStore::build(&[
            entry(vec!["api.example.org"], false, "exact"),
            entry(vec!["*.wild.example.org"], false, "wild"),
            entry(vec![], true, "def"),
        ])
        .unwrap();

        assert!(store.resolve(Some("api.example.org")).is_some());
        assert!(store.resolve(Some("foo.wild.example.org")).is_some());
        // unmatched falls back to default
        assert!(store.resolve(Some("nothing.org")).is_some());
        // no SNI → default
        assert!(store.resolve(None).is_some());
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn no_default_unmatched_is_none() {
        let store = CertStore::build(&[entry(vec!["api.example.org"], false, "only")]).unwrap();
        assert!(store.resolve(Some("other.org")).is_none());
        assert!(store.resolve(None).is_none());
    }

    #[test]
    fn rejects_two_defaults() {
        let err = CertStore::build(&[entry(vec![], true, "d1"), entry(vec![], true, "d2")]);
        assert!(err.is_err());
    }
}
