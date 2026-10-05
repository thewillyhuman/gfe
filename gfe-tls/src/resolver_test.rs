//! `ClientHello` cannot be built outside rustls, so these tests go through
//! `resolve_sni`; the `ResolvesServerCert` wiring is covered end to end by
//! `tests/acceptor.rs`.

use super::*;
use crate::test_support::entry;

#[test]
fn a_miss_is_counted() {
    let resolver = SniResolver::new(CertStore::default());

    assert!(resolver.resolve_sni(Some("x.org")).is_none());
    assert!(resolver.resolve_sni(None).is_none());

    assert_eq!(resolver.miss_count(), 2);
}

#[test]
fn a_hit_is_not_counted() {
    let store = CertStore::build(&[entry(&["api.example.org"], false)]).unwrap();
    let resolver = SniResolver::new(store);

    assert!(resolver.resolve_sni(Some("api.example.org")).is_some());

    assert_eq!(resolver.miss_count(), 0);
}

#[test]
fn a_swapped_store_serves_the_next_resolution() {
    let resolver = SniResolver::new(CertStore::default());
    let store = CertStore::build(&[entry(&["api.example.org"], false)]).unwrap();

    resolver.swap(store);

    assert!(resolver.resolve_sni(Some("api.example.org")).is_some());
    assert_eq!(resolver.current().len(), 1);
}
