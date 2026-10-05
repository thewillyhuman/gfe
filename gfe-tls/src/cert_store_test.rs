use super::*;
use crate::test_support::{entry, self_signed};

#[test]
fn resolves_exact_then_wildcard_then_default() {
    let exact = entry(&["api.example.org"], false);
    let wild = entry(&["*.wild.example.org"], false);
    let default = entry(&[], true);
    let store = CertStore::build(&[exact, wild, default]).unwrap();
    let only_default = CertStore::build(&[entry(&[], true)]).unwrap();

    let exact_key = store.resolve(Some("api.example.org")).unwrap();
    let wild_key = store.resolve(Some("foo.wild.example.org")).unwrap();
    let default_key = store.resolve(Some("nothing.org")).unwrap();

    assert!(!Arc::ptr_eq(&exact_key, &wild_key));
    assert!(!Arc::ptr_eq(&wild_key, &default_key));
    assert!(Arc::ptr_eq(&store.resolve(None).unwrap(), &default_key));
    assert_eq!(store.len(), 3);
    assert!(only_default.resolve(None).is_some());
}

#[test]
fn resolution_ignores_the_case_of_the_name() {
    let store = CertStore::build(&[entry(&["API.example.org"], false)]).unwrap();

    assert!(store.resolve(Some("api.EXAMPLE.org")).is_some());
}

#[test]
fn a_wildcard_matches_a_single_label_only() {
    let store = CertStore::build(&[entry(&["*.example.org"], false)]).unwrap();

    assert!(store.resolve(Some("a.example.org")).is_some());
    assert!(store.resolve(Some("a.b.example.org")).is_none());
    assert!(store.resolve(Some("example.org")).is_none());
    assert!(store.resolve(Some(".example.org")).is_none());
}

#[test]
fn the_longest_wildcard_wins() {
    let short = entry(&["*.example.org"], false);
    let long = entry(&["*.b.example.org"], false);
    let store = CertStore::build(&[short, long.clone()]).unwrap();
    let expected = load_cert_files(&long.cert_file, &long.key_file).unwrap();

    let key = store.resolve(Some("a.b.example.org")).unwrap();

    assert_eq!(key.cert, expected.certified_key.cert);
}

#[test]
fn an_unmatched_name_without_a_default_resolves_to_nothing() {
    let store = CertStore::build(&[entry(&["api.example.org"], false)]).unwrap();

    assert!(store.resolve(Some("other.org")).is_none());
    assert!(store.resolve(None).is_none());
}

#[test]
fn names_resolved_to_one_entry_share_its_certificate() {
    let shared = entry(&["api.example.org", "*.wild.example.org"], false);
    let other = entry(&["other.example.org"], false);
    let store = CertStore::build(&[shared, other]).unwrap();

    assert!(store.same_certificate("api.example.org", "foo.wild.example.org"));
    assert!(store.same_certificate("API.example.org", "api.example.org"));
    assert!(!store.same_certificate("api.example.org", "other.example.org"));
}

#[test]
fn names_resolved_to_nothing_share_no_certificate() {
    let store = CertStore::build(&[entry(&["api.example.org"], false)]).unwrap();

    assert!(!store.same_certificate("x.org", "y.org"));
    assert!(!store.same_certificate("api.example.org", "y.org"));
}

#[test]
fn rejects_two_defaults() {
    let first = entry(&[], true);
    let second = entry(&[], true);

    let err = CertStore::build(&[first.clone(), second.clone()])
        .err()
        .unwrap();

    assert!(
        matches!(&err, TlsError::TwoDefaults { first: a, second: b }
            if *a == first.cert_file && *b == second.cert_file),
        "{err}"
    );
}

#[test]
fn an_unusable_entry_is_named_by_its_sni_names() {
    let broken = entry(&["api.example.org", "*.example.org"], false);
    let (_, other_key) = self_signed(&["api.example.org"]);
    std::fs::write(&broken.key_file, other_key).unwrap();

    let err = CertStore::build(&[broken]).err().unwrap();

    let message = err.to_string();
    assert!(
        message.contains("api.example.org, *.example.org"),
        "{message}"
    );
    assert!(message.contains("does not match"), "{message}");
}

#[test]
fn an_unusable_default_entry_is_named_as_the_default() {
    let broken = entry(&[], true);
    std::fs::write(&broken.cert_file, b"garbage").unwrap();

    let err = CertStore::build(&[broken]).err().unwrap();

    assert!(err.to_string().contains("<default>"), "{err}");
}

#[test]
fn expiries_are_listed_per_sni_name_and_for_the_default() {
    let store = CertStore::build(&[
        entry(&["api.example.org", "*.Wild.example.org"], true),
        entry(&["other.example.org"], false),
    ])
    .unwrap();

    let names: Vec<&str> = store
        .expiries()
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();

    assert_eq!(
        names,
        [
            "<default>",
            "api.example.org",
            "*.wild.example.org",
            "other.example.org"
        ]
    );
    assert!(store.expiries().iter().all(|(_, not_after)| *not_after > 0));
}

#[test]
fn an_empty_store_is_empty() {
    let store = CertStore::default();

    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
}
