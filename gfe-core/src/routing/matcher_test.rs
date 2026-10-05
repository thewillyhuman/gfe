use super::*;

#[test]
fn wildcard_host_matches_a_single_label() {
    assert!(host_matches("*.example.org", "api.example.org"));
    assert!(!host_matches("*.example.org", "example.org"));
    assert!(!host_matches("*.example.org", "a.b.example.org"));
}

#[test]
fn wildcard_host_requires_the_dot_before_the_suffix() {
    assert!(!host_matches("*.example.org", "fooexample.org"));
}

#[test]
fn any_and_exact_host() {
    assert!(host_matches("*", "anything.org"));
    assert!(host_matches("API.example.org", "api.example.org"));
    assert!(!host_matches("api.example.org", "other.example.org"));
}

#[test]
fn path_prefix_respects_segment_boundaries() {
    assert!(path_prefix_matches("/", "/anything"));
    assert!(path_prefix_matches("/api", "/api"));
    assert!(path_prefix_matches("/api", "/api/v1"));
    assert!(!path_prefix_matches("/api", "/apix"));
    assert!(path_prefix_matches("/api/", "/api/v1"));
}
