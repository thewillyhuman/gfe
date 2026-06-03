//! Host and path matching primitives.

/// Match a request host against a route host pattern.
///
/// Patterns:
/// - `*` matches any host.
/// - `*.example.org` matches a single extra label: `api.example.org` ✓,
///   `example.org` ✗, `a.b.example.org` ✗.
/// - anything else is an exact (case-insensitive) match.
///
/// This is the slow-path reference used in tests and for `any`/wildcard
/// fallback; the compiled table buckets exact hosts into a map.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // host must be `<single-label>.<suffix>`
        match host.strip_suffix(suffix) {
            Some(prefix) => {
                let prefix = prefix.strip_suffix('.').unwrap_or(prefix);
                !prefix.is_empty() && !prefix.contains('.')
            }
            None => false,
        }
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

/// Returns `true` if `prefix` is a path prefix of `path`, respecting path
/// segment boundaries: `/api` matches `/api` and `/api/x` but not `/apix`.
/// A prefix ending in `/` matches purely as a string prefix.
pub fn path_prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" || prefix.is_empty() {
        return true;
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        rest.is_empty() || rest.starts_with('/') || prefix.ends_with('/')
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_host_single_label() {
        assert!(host_matches("*.example.org", "api.example.org"));
        assert!(!host_matches("*.example.org", "example.org"));
        assert!(!host_matches("*.example.org", "a.b.example.org"));
    }

    #[test]
    fn any_and_exact_host() {
        assert!(host_matches("*", "anything.org"));
        assert!(host_matches("API.example.org", "api.example.org"));
        assert!(!host_matches("api.example.org", "other.example.org"));
    }

    #[test]
    fn path_boundaries() {
        assert!(path_prefix_matches("/", "/anything"));
        assert!(path_prefix_matches("/api", "/api"));
        assert!(path_prefix_matches("/api", "/api/v1"));
        assert!(!path_prefix_matches("/api", "/apix"));
        assert!(path_prefix_matches("/api/", "/api/v1"));
    }
}
