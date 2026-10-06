use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A resolver that answers `10.0.0.<n>` on its n-th lookup, or fails while
/// told to, and counts its lookups.
#[derive(Debug, Default, Clone)]
struct Scripted {
    lookups: Arc<AtomicUsize>,
    failing: Arc<AtomicBool>,
}

impl Resolve for Scripted {
    async fn resolve(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let n = self.lookups.fetch_add(1, Ordering::SeqCst) + 1;
        if self.failing.load(Ordering::SeqCst) {
            return Err(io::Error::other("resolver down"));
        }
        Ok(vec![SocketAddr::from(([10, 0, 0, n as u8], port))])
    }
}

/// How long the caches of these tests trust an answer.
const TTL: Duration = Duration::from_secs(10);

fn address(n: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, n], 80))
}

#[tokio::test]
async fn never_looks_up_an_ip_literal() {
    let resolver = Scripted::default();
    let cache = Cache::new(resolver.clone(), TTL);

    let v4 = cache
        .address("192.0.2.1", 80, Instant::now())
        .await
        .unwrap();
    let v6 = cache
        .address("2001:db8::1", 443, Instant::now())
        .await
        .unwrap();

    assert_eq!(v4, "192.0.2.1:80".parse().unwrap());
    assert_eq!(v6, "[2001:db8::1]:443".parse().unwrap());
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn answers_from_the_cache_while_the_answer_is_fresh() {
    let resolver = Scripted::default();
    let cache = Cache::new(resolver.clone(), TTL);
    let start = Instant::now();

    let first = cache.address("backend", 80, start).await.unwrap();
    let again = cache
        .address("backend", 80, start + TTL - Duration::from_millis(1))
        .await
        .unwrap();

    assert_eq!(first, address(1));
    assert_eq!(again, address(1));
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn looks_up_again_once_the_answer_is_stale() {
    let resolver = Scripted::default();
    let cache = Cache::new(resolver.clone(), TTL);
    let start = Instant::now();
    cache.address("backend", 80, start).await.unwrap();

    let refreshed = cache.address("backend", 80, start + TTL).await.unwrap();

    assert_eq!(refreshed, address(2));
}

#[tokio::test]
async fn keeps_the_last_answer_when_a_refresh_fails() {
    let resolver = Scripted::default();
    let cache = Cache::new(resolver.clone(), TTL);
    let start = Instant::now();
    cache.address("backend", 80, start).await.unwrap();
    resolver.failing.store(true, Ordering::SeqCst);

    let kept = cache.address("backend", 80, start + TTL * 3).await.unwrap();

    assert_eq!(kept, address(1));
}

#[tokio::test]
async fn fails_a_name_that_was_never_resolved() {
    let resolver = Scripted::default();
    resolver.failing.store(true, Ordering::SeqCst);
    let cache = Cache::new(resolver, TTL);

    let failed = cache.address("backend", 80, Instant::now()).await;

    assert!(failed.is_err());
}

#[tokio::test]
async fn caches_names_per_port() {
    let resolver = Scripted::default();
    let cache = Cache::new(resolver.clone(), TTL);
    let now = Instant::now();

    cache.address("backend", 80, now).await.unwrap();
    let other_port = cache.address("backend", 81, now).await.unwrap();

    assert_eq!(other_port, SocketAddr::from(([10, 0, 0, 2], 81)));
}

#[tokio::test]
async fn system_resolver_resolves_localhost() {
    let cache = Cache::new(SystemResolver, TTL);

    let resolved = cache
        .address("localhost", 80, Instant::now())
        .await
        .unwrap();

    assert!(resolved.ip().is_loopback(), "{resolved}");
}
