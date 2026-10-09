use super::*;

const MS: Duration = Duration::from_millis(1);
const SECOND: Duration = Duration::from_secs(1);

fn buckets(per_second: u32, burst: u32, capacity: usize) -> KeyedBuckets<&'static str> {
    KeyedBuckets::new(
        NonZeroU32::new(per_second).unwrap(),
        NonZeroU32::new(burst).unwrap(),
        NonZeroUsize::new(capacity).unwrap(),
    )
}

#[test]
fn limits_each_key_on_its_own() {
    let buckets = buckets(1, 1, 10);
    let now = Instant::now();

    let first_of_a = buckets.try_acquire("a", now);
    let first_of_b = buckets.try_acquire("b", now);
    let second_of_a = buckets.try_acquire("a", now);

    assert!(first_of_a.is_ok());
    assert!(first_of_b.is_ok());
    assert_eq!(
        second_of_a,
        Err(RateLimited {
            per_second: 1,
            burst: 1
        })
    );
}

#[test]
fn a_key_refills_at_the_rate() {
    let buckets = buckets(10, 1, 10);
    let start = Instant::now();
    buckets.try_acquire("a", start).unwrap();

    // One permit every 100 ms.
    let too_early = buckets.try_acquire("a", start + 99 * MS);
    let on_time = buckets.try_acquire("a", start + 100 * MS);

    assert!(too_early.is_err());
    assert!(on_time.is_ok());
}

#[test]
fn remembers_each_key_it_has_seen() {
    let buckets = buckets(1, 1, 10);
    let now = Instant::now();

    buckets.try_acquire("a", now).unwrap();
    buckets.try_acquire("b", now).unwrap();
    buckets.try_acquire("a", now).unwrap_err();

    assert_eq!(buckets.tracked(), 2);
}

#[test]
fn forgets_the_keys_that_have_refilled_when_it_is_full() {
    let buckets = buckets(1, 1, 2);
    let start = Instant::now();
    buckets.try_acquire("a", start).unwrap();
    buckets.try_acquire("b", start).unwrap();

    // A second later both have refilled: a key that is full again is one
    // that was never seen, so nothing is lost by forgetting it.
    let newcomer = buckets.try_acquire("c", start + SECOND);

    assert!(newcomer.is_ok());
    assert_eq!(buckets.tracked(), 1);
    assert_eq!(buckets.untracked(), 0);
}

#[test]
fn admits_a_new_key_uncounted_when_no_key_can_be_forgotten() {
    let buckets = buckets(1, 1, 2);
    let now = Instant::now();
    buckets.try_acquire("a", now).unwrap();
    buckets.try_acquire("b", now).unwrap();

    let first_of_c = buckets.try_acquire("c", now);
    let second_of_c = buckets.try_acquire("c", now);

    assert!(first_of_c.is_ok());
    assert!(second_of_c.is_ok(), "an uncounted key was refused");
    assert_eq!(buckets.tracked(), 2);
    assert_eq!(buckets.untracked(), 2);
}

#[test]
fn looks_for_keys_to_forget_at_most_once_a_second() {
    // Refills in half a second, so a key is idle well before the next look.
    let buckets = buckets(2, 1, 1);
    let start = Instant::now();
    buckets.try_acquire("a", start).unwrap();
    // Full: "a" has refilled, and is forgotten to make room for "b".
    buckets.try_acquire("b", start + SECOND).unwrap();

    // "b" has refilled too, but the last look was only 600 ms ago.
    buckets.try_acquire("c", start + SECOND + 600 * MS).unwrap();
    let after_the_wait = buckets.try_acquire("d", start + 2 * SECOND);

    assert_eq!(buckets.untracked(), 1);
    assert!(after_the_wait.is_ok());
    assert_eq!(
        buckets.tracked(),
        1,
        "\"d\" did not take the place of \"b\""
    );
}

#[test]
fn can_be_shared_between_threads() {
    fn shareable<T: Send + Sync + 'static>() {}
    shareable::<KeyedBuckets<std::net::IpAddr>>();
}
