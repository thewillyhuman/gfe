use super::*;

const MS: Duration = Duration::from_millis(1);

/// A bucket of `burst` permits refilled at `per_second` a second.
fn bucket_of(per_second: u32, burst: u32) -> TokenBucket {
    TokenBucket::new(
        NonZeroU32::new(per_second).unwrap(),
        NonZeroU32::new(burst).unwrap(),
    )
}

#[test]
fn starts_full() {
    let bucket = bucket_of(1, 3);
    let now = Instant::now();

    let taken = (0..3).filter(|_| bucket.try_acquire(now).is_ok()).count();

    assert_eq!(taken, 3);
}

#[test]
fn refuses_when_empty() {
    let bucket = bucket_of(1, 2);
    let now = Instant::now();
    bucket.try_acquire(now).unwrap();
    bucket.try_acquire(now).unwrap();

    let refused = bucket.try_acquire(now);

    assert_eq!(
        refused,
        Err(RateLimited {
            per_second: 1,
            burst: 2
        })
    );
}

#[test]
fn refills_at_the_rate() {
    let bucket = bucket_of(10, 1);
    let start = Instant::now();
    bucket.try_acquire(start).unwrap();

    // One permit every 100 ms.
    let too_early = bucket.try_acquire(start + 99 * MS);
    let on_time = bucket.try_acquire(start + 100 * MS);

    assert!(too_early.is_err());
    assert!(on_time.is_ok());
}

#[test]
fn keeps_the_fraction_of_a_permit_already_earned() {
    let bucket = bucket_of(10, 1);
    let start = Instant::now();
    bucket.try_acquire(start).unwrap();

    // Two refused attempts 60 ms apart earn the permit between them.
    assert!(bucket.try_acquire(start + 60 * MS).is_err());

    assert!(bucket.try_acquire(start + 100 * MS).is_ok());
}

#[test]
fn never_holds_more_than_the_burst() {
    let bucket = bucket_of(10, 2);
    let start = Instant::now();
    bucket.try_acquire(start).unwrap();
    let later = start + Duration::from_secs(3600);

    let taken = (0..10)
        .filter(|_| bucket.try_acquire(later).is_ok())
        .count();

    assert_eq!(taken, 2);
}

#[test]
fn a_clock_that_goes_backwards_does_no_harm() {
    let bucket = bucket_of(10, 1);
    let start = Instant::now() + Duration::from_secs(1);
    bucket.try_acquire(start).unwrap();

    let earlier = bucket.try_acquire(start - Duration::from_secs(1));
    let back_on_time = bucket.try_acquire(start + 100 * MS);

    assert!(earlier.is_err(), "going back in time earned a permit");
    assert!(back_on_time.is_ok(), "going back in time lost a permit");
}

#[test]
fn can_be_shared_between_threads() {
    fn shareable<T: Send + Sync + 'static>() {}
    shareable::<TokenBucket>();
}
