use super::*;

#[test]
fn takes_up_to_the_cap_and_no_further() {
    let limit = ConcurrencyLimit::new(Some(2));

    let first = limit.try_acquire();
    let second = limit.try_acquire();
    let third = limit.try_acquire();

    assert!(first.is_ok() && second.is_ok());
    assert_eq!(third.unwrap_err(), LimitReached { max: 2 });
    assert_eq!(limit.in_use(), 2);
}

#[test]
fn a_dropped_permit_makes_room_again() {
    let limit = ConcurrencyLimit::new(Some(1));
    let only = limit.try_acquire().unwrap();

    drop(only);

    assert_eq!(limit.in_use(), 0);
    assert!(limit.try_acquire().is_ok());
}

#[test]
fn without_a_cap_everything_is_taken_and_counted() {
    let limit = ConcurrencyLimit::new(None);

    let permits: Vec<_> = (0..1000).map(|_| limit.try_acquire().unwrap()).collect();

    assert_eq!(limit.in_use(), permits.len());
}

#[test]
fn reports_its_cap() {
    assert_eq!(ConcurrencyLimit::new(Some(7)).max(), Some(7));
    assert_eq!(ConcurrencyLimit::new(None).max(), None);
}
