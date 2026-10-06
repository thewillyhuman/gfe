use super::*;

#[test]
fn nothing_is_signalled_until_the_process_drains() {
    let drain = Drain::new();

    let subscriber = drain.subscribe();

    assert!(!*subscriber.borrow());
    assert!(!drain.is_draining());
}

#[test]
fn draining_signals_every_subscriber_old_and_new() {
    let drain = Drain::new();
    let before = drain.subscribe();

    drain.trigger();
    let after = drain.subscribe();

    assert!(*before.borrow());
    assert!(*after.borrow());
}

#[test]
fn a_drain_can_be_asked_whether_it_has_begun() {
    let drain = Drain::new();

    drain.trigger();

    assert!(drain.is_draining());
}

#[test]
fn triggering_twice_changes_nothing() {
    let drain = Drain::new();
    drain.trigger();
    let mut subscriber = drain.subscribe();
    subscriber.mark_unchanged();

    drain.trigger();

    assert!(drain.is_draining());
    assert!(!subscriber.has_changed().unwrap());
}
