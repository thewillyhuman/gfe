use super::*;
use crate::listener::test_support::shared;
use gfe_config::TimeoutsConfig;

#[test]
fn draining_fails_readiness_and_signals_every_subscriber() {
    let shared = shared(TimeoutsConfig::default());
    let drain = Drain::new();
    let before = drain.subscribe();

    drain.trigger(&shared);
    let after = drain.subscribe();

    assert!(shared.is_draining());
    assert!(*before.borrow());
    assert!(*after.borrow());
}

#[test]
fn nothing_is_signalled_until_the_node_drains() {
    let shared = shared(TimeoutsConfig::default());
    let drain = Drain::new();

    let shutdown = drain.subscribe();

    assert!(!*shutdown.borrow());
    assert!(!shared.is_draining());
}
