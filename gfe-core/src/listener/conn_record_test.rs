use super::*;
use crate::listener::test_support::shared;
use gfe_config::{ListenProtocol, ListenerId, TimeoutsConfig};

/// A connection that was served, saw nothing special, and carried one
/// request that has been answered.
fn ordinary() -> Observed {
    Observed {
        handshake: Handshake::Done,
        served: true,
        panicked: false,
        expiry: None,
        end: None,
        draining: false,
        requests: 1,
        in_flight: false,
    }
}

#[test]
fn a_connection_closed_after_its_requests_is_closed() {
    let by_server = ordinary();
    let by_client = Observed {
        end: Some(WireEnd::Eof),
        ..ordinary()
    };

    assert_eq!(close_reason(&by_server), "closed");
    assert_eq!(close_reason(&by_client), "closed");
}

#[test]
fn a_client_that_leaves_in_the_middle_of_a_request_aborted_it() {
    let observed = Observed {
        end: Some(WireEnd::Eof),
        in_flight: true,
        ..ordinary()
    };

    assert_eq!(close_reason(&observed), "client_abort");
}

#[test]
fn a_reset_connection_is_a_client_abort() {
    let observed = Observed {
        end: Some(WireEnd::Reset),
        ..ordinary()
    };

    assert_eq!(close_reason(&observed), "client_abort");
}

#[test]
fn a_connection_timed_out_by_tcp_keepalive_is_unresponsive() {
    let observed = Observed {
        end: Some(WireEnd::TimedOut),
        ..ordinary()
    };

    assert_eq!(close_reason(&observed), "client_unresponsive");
}

#[test]
fn a_connection_idle_for_too_long_timed_out() {
    // An HTTP/2 client asked to leave closes the connection itself.
    let observed = Observed {
        expiry: Some(Expiry::Idle),
        end: Some(WireEnd::Eof),
        ..ordinary()
    };

    assert_eq!(close_reason(&observed), "idle_timeout");
}

#[test]
fn a_connection_that_never_sent_a_request_head_timed_out() {
    let observed = Observed {
        expiry: Some(Expiry::Header),
        requests: 0,
        ..ordinary()
    };

    assert_eq!(close_reason(&observed), "header_timeout");
}

#[test]
fn a_connection_ended_by_a_drain_is_drain() {
    let told_to_close = Observed {
        draining: true,
        ..ordinary()
    };
    let left_when_told = Observed {
        draining: true,
        end: Some(WireEnd::Eof),
        ..ordinary()
    };
    let idle_too_long = Observed {
        draining: true,
        expiry: Some(Expiry::Drain),
        ..ordinary()
    };

    assert_eq!(close_reason(&told_to_close), "drain");
    assert_eq!(close_reason(&left_when_told), "drain");
    assert_eq!(close_reason(&idle_too_long), "drain");
}

#[test]
fn a_connection_given_up_before_its_first_request_is_a_protocol_error() {
    let observed = Observed {
        requests: 0,
        ..ordinary()
    };

    assert_eq!(close_reason(&observed), "protocol_error");
}

#[test]
fn a_failed_handshake_is_tls_handshake_failed() {
    let observed = Observed {
        handshake: Handshake::Failed,
        served: false,
        requests: 0,
        ..ordinary()
    };

    assert_eq!(close_reason(&observed), "tls_handshake_failed");
}

#[test]
fn a_handshake_never_completed_is_tls_handshake_timeout() {
    let observed = Observed {
        handshake: Handshake::TimedOut,
        served: false,
        requests: 0,
        ..ordinary()
    };

    assert_eq!(close_reason(&observed), "tls_handshake_timeout");
}

#[test]
fn a_connection_that_failed_on_the_wire_or_with_a_request_in_flight_is_an_error() {
    let on_the_wire = Observed {
        end: Some(WireEnd::Error),
        ..ordinary()
    };
    let given_up_in_flight = Observed {
        in_flight: true,
        draining: true,
        ..ordinary()
    };
    let panicked = Observed {
        served: false,
        panicked: true,
        ..ordinary()
    };

    assert_eq!(close_reason(&on_the_wire), "error");
    assert_eq!(close_reason(&given_up_in_flight), "error");
    assert_eq!(close_reason(&panicked), "error");
}

#[test]
fn a_connection_cut_before_it_was_done_is_shutdown() {
    let observed = Observed {
        served: false,
        in_flight: true,
        draining: true,
        ..ordinary()
    };

    assert_eq!(close_reason(&observed), "shutdown");
}

fn listener() -> Listener {
    Listener {
        id: ListenerId("web".into()),
        address: "127.0.0.1".parse().unwrap(),
        port: 80,
        protocol: ListenProtocol::Http,
    }
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[test]
fn counts_a_connection_while_it_is_open_and_its_end_once() {
    let shared = shared(TimeoutsConfig::default());
    let record = ConnRecord::open(shared.clone(), &listener(), addr(80), addr(40000));
    let open = shared.metrics().encode();

    drop(record);

    let closed = shared.metrics().encode();
    assert!(open.contains("gfe_connections_active 1"), "{open}");
    assert!(
        open.contains(r#"gfe_connections_accepted_total{listener="web"} 1"#),
        "{open}"
    );
    assert!(closed.contains("gfe_connections_active 0"), "{closed}");
    assert!(
        closed.contains(r#"gfe_listener_connections_active{listener="web"} 0"#),
        "{closed}"
    );
    // Never handed to the application: its task was cut short.
    assert!(
        closed.contains(r#"gfe_connections_closed_total{listener="web",reason="shutdown"} 1"#),
        "{closed}"
    );
    assert!(
        closed.contains(r#"gfe_connection_duration_seconds_count{listener="web"} 1"#),
        "{closed}"
    );
}

#[test]
fn a_timed_out_handshake_is_counted_as_rejected() {
    let shared = shared(TimeoutsConfig::default());
    let mut record = ConnRecord::open(shared.clone(), &listener(), addr(443), addr(40000));

    record.tls_timed_out();
    drop(record);

    let exposed = shared.metrics().encode();
    assert!(
        exposed.contains(r#"gfe_connections_rejected_total{reason="handshake_timeout"} 1"#),
        "{exposed}"
    );
    assert!(
        exposed.contains(r#"reason="tls_handshake_timeout"} 1"#),
        "{exposed}"
    );
}

#[test]
fn reads_the_requests_off_the_registered_connection() {
    let shared = shared(TimeoutsConfig::default());
    let mut record = ConnRecord::open(shared.clone(), &listener(), addr(80), addr(40000));
    let conn = ConnInfo::new(
        addr(40000),
        addr(80),
        Arc::new(arc_swap::ArcSwap::from_pointee(listener())),
        None,
    );
    drop(conn.begin_request());

    record.serving(conn);
    record.served();

    assert_eq!(record.observed().requests, 1);
    assert_eq!(close_reason(&record.observed()), "closed");
}
