use super::*;
use std::time::Duration;

fn timeouts() -> TimeoutsConfig {
    TimeoutsConfig {
        request_header: Duration::from_secs(10),
        client_idle: Duration::from_secs(75),
        ..Default::default()
    }
}

fn fresh(established: Instant) -> Activity {
    Activity {
        established,
        requests: 0,
        in_flight: false,
        idle_since: established,
    }
}

fn idle_after_one_request(established: Instant, idle_since: Instant) -> Activity {
    Activity {
        requests: 1,
        idle_since,
        ..fresh(established)
    }
}

#[test]
fn waits_for_the_first_request_until_request_header() {
    let established = Instant::now();

    let verdict = verdict(
        fresh(established),
        established + Duration::from_secs(9),
        &timeouts(),
        None,
    );

    assert_eq!(
        verdict,
        Verdict::CheckAgainAt(established + Duration::from_secs(10))
    );
}

#[test]
fn times_out_a_connection_that_never_sends_a_request() {
    let established = Instant::now();

    let verdict = verdict(
        fresh(established),
        established + Duration::from_secs(10),
        &timeouts(),
        None,
    );

    assert_eq!(verdict, Verdict::Expired(Expiry::Header));
}

#[test]
fn never_times_out_while_a_request_is_in_flight() {
    let established = Instant::now();
    let busy = Activity {
        requests: 1,
        in_flight: true,
        ..fresh(established)
    };

    let verdict = verdict(
        busy,
        established + Duration::from_secs(3600),
        &timeouts(),
        Some(established),
    );

    assert_eq!(verdict, Verdict::WaitUntilIdle);
}

#[test]
fn times_out_once_idle_for_client_idle_after_the_last_request() {
    let established = Instant::now();
    let finished = established + Duration::from_secs(30);
    let activity = idle_after_one_request(established, finished);

    let before = verdict(
        activity,
        finished + Duration::from_secs(74),
        &timeouts(),
        None,
    );
    let after = verdict(
        activity,
        finished + Duration::from_secs(75),
        &timeouts(),
        None,
    );

    assert_eq!(
        before,
        Verdict::CheckAgainAt(finished + Duration::from_secs(75))
    );
    assert_eq!(after, Verdict::Expired(Expiry::Idle));
}

#[test]
fn a_draining_node_waits_for_one_more_request_until_it_must_leave() {
    let established = Instant::now();
    let leave_by = established + Duration::from_secs(5);

    let verdict = verdict(
        idle_after_one_request(established, established),
        established + Duration::from_secs(1),
        &timeouts(),
        Some(leave_by),
    );

    assert_eq!(verdict, Verdict::CheckAgainAt(leave_by));
}

#[test]
fn a_draining_node_ends_an_idle_connection_once_it_must_leave() {
    let established = Instant::now();
    let leave_by = established + Duration::from_secs(5);

    let verdict = verdict(
        idle_after_one_request(established, established),
        leave_by,
        &timeouts(),
        Some(leave_by),
    );

    assert_eq!(verdict, Verdict::Expired(Expiry::Drain));
}

#[test]
fn a_timeout_due_before_the_drain_deadline_still_applies() {
    let established = Instant::now();
    let leave_by = established + Duration::from_secs(60);

    let verdict = verdict(
        fresh(established),
        established + Duration::from_secs(10),
        &timeouts(),
        Some(leave_by),
    );

    assert_eq!(verdict, Verdict::Expired(Expiry::Header));
}

#[test]
fn reads_the_activity_off_the_connection() {
    let conn = ConnInfo::new(
        "127.0.0.1:40000".parse().unwrap(),
        "127.0.0.1:443".parse().unwrap(),
        std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(gfe_config::Listener {
            id: gfe_config::ListenerId("http".into()),
            address: "127.0.0.1".parse().unwrap(),
            port: 443,
            protocol: gfe_config::ListenProtocol::Http,
        })),
        None,
    );
    let _request = conn.begin_request();

    let activity = Activity::of(&conn);

    assert_eq!(activity.requests, 1);
    assert!(activity.in_flight);
    assert_eq!(activity.established, conn.established());
}
