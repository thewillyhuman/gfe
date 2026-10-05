use super::*;
use crate::proxy::record::Arrival;
use crate::proxy::test_support::state;
use http::{Method, Version};

fn record() -> RequestRecord {
    RequestRecord::begin(
        Instant::now(),
        Arrival {
            client: Some("127.0.0.1:5000".parse().unwrap()),
            listener: "http".into(),
            is_tls: false,
            sni: None,
            tls_version: None,
            tls_cipher: None,
        },
        "abc".into(),
        Method::GET,
        Version::HTTP_11,
        "/".into(),
        None,
        false,
    )
}

fn requests_total(state: &State, status: u16) -> bool {
    state.metrics().encode().contains(&format!(
        r#"gfe_requests_total{{listener="http",vhost="none",route="none",status="{status}"}} 1"#
    ))
}

#[test]
fn reports_a_request_once() {
    let state = state();
    let mut ctx = RequestCtx::new(Arc::clone(&state));
    ctx.begin(record(), None);

    ctx.finish(Some(200), (0, 0), Termination::Complete);
    ctx.finish(Some(502), (0, 0), Termination::Complete);
    drop(ctx);

    assert!(requests_total(&state, 200));
    assert!(!state.metrics().encode().contains(r#"status="502""#));
    assert!(!state.metrics().encode().contains(r#"status="499""#));
}

#[test]
fn reports_a_request_dropped_before_its_end_as_abandoned() {
    let state = state();
    let mut ctx = RequestCtx::new(Arc::clone(&state));
    ctx.begin(record(), None);

    drop(ctx);

    assert!(requests_total(&state, 499));
    assert!(
        state
            .metrics()
            .encode()
            .contains("gfe_requests_in_flight 0")
    );
}

#[test]
fn reports_nothing_for_a_request_never_begun() {
    let state = state();

    drop(RequestCtx::new(Arc::clone(&state)));

    assert!(!state.metrics().encode().contains("gfe_requests_total{"));
}

#[test]
fn keeps_the_connection_busy_until_the_request_is_reported() {
    let state = state();
    let listener = Arc::new(arc_swap::ArcSwap::from_pointee(gfe_config::Listener {
        id: gfe_config::ListenerId("http".into()),
        address: "127.0.0.1".parse().unwrap(),
        port: 80,
        protocol: gfe_config::ListenProtocol::Http,
    }));
    let conn = ConnInfo::new(
        "127.0.0.1:5000".parse().unwrap(),
        "127.0.0.1:80".parse().unwrap(),
        listener,
        None,
    );
    let mut ctx = RequestCtx::new(state);
    ctx.begin(record(), Some(&conn));
    assert!(conn.has_request_in_flight());

    ctx.finish(Some(200), (0, 0), Termination::Complete);

    assert!(!conn.has_request_in_flight());
}

#[test]
fn an_answer_sets_the_status_and_grpc_status() {
    let mut ctx = RequestCtx::new(state());
    ctx.begin(record(), None);

    ctx.answering(&crate::proxy::respond::refusal(
        Refusal::NoRoute,
        "abc",
        true,
    ));

    assert!(ctx.answer_attempted);
    assert_eq!(ctx.record().status, Some(200));
    assert_eq!(ctx.record().grpc_status, Some(12));
}
