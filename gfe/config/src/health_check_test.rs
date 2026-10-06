use super::*;

#[test]
fn grpc_probe_type_is_spelled_grpc() {
    let check: HealthCheckConfig = serde_json::from_str(r#"{"type":"grpc"}"#).unwrap();
    assert_eq!(check.probe_type, ProbeType::Grpc);
}

#[test]
fn an_empty_check_takes_every_default() {
    let check: HealthCheckConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(check, HealthCheckConfig::default());
    assert_eq!(check.probe_type, ProbeType::Http);
    assert_eq!(check.interval, Duration::from_secs(5));
    assert_eq!(check.timeout, Duration::from_secs(2));
    assert_eq!(check.healthy_threshold, 2);
    assert_eq!(check.unhealthy_threshold, 3);
    assert_eq!(check.path, "/healthz");
    assert_eq!(check.expected_status, 200);
    assert_eq!(check.drain_status, None);
}

/// The last-known-good cache writes a pool's check back to JSON; what it
/// writes must read back the same.
#[test]
fn a_check_written_to_json_reads_back_the_same() {
    let check = HealthCheckConfig {
        probe_type: ProbeType::Tcp,
        interval: Duration::from_millis(1500),
        drain_status: Some(503),
        ..Default::default()
    };

    let json = serde_json::to_string(&check).unwrap();

    assert_eq!(
        serde_json::from_str::<HealthCheckConfig>(&json).unwrap(),
        check
    );
}
