use super::*;

#[test]
fn parses_units() {
    assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
    assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    assert_eq!(parse_duration("10us").unwrap(), Duration::from_micros(10));
}

#[test]
fn rejects_unknown() {
    assert!(parse_duration("5").is_err());
    assert!(parse_duration("5m").is_err());
}

/// The text `serialize_duration` writes for `duration`.
fn written(duration: Duration) -> String {
    serialize_duration(&duration, serde_json::value::Serializer)
        .unwrap()
        .as_str()
        .expect("a duration is written as a string")
        .to_owned()
}

#[test]
fn writes_the_largest_unit_that_is_exact() {
    assert_eq!(written(Duration::from_secs(5)), "5s");
    assert_eq!(written(Duration::from_millis(250)), "250ms");
    assert_eq!(written(Duration::from_micros(10)), "10us");
}

#[test]
fn what_is_written_reads_back_the_same() {
    for duration in [
        Duration::ZERO,
        Duration::from_secs(60),
        Duration::from_millis(1500),
        Duration::from_micros(1001),
    ] {
        assert_eq!(parse_duration(&written(duration)).unwrap(), duration);
    }
}
