//! Human-readable duration parsing for config fields (`"5s"`, `"250ms"`,
//! `"10us"`). Shared by every `Duration` field in [`crate::config`] so the
//! TOML and JSON config surfaces accept the same friendly format.

use std::time::Duration;

/// Parse a duration from a human-readable string like `"5s"`, `"250ms"`, `"10us"`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Some(val) = s.strip_suffix("us") {
        let n: u64 = val.trim().parse().map_err(|e| format!("{e}"))?;
        Ok(Duration::from_micros(n))
    } else if let Some(val) = s.strip_suffix("ms") {
        let n: u64 = val.trim().parse().map_err(|e| format!("{e}"))?;
        Ok(Duration::from_millis(n))
    } else if let Some(val) = s.strip_suffix('s') {
        let n: u64 = val.trim().parse().map_err(|e| format!("{e}"))?;
        Ok(Duration::from_secs(n))
    } else {
        Err(format!("unknown duration format: {s}"))
    }
}

/// Serialize a duration as a human-readable string.
pub fn serialize_duration<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let micros = duration.as_micros();
    let s = if micros.is_multiple_of(1_000_000) {
        format!("{}s", micros / 1_000_000)
    } else if micros.is_multiple_of(1_000) {
        format!("{}ms", micros / 1_000)
    } else {
        format!("{micros}us")
    };
    serializer.serialize_str(&s)
}

/// Deserialize a duration from a human-readable string like `"5s"`, `"50us"`, `"10ms"`.
pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let s = String::deserialize(deserializer)?;
    parse_duration(&s).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
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
}
