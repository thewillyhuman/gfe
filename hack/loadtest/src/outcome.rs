//! What a scenario measured, and the row it is reported on.

use std::fmt;

/// What one scenario of the load client measured.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The scenario's name, as printed on its row.
    pub label: String,
    /// `keepalive`, `reconnect` or `reconnect+full-tls`.
    pub mode: String,
    /// Requests answered with a success status.
    pub requests: u64,
    pub requests_per_second: f64,
    /// Latency of the answered requests, in microseconds.
    pub p50_us: f64,
    pub p90_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
    /// Attempts that failed: a connection refused, a handshake that did
    /// not complete, a status that was not a success.
    pub errors: u64,
}

impl Outcome {
    /// Summarise a run that took `elapsed_secs`: `latencies` are the
    /// nanoseconds each answered request took, in any order.
    pub fn measure(
        label: &str,
        mode: &str,
        latencies: &mut [u64],
        errors: u64,
        elapsed_secs: f64,
    ) -> Outcome {
        latencies.sort_unstable();
        let requests = latencies.len() as u64;
        Outcome {
            label: label.to_string(),
            mode: mode.to_string(),
            requests,
            requests_per_second: requests as f64 / elapsed_secs,
            p50_us: percentile_us(latencies, 0.50),
            p90_us: percentile_us(latencies, 0.90),
            p99_us: percentile_us(latencies, 0.99),
            max_us: percentile_us(latencies, 1.0),
            errors,
        }
    }
}

/// The `p`-th percentile (0 to 1) of `sorted` nanoseconds, in
/// microseconds; 0 of nothing.
fn percentile_us(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[index] as f64 / 1000.0
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<38} {:<10} reqs={:<9} {:>10.0} req/s  p50={:>8.1}µs p90={:>8.1}µs p99={:>9.1}µs max={:>9.1}µs errors={}",
            self.label,
            self.mode,
            self.requests,
            self.requests_per_second,
            self.p50_us,
            self.p90_us,
            self.p99_us,
            self.max_us,
            self.errors
        )
    }
}

#[cfg(test)]
#[path = "outcome_test.rs"]
mod tests;
