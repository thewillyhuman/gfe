//! What a scenario measured, the row it is reported on, and the JSON line
//! it is kept as for a later comparison.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

/// What one scenario of the load client measured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// The CPU a process of interest (the node) spent per answered
    /// request, in microseconds, when the run was told which process.
    pub cpu_us_per_request: Option<f64>,
    /// What each request uploaded, in bytes; 0 for a GET.
    #[serde(default)]
    pub bytes_per_request: u64,
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
            cpu_us_per_request: None,
            bytes_per_request: 0,
        }
    }

    /// What the requests uploaded per second, in MiB.
    pub fn upload_mib_per_second(&self) -> f64 {
        self.requests_per_second * self.bytes_per_request as f64 / (1024.0 * 1024.0)
    }

    /// Charge `cpu`, the CPU time a process spent during the run, to the
    /// answered requests.
    pub fn charge_cpu(&mut self, cpu: Duration) {
        let per_request = match self.requests {
            0 => 0.0,
            requests => cpu.as_secs_f64() * 1e6 / requests as f64,
        };
        self.cpu_us_per_request = Some(per_request);
    }

    /// Every outcome of `path`, one JSON line each, in order.
    pub fn read_all(path: &Path) -> Result<Vec<Outcome>> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line).with_context(|| format!("in {}", path.display()))
            })
            .collect()
    }

    /// Append this outcome to `path` as one JSON line, creating the file.
    pub fn append_to(&self, path: &Path) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        serde_json::to_writer(&mut file, self)?;
        file.write_all(b"\n")?;
        Ok(())
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
        )?;
        if self.bytes_per_request > 0 {
            write!(f, "  {:.0} MiB/s", self.upload_mib_per_second())?;
        }
        if let Some(cpu) = self.cpu_us_per_request {
            write!(f, "  cpu={cpu:.0}µs/req")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "outcome_test.rs"]
mod tests;
