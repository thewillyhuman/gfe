//! Process and runtime saturation: the resources a node runs out of before
//! it runs out of anything the proxy itself counts.
//!
//! The `process_*` series follow the names every Prometheus client library
//! uses, so stock dashboards and alerts work. They are read from `/proc` and
//! therefore only reported on Linux.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The unit of the CPU times in `/proc/<pid>/stat`. A fixed part of the
/// kernel's userspace ABI, whatever the kernel's internal tick rate.
const USER_HZ: f64 = 100.0;

/// `version` label of the build-info series.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BuildLabels {
    pub version: String,
}

/// Process-level and async-runtime metrics.
pub struct ProcessMetrics {
    open_fds: Gauge,
    max_fds: Gauge,
    resident_memory_bytes: Gauge,
    cpu_seconds: Counter<f64, AtomicU64>,
    /// CPU seconds already added to `cpu_seconds`.
    cpu_seconds_reported: Mutex<f64>,
    /// Worker threads of the async runtime.
    pub runtime_workers: Gauge,
    /// Tasks alive on the runtime (roughly: connections plus housekeeping).
    pub runtime_alive_tasks: Gauge,
    /// Tasks waiting in the runtime's global queue for a free worker. Stays
    /// near zero unless the workers are saturated.
    pub runtime_global_queue_depth: Gauge,
}

impl ProcessMetrics {
    pub fn register(registry: &mut Registry) -> Self {
        let m = ProcessMetrics {
            open_fds: Gauge::default(),
            max_fds: Gauge::default(),
            resident_memory_bytes: Gauge::default(),
            cpu_seconds: Counter::default(),
            cpu_seconds_reported: Mutex::new(0.0),
            runtime_workers: Gauge::default(),
            runtime_alive_tasks: Gauge::default(),
            runtime_global_queue_depth: Gauge::default(),
        };

        let build_info = Family::<BuildLabels, Gauge>::default();
        build_info
            .get_or_create(&BuildLabels {
                version: env!("CARGO_PKG_VERSION").to_string(),
            })
            .set(1);
        registry.register("gfe_build_info", "Build version (always 1)", build_info);

        let start_time = Gauge::<i64>::default();
        let now = SystemTime::now().duration_since(UNIX_EPOCH);
        start_time.set(now.map(|d| d.as_secs() as i64).unwrap_or(0));
        registry.register(
            "process_start_time_seconds",
            "Start time of the process, Unix seconds",
            start_time,
        );

        registry.register(
            "process_open_fds",
            "Open file descriptors",
            m.open_fds.clone(),
        );
        registry.register(
            "process_max_fds",
            "Maximum number of open file descriptors",
            m.max_fds.clone(),
        );
        registry.register(
            "process_resident_memory_bytes",
            "Resident memory size",
            m.resident_memory_bytes.clone(),
        );
        registry.register(
            "process_cpu_seconds",
            "User and system CPU time spent",
            m.cpu_seconds.clone(),
        );
        registry.register(
            "gfe_runtime_workers",
            "Worker threads of the async runtime",
            m.runtime_workers.clone(),
        );
        registry.register(
            "gfe_runtime_alive_tasks",
            "Tasks alive on the async runtime",
            m.runtime_alive_tasks.clone(),
        );
        registry.register(
            "gfe_runtime_global_queue_depth",
            "Tasks queued for a free runtime worker",
            m.runtime_global_queue_depth.clone(),
        );
        m
    }

    /// Bring the `process_*` series up to date. Called before every scrape;
    /// does nothing where there is no `/proc`.
    pub fn refresh(&self) {
        let read = |file: &str| std::fs::read_to_string(format!("/proc/self/{file}")).ok();
        if let Ok(fds) = std::fs::read_dir("/proc/self/fd") {
            // One of the entries is the descriptor used to list them.
            self.open_fds.set(fds.count().saturating_sub(1) as i64);
        }
        if let Some(max) = read("limits").as_deref().and_then(max_open_files) {
            self.max_fds.set(max);
        }
        if let Some(rss) = read("status").as_deref().and_then(resident_bytes) {
            self.resident_memory_bytes.set(rss);
        }
        if let Some(total) = read("stat").as_deref().and_then(cpu_seconds) {
            let mut reported = self
                .cpu_seconds_reported
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if total > *reported {
                self.cpu_seconds.inc_by(total - *reported);
                *reported = total;
            }
        }
    }
}

/// The soft limit on open files, from `/proc/<pid>/limits`.
fn max_open_files(limits: &str) -> Option<i64> {
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    line.split_whitespace().nth(3)?.parse().ok()
}

/// The resident set size in bytes, from `/proc/<pid>/status`.
fn resident_bytes(status: &str) -> Option<i64> {
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kilobytes: i64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kilobytes * 1024)
}

/// User plus system CPU time in seconds, from `/proc/<pid>/stat`.
fn cpu_seconds(stat: &str) -> Option<f64> {
    // The second field is the command name in parentheses and may itself
    // contain spaces or parentheses, so count fields from its end.
    let after_name = &stat[stat.rfind(')')? + 1..];
    let mut fields = after_name.split_whitespace();
    let user: f64 = fields.nth(11)?.parse().ok()?;
    let system: f64 = fields.next()?.parse().ok()?;
    Some((user + system) / USER_HZ)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_soft_open_files_limit() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                      Max cpu time              unlimited            unlimited            seconds\n\
                      Max open files            1048576              2097152              files\n";
        assert_eq!(max_open_files(limits), Some(1_048_576));
    }

    #[test]
    fn reads_resident_memory_in_bytes() {
        let status = "Name:\tgfe-node\nVmPeak:\t  300000 kB\nVmRSS:\t   20480 kB\n";
        assert_eq!(resident_bytes(status), Some(20_480 * 1024));
    }

    #[test]
    fn reads_cpu_time_despite_spaces_in_the_command_name() {
        let stat = "4242 (gfe node) S 1 4242 4242 0 -1 4194560 100 0 0 0 \
                    1250 250 0 0 20 0 9 0 12345 1000000 5120 18446744073709551615";
        assert_eq!(cpu_seconds(stat), Some(15.0));
    }

    #[test]
    fn missing_data_is_not_reported() {
        assert_eq!(max_open_files(""), None);
        assert_eq!(resident_bytes("Name:\tgfe-node\n"), None);
        assert_eq!(cpu_seconds("garbage"), None);
    }
}
