//! What a process tells about itself: its metrics, exposed in the
//! Prometheus text format, and its log, which never holds up whoever logs.
//!
//! The crate defines no metric. The caller registers its own families in a
//! [`Registry`], with the metric types and the label derive re-exported
//! here, so that only this crate names `prometheus-client`.

pub mod logging;

pub use logging::{Log, LogSettings};

/// The crate the label derive expands to; see [`EncodeLabelSet`].
pub use prometheus_client;
/// Derives the encoding of a struct of labels. Its expansion names the
/// `prometheus_client` crate, so a module that derives it also brings
/// [`prometheus_client`] into scope:
/// `use netkit_observability::prometheus_client;`.
pub use prometheus_client::encoding::EncodeLabelSet;
pub use prometheus_client::metrics::counter::Counter;
pub use prometheus_client::metrics::family::Family;
pub use prometheus_client::metrics::gauge::Gauge;
pub use prometheus_client::metrics::histogram::Histogram;
pub use prometheus_client::registry::Registry;

use std::collections::HashSet;

/// Every metric of `registry` in the Prometheus text exposition format
/// (OpenMetrics flavour), ending with `# EOF`.
pub fn encode(registry: &Registry) -> String {
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, registry)
        .expect("writing to a String does not fail");
    text
}

/// `exposition` without the family metadata (`# HELP`, `# TYPE`, `# UNIT`)
/// of its histograms. Their `_bucket`, `_sum` and `_count` series are then
/// series of no declared type, which is all a query over them needs.
///
/// It is for collectors that rebuild a scraped histogram in a model of
/// their own and get it wrong, so that it is lost further on. Given series
/// of no declared type, they pass them on as they are.
pub fn without_histogram_metadata(exposition: &str) -> String {
    let histograms: HashSet<&str> = exposition
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE ")?.strip_suffix(" histogram"))
        .collect();
    let describes_a_histogram = |line: &str| {
        ["# HELP ", "# TYPE ", "# UNIT "].iter().any(|prefix| {
            line.strip_prefix(prefix)
                .and_then(|rest| rest.split(' ').next())
                .is_some_and(|family| histograms.contains(family))
        })
    };
    let mut untyped = String::with_capacity(exposition.len());
    for line in exposition
        .lines()
        .filter(|line| !describes_a_histogram(line))
    {
        untyped.push_str(line);
        untyped.push('\n');
    }
    untyped
}

#[cfg(test)]
#[path = "lib_test.rs"]
mod tests;
