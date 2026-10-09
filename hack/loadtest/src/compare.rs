//! Whether a change made the node slower: the outcomes of a run against
//! those of a base run, scenario by scenario, on the node's CPU per
//! request.

use crate::outcome::Outcome;
use std::fmt;

/// What was decided about one scenario.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Within the tolerance; the change against the base, in percent.
    Within(f64),
    /// Beyond the tolerance; the change against the base, in percent.
    Regressed(f64),
    /// Nothing could be decided; why.
    Unusable(String),
}

/// One scenario of the head run against the same one of the base run.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub label: String,
    /// The lowest CPU per request among the base's rounds of the scenario.
    pub base_cpu_us: Option<f64>,
    /// The same for the head.
    pub head_cpu_us: Option<f64>,
    pub verdict: Verdict,
}

/// A head run compared with a base run.
#[derive(Debug, Clone, PartialEq)]
pub struct Comparison {
    /// How much slower than the base, in percent, a scenario may be.
    pub tolerance_percent: f64,
    pub rows: Vec<Row>,
}

impl Comparison {
    /// Compare the scenarios of `head`, in the order they first appear,
    /// with the same scenarios of `base`. A side may hold several rounds
    /// of a scenario: the lowest CPU per request among them is its
    /// measurement, since noise only adds. A round with errors, or
    /// without a CPU measurement, makes the scenario unusable, as does a
    /// scenario the base did not run.
    pub fn of(base: &[Outcome], head: &[Outcome], tolerance_percent: f64) -> Comparison {
        let mut rows: Vec<Row> = Vec::new();
        for outcome in head {
            if rows.iter().any(|row| row.label == outcome.label) {
                continue;
            }
            rows.push(compare_one(&outcome.label, base, head, tolerance_percent));
        }
        Comparison {
            tolerance_percent,
            rows,
        }
    }

    /// Whether every scenario is within the tolerance.
    pub fn passed(&self) -> bool {
        self.rows
            .iter()
            .all(|row| matches!(row.verdict, Verdict::Within(_)))
    }
}

fn compare_one(label: &str, base: &[Outcome], head: &[Outcome], tolerance_percent: f64) -> Row {
    let base_cpu = best_cpu(label, base, "base");
    let head_cpu = best_cpu(label, head, "head");
    let verdict = match (&base_cpu, &head_cpu) {
        (Err(reason), _) | (_, Err(reason)) => Verdict::Unusable(reason.clone()),
        (Ok(base), Ok(head)) => {
            // To a tenth of a percent, which is what the table shows and
            // more than the measurement resolves.
            let change = ((head - base) / base * 1000.0).round() / 10.0;
            if change > tolerance_percent {
                Verdict::Regressed(change)
            } else {
                Verdict::Within(change)
            }
        }
    };
    Row {
        label: label.to_string(),
        base_cpu_us: base_cpu.ok(),
        head_cpu_us: head_cpu.ok(),
        verdict,
    }
}

/// The lowest CPU per request among the rounds of `label` on one `side`,
/// or why there is none.
fn best_cpu(label: &str, side: &[Outcome], side_name: &str) -> Result<f64, String> {
    let rounds: Vec<&Outcome> = side.iter().filter(|o| o.label == label).collect();
    if rounds.is_empty() {
        return Err(format!("not in {side_name}"));
    }
    let errors: u64 = rounds.iter().map(|o| o.errors).sum();
    if errors > 0 {
        let plural = if errors == 1 { "" } else { "s" };
        return Err(format!("{errors} error{plural} in {side_name}"));
    }
    rounds
        .iter()
        .filter_map(|o| o.cpu_us_per_request)
        .min_by(f64::total_cmp)
        .filter(|_| rounds.iter().all(|o| o.cpu_us_per_request.is_some()))
        .ok_or_else(|| format!("no cpu in {side_name}"))
}

impl fmt::Display for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{:<38} {:>13} {:>13} {:>9}",
            "scenario", "base µs/req", "head µs/req", "change"
        )?;
        for row in &self.rows {
            write!(
                f,
                "{:<38} {:>13} {:>13}",
                row.label,
                cpu_column(row.base_cpu_us),
                cpu_column(row.head_cpu_us)
            )?;
            match &row.verdict {
                Verdict::Within(change) => writeln!(f, " {change:>+8.1}%")?,
                Verdict::Regressed(change) => writeln!(f, " {change:>+8.1}%  REGRESSED")?,
                Verdict::Unusable(reason) => writeln!(f, " {:>9}  UNUSABLE: {reason}", "")?,
            }
        }
        let failed = self
            .rows
            .iter()
            .filter(|row| !matches!(row.verdict, Verdict::Within(_)))
            .count();
        let tolerance = self.tolerance_percent;
        if failed == 0 {
            writeln!(
                f,
                "passed: no scenario beyond the tolerance of {tolerance}% on the node's cpu per request"
            )
        } else {
            let plural = if failed == 1 { "" } else { "s" };
            writeln!(
                f,
                "FAILED: {failed} scenario{plural} beyond the tolerance of {tolerance}% on the node's cpu per request"
            )
        }
    }
}

fn cpu_column(cpu: Option<f64>) -> String {
    match cpu {
        Some(cpu) => format!("{cpu:.1}"),
        None => "-".to_string(),
    }
}

#[cfg(test)]
#[path = "compare_test.rs"]
mod tests;
