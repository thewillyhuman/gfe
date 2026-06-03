//! Per-backend health state machine with success/failure thresholds.

use crate::probe::ProbeResult;
use gfe_types::HealthStatus;

/// Tracks consecutive probe outcomes and decides committed state transitions.
#[derive(Debug, Clone)]
pub struct BackendHealth {
    status: HealthStatus,
    consecutive_success: u32,
    consecutive_failure: u32,
}

impl Default for BackendHealth {
    fn default() -> Self {
        BackendHealth {
            status: HealthStatus::Unknown,
            consecutive_success: 0,
            consecutive_failure: 0,
        }
    }
}

impl BackendHealth {
    pub fn status(&self) -> HealthStatus {
        self.status
    }

    /// Record a probe outcome. Returns `Some(new_status)` when the committed
    /// status transitions, `None` otherwise.
    ///
    /// A `Drain` outcome takes effect immediately (lame duck must stop new
    /// traffic promptly); `Pass`/`Fail` are debounced by the thresholds.
    pub fn record(
        &mut self,
        outcome: ProbeResult,
        healthy_threshold: u32,
        unhealthy_threshold: u32,
    ) -> Option<HealthStatus> {
        match outcome {
            ProbeResult::Drain => {
                self.consecutive_success = 0;
                self.consecutive_failure = 0;
                if self.status != HealthStatus::Draining {
                    self.status = HealthStatus::Draining;
                    return Some(self.status);
                }
                None
            }
            ProbeResult::Pass => {
                self.consecutive_success = self.consecutive_success.saturating_add(1);
                self.consecutive_failure = 0;
                if self.status != HealthStatus::Healthy
                    && self.consecutive_success >= healthy_threshold
                {
                    self.status = HealthStatus::Healthy;
                    return Some(self.status);
                }
                None
            }
            ProbeResult::Fail => {
                self.consecutive_failure = self.consecutive_failure.saturating_add(1);
                self.consecutive_success = 0;
                if self.status != HealthStatus::Unhealthy
                    && self.consecutive_failure >= unhealthy_threshold
                {
                    self.status = HealthStatus::Unhealthy;
                    return Some(self.status);
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ProbeResult::{Drain, Fail, Pass};

    #[test]
    fn transitions_after_thresholds() {
        let mut bh = BackendHealth::default();
        assert_eq!(bh.status(), HealthStatus::Unknown);
        assert_eq!(bh.record(Pass, 2, 3), None);
        assert_eq!(bh.record(Pass, 2, 3), Some(HealthStatus::Healthy));
        assert_eq!(bh.record(Fail, 2, 3), None);
        assert_eq!(bh.record(Fail, 2, 3), None);
        assert_eq!(bh.record(Fail, 2, 3), Some(HealthStatus::Unhealthy));
    }

    #[test]
    fn unknown_to_unhealthy() {
        let mut bh = BackendHealth::default();
        assert_eq!(bh.record(Fail, 2, 2), None);
        assert_eq!(bh.record(Fail, 2, 2), Some(HealthStatus::Unhealthy));
    }

    #[test]
    fn success_resets_failures() {
        let mut bh = BackendHealth::default();
        bh.record(Fail, 2, 3);
        bh.record(Fail, 2, 3);
        bh.record(Pass, 2, 3); // resets failure run
        assert_eq!(bh.record(Fail, 2, 3), None);
    }

    #[test]
    fn drain_takes_effect_immediately() {
        let mut bh = BackendHealth::default();
        bh.record(Pass, 1, 1); // → Healthy
        assert_eq!(bh.record(Drain, 2, 3), Some(HealthStatus::Draining));
        // Idempotent while draining.
        assert_eq!(bh.record(Drain, 2, 3), None);
        // Recovery back to Healthy after threshold passes.
        assert_eq!(bh.record(Pass, 1, 3), Some(HealthStatus::Healthy));
    }
}
