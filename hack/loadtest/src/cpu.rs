//! The CPU time a process has used so far, user and system together: from
//! `/proc` where there is one, from `ps` elsewhere.

use anyhow::{Context, Result};
use std::process::Command;
use std::time::Duration;

/// The unit of the times in `/proc/<pid>/stat`: USER_HZ, fixed at 100
/// in the kernel's user-space ABI whatever the kernel's own tick rate.
const PROC_TICKS_PER_SECOND: u64 = 100;

/// How much CPU the process `pid` has used so far.
pub fn cpu_time(pid: u32) -> Result<Duration> {
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        return parse_proc_stat(&stat).with_context(|| format!("reading /proc/{pid}/stat"));
    }
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "cputime="])
        .output()
        .context("running ps")?;
    parse_ps_cputime(&String::from_utf8_lossy(&output.stdout))
        .with_context(|| format!("no cpu time from ps for process {pid}"))
}

/// The user plus system time of a `/proc/<pid>/stat` line: its 14th and
/// 15th fields, after the command name in parentheses.
fn parse_proc_stat(stat: &str) -> Option<Duration> {
    let after_command = &stat[stat.rfind(')')? + 1..];
    let mut fields = after_command.split_whitespace().skip(11);
    let user: u64 = fields.next()?.parse().ok()?;
    let system: u64 = fields.next()?.parse().ok()?;
    Some(Duration::from_secs_f64(
        (user + system) as f64 / PROC_TICKS_PER_SECOND as f64,
    ))
}

/// The `cputime` column of `ps`: `[[hours:]minutes:]seconds`, the seconds
/// with hundredths on some systems.
fn parse_ps_cputime(text: &str) -> Option<Duration> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut seconds = 0.0;
    for part in text.split(':') {
        seconds = seconds * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(Duration::from_secs_f64(seconds))
}

#[cfg(test)]
#[path = "cpu_test.rs"]
mod tests;
