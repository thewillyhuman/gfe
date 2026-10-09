use super::*;
use std::time::Instant;

#[test]
fn proc_stat_cpu_is_user_plus_system_time() {
    // proc(5): the pid, the command in parentheses (which may hold spaces
    // and parentheses of its own), then the fields; utime is the 14th and
    // stime the 15th, in USER_HZ ticks: 150 + 50 ticks is 2 s.
    let stat = "4242 (gfe node (x)) S 1 4242 4242 0 -1 4194560 1000 0 0 0 150 50 0 0 20 0 9 0 12345 1000000 500 18446744073709551615\n";

    assert_eq!(parse_proc_stat(stat), Some(Duration::from_secs(2)));
}

#[test]
fn proc_stat_without_the_time_fields_is_rejected() {
    assert_eq!(parse_proc_stat("1 (x) S 1 1 1 0 -1 0 0 0 0 0"), None);
    assert_eq!(parse_proc_stat("1 (x) S 1 1 1 0 -1 0 0 0 0 0 a b"), None);
    assert_eq!(parse_proc_stat(""), None);
}

#[test]
fn ps_cputime_reads_hours_minutes_seconds_and_hundredths() {
    assert_eq!(
        parse_ps_cputime(" 0:01.23\n"),
        Some(Duration::from_millis(1_230))
    );
    assert_eq!(parse_ps_cputime("12:34"), Some(Duration::from_secs(754)));
    assert_eq!(
        parse_ps_cputime("1:02:03"),
        Some(Duration::from_secs(3_723))
    );
    assert_eq!(parse_ps_cputime("00:00:00"), Some(Duration::ZERO));
}

#[test]
fn ps_cputime_of_no_process_is_rejected() {
    assert_eq!(parse_ps_cputime(""), None);
    assert_eq!(parse_ps_cputime("\n"), None);
    assert_eq!(parse_ps_cputime("x:y"), None);
}

/// Read after the process has worked: a test process of its own, as
/// nextest starts one per test, may not have used a whole tick of the
/// kernel's clock (10 ms on Linux) by the time it looks at itself.
#[test]
fn the_cpu_of_this_process_rises_as_it_works() {
    let pid = std::process::id();
    let started = Instant::now();
    let mut sink = 0u64;
    while cpu_time(pid).unwrap().is_zero() && started.elapsed() < Duration::from_secs(5) {
        for i in 0..100_000u64 {
            sink = sink.wrapping_mul(31).wrapping_add(i);
        }
        std::hint::black_box(sink);
    }

    let used = cpu_time(pid).unwrap();

    assert!(
        used > Duration::ZERO,
        "{used:?} after {:?}",
        started.elapsed()
    );
}
