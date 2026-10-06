use super::*;

#[test]
fn exposes_every_process_metric_with_its_type() {
    let mut registry = Registry::default();
    ProcessMetrics::register(&mut registry);
    let text = netkit_observability::encode(&registry);

    for (name, kind) in [
        ("gfe_build_info", "gauge"),
        ("process_start_time_seconds", "gauge"),
        ("process_open_fds", "gauge"),
        ("process_max_fds", "gauge"),
        ("process_resident_memory_bytes", "gauge"),
        ("process_cpu_seconds", "counter"),
        ("gfe_runtime_workers", "gauge"),
        ("gfe_runtime_alive_tasks", "gauge"),
        ("gfe_runtime_global_queue_depth", "gauge"),
        ("gfe_log_lost_lines", "gauge"),
    ] {
        assert!(
            text.contains(&format!("# TYPE {name} {kind}\n")),
            "{name} {kind} missing from:\n{text}"
        );
    }
}

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
