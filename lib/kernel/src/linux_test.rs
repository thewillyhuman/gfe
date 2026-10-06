use super::*;

#[test]
fn a_service_with_both_capabilities_lacks_nothing() {
    // CAP_NET_BIND_SERVICE (10), CAP_NET_ADMIN (12) and CAP_BPF (39).
    let status = "Name:\tapp\nCapEff:\t0000008000001400\n";
    assert_eq!(missing_capabilities(status), None);
}

#[test]
fn root_with_cap_sys_admin_lacks_nothing() {
    let status = "CapEff:\t000001ffffffffff\n";
    assert_eq!(missing_capabilities(status), None);
}

#[test]
fn names_the_capabilities_an_unprivileged_process_lacks() {
    // Only CAP_NET_BIND_SERVICE: what a service binding a low port gets.
    let status = "CapEff:\t0000000000000400\n";
    assert_eq!(
        missing_capabilities(status),
        Some("the process lacks CAP_BPF and CAP_NET_ADMIN")
    );
}

#[test]
fn names_the_one_capability_that_is_missing() {
    let only_bpf = "CapEff:\t0000008000000000\n";
    assert_eq!(
        missing_capabilities(only_bpf),
        Some("the process lacks CAP_NET_ADMIN")
    );
}

#[test]
fn finds_the_cgroup_of_a_systemd_service() {
    let membership = "0::/system.slice/app.service\n";
    assert_eq!(
        own_cgroup(membership),
        Some(PathBuf::from("/sys/fs/cgroup/system.slice/app.service"))
    );
}

#[test]
fn finds_the_cgroup_of_a_container() {
    // Inside a cgroup namespace the process sees itself at the root.
    assert_eq!(own_cgroup("0::/\n"), Some(PathBuf::from("/sys/fs/cgroup")));
}

#[test]
fn finds_no_cgroup_on_a_cgroup_v1_host() {
    let membership = "12:pids:/user.slice\n1:name=systemd:/user.slice\n";
    assert_eq!(own_cgroup(membership), None);
}
