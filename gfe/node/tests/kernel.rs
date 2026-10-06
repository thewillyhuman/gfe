//! The kernel view of a node run as the service manager runs it: attached
//! where the process has what it takes (Linux, `CAP_BPF` and
//! `CAP_NET_ADMIN`), and where it has not, the node serves all the same and
//! says why.
#![cfg(unix)]

mod common;

use common::{Launch, Node, http_get, scratch};
use std::process::Stdio;

/// The capabilities the kernel view needs, as bits of a capability set.
const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_BPF: u64 = 1 << 39;

/// Whether this process, and so the node it starts, has the capabilities
/// the kernel view needs. Only Linux has them.
fn has_the_capabilities() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|bits| u64::from_str_radix(bits.trim(), 16).ok())
        .is_some_and(|effective| effective & (CAP_NET_ADMIN | CAP_BPF) == CAP_NET_ADMIN | CAP_BPF)
}

#[test]
fn attaches_the_kernel_view_where_it_has_the_capabilities() {
    let mut node = Node::start(
        &scratch("kernel", "attach"),
        &Launch {
            command: &|command| {
                command.stdout(Stdio::piped());
            },
            ..Launch::default()
        },
    );
    assert!(http_get(node.proxy, "/").starts_with("HTTP/1.1 200"));

    let metrics = node.ops_get("/metrics");
    node.signal("-TERM");
    let output = node.output();

    if has_the_capabilities() {
        assert!(
            metrics.lines().any(|line| line == "gfe_ebpf_attached 1"),
            "{output}"
        );
    } else {
        println!(
            "skipped: this process lacks CAP_BPF and CAP_NET_ADMIN (or is not on Linux); \
             checked instead that the node serves without the kernel view and says why"
        );
        assert!(
            metrics.lines().any(|line| line == "gfe_ebpf_attached 0"),
            "{metrics}"
        );
        let said_why = output
            .lines()
            .any(|line| line.contains(r#""level":"ERROR""#) && line.contains("eBPF not attached"));
        assert!(said_why, "{output}");
    }
}
