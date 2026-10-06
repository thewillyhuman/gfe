//! The kernel view of a whole front end. Every node attempts to attach it:
//! where it attaches (Linux, with `CAP_BPF` and `CAP_NET_ADMIN`), a closed
//! client connection is reported under its listener; where it cannot, the
//! node serves all the same, and says why.
//!
//! Which case a host is in is decided by the node itself
//! (`gfe_ebpf_attached`); each test checks the case it is about and skips
//! itself, saying so, on a host in the other one.

mod common;

use common::node::Node;
use common::{CapturedLogs, fixed_response_config, raw_exchange};

const REQUEST: &str = "GET / HTTP/1.1\r\nhost: a.example.org\r\nconnection: close\r\n\r\n";

#[tokio::test]
async fn a_node_without_the_kernel_view_serves_and_says_why() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::serving("no-kernel-view", &fixed_response_config());
    if node.has_metric("gfe_ebpf_attached 1") {
        println!("skipped: the kernel view attaches on this host");
        return;
    }

    let response = raw_exchange(node.addr("http"), REQUEST).await;

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let said_why = logs.lines().into_iter().any(|line| {
        line["level"] == "ERROR"
            && line["fields"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("eBPF"))
            && line["fields"]["reason"].is_string()
    });
    assert!(said_why, "{:?}", logs.lines());
}

#[tokio::test]
async fn reports_a_closed_client_connection_under_its_listener() {
    let (logs, _capturing) = CapturedLogs::start();
    let node = Node::serving("kernel-view", &fixed_response_config());
    if !node.has_metric("gfe_ebpf_attached 1") {
        println!(
            "skipped: the kernel view does not attach on this host \
             (it needs Linux, CAP_BPF and CAP_NET_ADMIN)"
        );
        return;
    }

    let response = raw_exchange(node.addr("http"), REQUEST).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    node.wait_for_metric(r#"gfe_client_tcp_closes_total{listener="http",ending="#)
        .await;
    node.wait_for_metric(r#"gfe_client_tcp_rtt_seconds_count{listener="http"} 1"#)
        .await;
    let conn = logs.wait_for_events("gfe::conn", 1).await.remove(0);
    let tcp = logs.wait_for_events("gfe::tcp", 1).await;
    let client_side: Vec<_> = tcp
        .iter()
        .filter(|event| event["side"] == "client")
        .collect();
    assert_eq!(client_side.len(), 1, "{tcp:?}");
    let event = client_side[0];
    assert_eq!(event["listener"], "http");
    assert_eq!(event["client"], conn["client"]);
    assert_eq!(event["client_port"], conn["client_port"]);
    // The kernel also says how long the connection waited to be accepted.
    assert!(conn["accept_wait_ms"].is_number(), "{conn}");
}
