//! Where `gfe-node` writes its log, and what goes into it: the binary is run
//! as the service manager would run it.
#![cfg(unix)]

mod common;

use common::{Launch, Node, eventually, http_get, scratch};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Whatever the node writes to standard output goes to the test.
fn piped_output(command: &mut Command) {
    command.stdout(Stdio::piped());
}

/// Start a node in a scratch directory of `test` whose bootstrap config
/// ends with `extra`, its standard output piped to the test.
fn start(test: &str, extra: &str) -> Node {
    Node::start(
        &scratch("logging", test),
        &Launch {
            extra,
            command: &piped_output,
            ..Launch::default()
        },
    )
}

/// Stop `node` as a service manager does; everything it wrote to standard
/// output.
fn stop(mut node: Node) -> String {
    node.signal("-TERM");
    node.output()
}

/// The `[log]` section that sends the log to `file`.
fn log_to(file: &Path) -> String {
    format!("[log]\nfile = \"{}\"\n", file.display())
}

#[test]
fn reports_how_many_log_lines_were_lost_per_destination() {
    let node = start("lost", "");
    http_get(node.proxy, "/");

    let metrics = node.ops_get("/metrics");

    assert!(
        metrics.contains(r#"gfe_log_lost_lines{destination="stdout"} 0"#),
        "{metrics}"
    );
}

#[test]
fn writes_out_its_last_lines_before_it_exits() {
    let node = start("last-lines", "");

    let output = stop(node);

    let last = output.lines().last().unwrap_or_default();
    assert!(last.contains("gfe-node stopped"), "{output}");
}

#[test]
fn writes_every_line_to_its_log_file() {
    let dir = scratch("logging", "file");
    let file = dir.join("gfe.log");
    let node = Node::start(
        &dir,
        &Launch {
            extra: &log_to(&file),
            ..Launch::default()
        },
    );

    http_get(node.proxy, "/");
    let has_the_request = eventually(|| {
        std::fs::read_to_string(&file)
            .unwrap_or_default()
            .contains(r#""target":"gfe::access""#)
    });

    assert!(has_the_request, "the request is not in the log file");
    let log = std::fs::read_to_string(&file).unwrap();
    assert!(log.contains("gfe-node ready"), "{log}");
}

#[test]
fn keeps_requests_off_standard_output_when_it_has_a_log_file() {
    let dir = scratch("logging", "stdout");
    let node = Node::start(
        &dir,
        &Launch {
            extra: &log_to(&dir.join("gfe.log")),
            command: &piped_output,
            ..Launch::default()
        },
    );
    http_get(node.proxy, "/");

    let output = stop(node);

    assert!(output.contains("gfe-node stopped"), "{output}");
    assert!(!output.contains("gfe::access"), "{output}");
    assert!(!output.contains("gfe::conn"), "{output}");
}

#[test]
fn does_not_start_without_the_log_file_it_was_told_to_write() {
    let dir = scratch("logging", "unwritable");
    let nowhere = dir.join("no-such-directory").join("gfe.log");
    let mut node = Node::spawn(
        &dir,
        &Launch {
            extra: &log_to(&nowhere),
            ..Launch::default()
        },
    );

    let exit = node.exit();

    assert!(
        exit.is_some_and(|status| !status.success()),
        "the node should have refused to start: {exit:?}"
    );
}

/// The lines of `output` that the libraries under the node logged, rather
/// than the node itself: every line whose target is not one of GFE's own
/// (`gfe::*` events, `gfe_*` modules). A library logging through the `log`
/// crate (rustls does) keeps the module a record comes from as its target.
fn from_libraries(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter(|line| {
            let event: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
            !event["target"]
                .as_str()
                .is_some_and(|target| target.starts_with("gfe"))
        })
        .collect()
}

/// Send half a request head to `node` and leave.
fn leave_halfway_through_a_request(node: &Node) {
    let mut client = TcpStream::connect(node.proxy).unwrap();
    client.write_all(b"GET / HTTP/1.1\r\nhost: t\r\n").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    let _ = client.read_to_end(&mut rest);
}

/// A client that leaves halfway through a request head is reported by the
/// node's own event of the connection, and by nothing else: a line per
/// such client would let a scanner fill the journal.
#[test]
fn logs_nothing_from_its_libraries_about_a_client_that_leaves_mid_request() {
    let node = start("libraries-quiet", "");
    leave_halfway_through_a_request(&node);

    let output = stop(node);

    assert!(from_libraries(&output).is_empty(), "{output}");
    assert!(
        output.contains(r#""target":"gfe::conn""#),
        "the connection is still reported by the node itself: {output}"
    );
}

/// One request after another over a connection that is kept, then left
/// idle until the node closes it.
fn requests_over_a_kept_connection(node: &Node) {
    let mut client = TcpStream::connect(node.proxy).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    for _ in 0..3 {
        client
            .write_all(b"GET / HTTP/1.1\r\nhost: t\r\n\r\n")
            .unwrap();
        let mut response = Vec::new();
        let mut chunk = [0u8; 1024];
        while !response.ends_with(b"\r\n\r\nok") {
            let read = client.read(&mut chunk).unwrap();
            assert_ne!(read, 0, "closed before the response was complete");
            response.extend_from_slice(&chunk[..read]);
        }
    }
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).unwrap();
}

/// What a healthy node does all day, requests and connections that open,
/// idle and close, is in the access and connection logs and nowhere else:
/// a journal would drown in one line per request.
#[test]
fn logs_nothing_from_its_libraries_about_healthy_traffic() {
    let node = start("quiet", "[timeouts]\nclient_idle = \"1s\"\n");
    for _ in 0..5 {
        assert!(http_get(node.proxy, "/").starts_with("HTTP/1.1 200"));
    }
    requests_over_a_kept_connection(&node);
    // A client that closes its kept connection first.
    let mut client = TcpStream::connect(node.proxy).unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nhost: t\r\n\r\n")
        .unwrap();
    let mut answer = [0u8; 12];
    client.read_exact(&mut answer).unwrap();
    drop(client);
    // And one that connects and sends nothing.
    let silent = TcpStream::connect(node.proxy).unwrap();
    drop(silent);
    node.ops_get("/metrics");

    let output = stop(node);

    assert!(output.contains("gfe::access"), "{output}");
    assert!(from_libraries(&output).is_empty(), "{output}");
}
