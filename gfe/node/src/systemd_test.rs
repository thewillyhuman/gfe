use super::*;

#[test]
fn an_upgrade_failure_is_reported_on_one_status_line() {
    let state = upgrade_failed_state("the successor went away\ncaused by: exit 1");

    assert_eq!(
        state,
        "READY=1\nSTATUS=Upgrade failed, still serving: the successor went away caused by: exit 1"
    );
}

#[cfg(unix)]
#[test]
fn sends_the_state_to_the_notify_socket() {
    use std::os::unix::net::UnixDatagram;

    let dir = std::env::temp_dir().join(format!("gfe-node-systemd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("notify");
    let _ = std::fs::remove_file(&path);
    let systemd = UnixDatagram::bind(&path).unwrap();

    send(&path, "READY=1\nSTATUS=Serving").unwrap();

    let mut received = [0u8; 64];
    let len = systemd.recv(&mut received).unwrap();
    assert_eq!(&received[..len], b"READY=1\nSTATUS=Serving");
    std::fs::remove_dir_all(&dir).unwrap();
}
