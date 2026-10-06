//! Telling systemd what the node is doing (the `sd_notify` protocol).
//!
//! systemd gives a service of `Type=notify` the path of a Unix datagram
//! socket in `$NOTIFY_SOCKET`, and the service sends it `KEY=value` lines.
//! This is what lets a node replace itself under systemd: the service is
//! whichever process systemd was last told is the main one, not the one it
//! started.
//!
//! Where the variable is not set (the node was not started by systemd, or
//! not as `Type=notify`) nothing is sent.

/// The node serves.
pub fn ready() {
    notify("READY=1\nSTATUS=Serving");
}

/// The node has begun to replace itself. systemd shows the service as
/// reloading until it is told how that ended.
pub fn upgrading() {
    notify("RELOADING=1");
}

/// The process `successor` has taken over: it is the service from now on, and
/// this process may exit without the service being taken for stopped.
pub fn upgraded(successor: u32) {
    notify(&format!(
        "MAINPID={successor}\nREADY=1\nSTATUS=Serving (upgraded in place)"
    ));
}

/// The node could not be replaced and serves as before.
pub fn upgrade_failed(reason: &str) {
    notify(&upgrade_failed_state(reason));
}

/// What [`upgrade_failed`] tells systemd.
fn upgrade_failed_state(reason: &str) -> String {
    // A status is one line.
    let reason = reason.replace('\n', " ");
    format!("READY=1\nSTATUS=Upgrade failed, still serving: {reason}")
}

#[cfg(unix)]
fn notify(state: &str) {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    if let Err(e) = send(std::path::Path::new(&socket), state) {
        tracing::warn!(error = %e, state, "could not notify systemd");
    }
}

/// Send `state` to the datagram socket at `socket`.
#[cfg(unix)]
fn send(socket: &std::path::Path, state: &str) -> std::io::Result<()> {
    use std::os::unix::net::UnixDatagram;

    UnixDatagram::unbound()
        .and_then(|datagram| datagram.send_to(state.as_bytes(), socket))
        .map(drop)
}

#[cfg(not(unix))]
fn notify(_state: &str) {}

#[cfg(test)]
#[path = "systemd_test.rs"]
mod tests;
