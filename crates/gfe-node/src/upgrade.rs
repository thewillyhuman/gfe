//! Replacing a running node in place, without closing its listening sockets.
//!
//! A node told to upgrade starts the binary it was started from, as that
//! binary is on disk now, with `--upgrade` and, as its standard input, a Unix
//! socket to itself ([`hand_over`]). Over that socket the successor is given
//! the listening sockets ([`gfe_handover`], [`take_over`]). Once it accepts
//! connections on them it says so, and only then does the node that started
//! it stop accepting and drain.
//!
//! Until that moment nothing has changed for the running node: if the
//! successor does not start, the node goes on serving.
//!
//! The successor is not the node's child. What the node starts only starts
//! the successor in turn and exits ([`detach`]), which leaves the successor
//! to be adopted by the service manager. A service manager follows a service
//! by its main process and can wait only for a process that is its own
//! child: a main process that was the child of another when it was
//! announced is one systemd does not wait for, and kills outright the next
//! time the service is stopped.

use anyhow::Result;
use gfe_proxy::ListenerSet;
use std::net::{SocketAddr, TcpListener};
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

/// The flag that tells a node it is a successor.
pub const UPGRADE_FLAG: &str = "--upgrade";

/// The flag that tells a successor it has been detached already.
pub const DETACHED_FLAG: &str = "--detached";

/// How long a successor may take, from when it is started, to accept
/// connections before the upgrade is given up. Generous, because the running
/// node serves all the while.
const SUCCESSOR_START_TIMEOUT: Duration = Duration::from_secs(60);

/// The listening sockets a node starts with. None, unless it takes over from
/// a running node.
#[derive(Default)]
pub struct Inherited {
    /// The proxy's sockets, each with the address its listener is configured
    /// on.
    pub listeners: Vec<(SocketAddr, TcpListener)>,
    /// The socket of the ops server, with the address it is configured on.
    pub ops: Option<(SocketAddr, TcpListener)>,
}

/// The running node this process takes over from, which goes on serving
/// until it is told that it may stop.
pub struct Predecessor {
    #[cfg(unix)]
    channel: std::os::unix::net::UnixStream,
}

impl Predecessor {
    /// Tell the predecessor that this node accepts connections, so that it
    /// stops doing so and winds down.
    pub fn release(self) -> std::io::Result<()> {
        #[cfg(unix)]
        gfe_handover::confirm(&self.channel)?;
        Ok(())
    }
}

/// Take the listening sockets from the node that started this process, which
/// passes them on standard input.
#[cfg(unix)]
pub fn take_over() -> Result<(Predecessor, Inherited)> {
    use anyhow::Context;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    let stdin = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .context("duplicating standard input")?;
    let channel = UnixStream::from(stdin);
    let sockets = gfe_handover::receive(&channel)
        .context("receiving the listening sockets of the running node")?;
    let inherited = Inherited {
        listeners: sockets.listeners,
        ops: sockets.ops,
    };
    Ok((Predecessor { channel }, inherited))
}

#[cfg(not(unix))]
pub fn take_over() -> Result<(Predecessor, Inherited)> {
    anyhow::bail!("--upgrade is not supported on this platform")
}

/// Replace this process: start a successor, give it the listening sockets of
/// `listeners` and of the ops server (`ops`, with the address it is
/// configured on), and wait until it accepts connections. Returns the
/// successor's process id.
///
/// On success the caller must stop accepting and drain: the successor serves
/// from now on. On failure nothing has changed: this node still holds its
/// sockets and accepts on them, and the successor is gone or, if it was
/// started but never said which process it is, will find nobody to take
/// over from and exit.
///
/// Dropping the returned future abandons the upgrade, with the same outcome
/// as a failure: the wait for the successor ends at once, and a successor
/// that has said which process it is is stopped.
#[cfg(unix)]
pub async fn hand_over(
    listeners: &ListenerSet,
    ops: Option<(SocketAddr, &tokio::net::TcpListener)>,
) -> Result<u32> {
    use anyhow::Context;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    let ops = ops
        .map(|(addr, socket)| {
            let duplicate = socket.as_fd().try_clone_to_owned()?;
            Ok::<_, std::io::Error>((addr, TcpListener::from(duplicate)))
        })
        .transpose()
        .context("duplicating the ops socket")?;
    let sockets = gfe_handover::Sockets {
        listeners: listeners
            .sockets()
            .context("duplicating the listening sockets")?,
        ops,
    };
    let (ours, theirs) = UnixStream::pair().context("opening a socket to the successor")?;
    let abandon = Abandon {
        channel: ours
            .try_clone()
            .context("duplicating the socket to the successor")?,
        abandoned: Arc::new(AtomicBool::new(false)),
    };
    let abandoned = abandon.abandoned.clone();
    // Starting a process and waiting for it block.
    tokio::task::spawn_blocking(move || start_successor(&sockets, ours, theirs, &abandoned))
        .await
        .context("waiting for the successor")?
}

#[cfg(not(unix))]
pub async fn hand_over(
    _listeners: &ListenerSet,
    _ops: Option<(SocketAddr, &tokio::net::TcpListener)>,
) -> Result<u32> {
    anyhow::bail!("upgrading in place is not supported on this platform")
}

/// Ends the wait for the successor when [`hand_over`] is done with it, or
/// is dropped before: the thread that waits must not outlive the upgrade,
/// or it would keep the node from exiting.
#[cfg(unix)]
struct Abandon {
    /// The node's end of the exchange with the successor.
    channel: std::os::unix::net::UnixStream,
    /// Set before the wait is ended, so that the waiting thread can tell an
    /// abandoned upgrade from a successor that went away.
    abandoned: Arc<AtomicBool>,
}

#[cfg(unix)]
impl Drop for Abandon {
    fn drop(&mut self) {
        self.abandoned.store(true, Ordering::SeqCst);
        let _ = self.channel.shutdown(std::net::Shutdown::Both);
    }
}

/// Start the successor, with `theirs` as its end of `ours`, and see it take
/// `sockets` over, unless `abandoned` is set first.
#[cfg(unix)]
fn start_successor(
    sockets: &gfe_handover::Sockets,
    ours: std::os::unix::net::UnixStream,
    theirs: std::os::unix::net::UnixStream,
    abandoned: &AtomicBool,
) -> Result<u32> {
    use anyhow::Context;
    use std::os::fd::OwnedFd;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    // The path this node was started with, not the file it runs from: after
    // a package update that file is gone, and the path names the new one.
    let mut args = std::env::args_os();
    let program = args
        .next()
        .context("the command this node was started with is unknown")?;
    // This node may itself be a successor: its own flags are not passed on.
    let launched = Command::new(&program)
        .args(args.filter(|arg| arg != UPGRADE_FLAG && arg != DETACHED_FLAG))
        .arg(UPGRADE_FLAG)
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .status()
        .with_context(|| format!("starting {}", program.to_string_lossy()))?;
    anyhow::ensure!(
        launched.success(),
        "the successor could not be started ({launched})"
    );

    let deadline = Instant::now() + SUCCESSOR_START_TIMEOUT;
    gfe_handover::send(&ours, sockets).map_err(not_taken_over)?;
    let successor = gfe_handover::await_receipt(&ours, deadline).map_err(not_taken_over)?;
    gfe_handover::await_confirmation(&ours, deadline).map_err(|e| {
        if timed_out(&e) || abandoned.load(Ordering::SeqCst) {
            // It says it accepts connections as soon as it does, so one that
            // has not said so holds none that killing it would break.
            kill(successor);
        }
        not_taken_over(e)
    })?;
    Ok(successor)
}

#[cfg(unix)]
fn timed_out(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    matches!(e.kind(), TimedOut | WouldBlock)
}

/// Why the successor did not take over, in words an operator can act on.
#[cfg(unix)]
fn not_taken_over(e: std::io::Error) -> anyhow::Error {
    use std::io::ErrorKind::{BrokenPipe, ConnectionReset, UnexpectedEof};
    if timed_out(&e) {
        anyhow::anyhow!(
            "the successor did not accept connections within {} s",
            SUCCESSOR_START_TIMEOUT.as_secs()
        )
    } else if matches!(e.kind(), UnexpectedEof | ConnectionReset | BrokenPipe) {
        anyhow::anyhow!("the successor went away before it took over; its own log says why")
    } else {
        anyhow::Error::new(e).context("the successor did not take over")
    }
}

/// Kill the process `pid`, which is not a child of this one.
#[cfg(unix)]
fn kill(pid: u32) {
    use rustix::process::{kill_process, Pid, Signal};
    let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return;
    };
    if let Err(e) = kill_process(pid, Signal::KILL) {
        tracing::warn!(error = %e, "could not stop the successor that did not take over");
    }
}

/// Start this command again as the successor proper, and return at once.
///
/// This is what detaches the successor from the node it replaces: started
/// by a process that then exits, it is nobody's child and the service
/// manager adopts it. Its standard input, the socket to that node, is this
/// process's own.
#[cfg(unix)]
pub fn detach() -> Result<()> {
    use anyhow::Context;
    use std::process::Command;

    let mut args = std::env::args_os();
    let program = args
        .next()
        .context("the command this process was started with is unknown")?;
    Command::new(&program)
        .args(args)
        .arg(DETACHED_FLAG)
        .spawn()
        .with_context(|| format!("starting {}", program.to_string_lossy()))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn detach() -> Result<()> {
    anyhow::bail!("--upgrade is not supported on this platform")
}
