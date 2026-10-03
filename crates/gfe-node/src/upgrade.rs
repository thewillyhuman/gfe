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

use anyhow::Result;
use gfe_proxy::ListenerSet;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

/// The flag that tells a node it is a successor.
pub const UPGRADE_FLAG: &str = "--upgrade";

/// How long a successor may take to accept connections before the upgrade is
/// given up. Generous, because the running node serves all the while.
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
/// sockets and accepts on them, and the successor is gone.
#[cfg(unix)]
pub async fn hand_over(
    listeners: &ListenerSet,
    ops: Option<(SocketAddr, &tokio::net::TcpListener)>,
) -> Result<u32> {
    use anyhow::Context;
    use std::os::fd::AsFd;

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
    // Starting a process and waiting for it block.
    tokio::task::spawn_blocking(move || start_successor(&sockets))
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

/// Start the successor and see it take `sockets` over.
#[cfg(unix)]
fn start_successor(sockets: &gfe_handover::Sockets) -> Result<u32> {
    use anyhow::Context;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::{Command, Stdio};

    let (ours, theirs) = UnixStream::pair().context("opening a socket to the successor")?;
    // The path this node was started with, not the file it runs from: after
    // a package update that file is gone, and the path names the new one.
    let mut args = std::env::args_os();
    let program = args
        .next()
        .context("the command this node was started with is unknown")?;
    let mut successor = Command::new(&program)
        .args(args.filter(|arg| arg != UPGRADE_FLAG))
        .arg(UPGRADE_FLAG)
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .spawn()
        .with_context(|| format!("starting {}", program.to_string_lossy()))?;

    let taken_over = gfe_handover::send(&ours, sockets)
        .and_then(|()| ours.set_read_timeout(Some(SUCCESSOR_START_TIMEOUT)))
        .and_then(|()| gfe_handover::await_confirmation(&ours));
    match taken_over {
        Ok(()) => Ok(successor.id()),
        Err(e) => {
            // It says it accepts connections as soon as it does, so one that
            // has not said so holds none that killing it would break.
            let _ = successor.kill();
            let _ = successor.wait();
            Err(e).context("the successor did not take over")
        }
    }
}
