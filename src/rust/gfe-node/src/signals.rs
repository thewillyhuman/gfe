//! The signals a node acts on, and the ones it refuses to die of.

/// What a signal asks of the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Drain and exit (`SIGTERM`, `SIGINT`).
    Stop,
    /// Replace this process with the binary now on disk, without closing the
    /// listening sockets (`SIGUSR2`).
    Upgrade,
}

/// The requests made of the node by signal, in the order they arrive.
pub struct Signals {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    upgrade: tokio::signal::unix::Signal,
    /// `SIGHUP`, sent out of habit to make a daemon reload and by log
    /// rotation. Ignored: by default it kills the process without a drain,
    /// and systemd takes that for a clean exit and does not restart it.
    #[cfg(unix)]
    hangup: tokio::signal::unix::Signal,
    /// `SIGUSR1`, which would kill the node just as well. Ignored.
    #[cfg(unix)]
    user1: tokio::signal::unix::Signal,
}

impl Signals {
    /// Start listening for the signals. From here on they no longer have
    /// their default effect, which for all of them is to kill the process.
    pub fn install() -> std::io::Result<Signals> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(Signals {
                terminate: signal(SignalKind::terminate())?,
                interrupt: signal(SignalKind::interrupt())?,
                upgrade: signal(SignalKind::user_defined2())?,
                hangup: signal(SignalKind::hangup())?,
                user1: signal(SignalKind::user_defined1())?,
            })
        }
        #[cfg(not(unix))]
        Ok(Signals {})
    }

    /// Wait for the next request. A signal that asks for nothing is logged
    /// and waited past.
    pub async fn next(&mut self) -> Request {
        #[cfg(unix)]
        loop {
            let ignored = tokio::select! {
                _ = self.terminate.recv() => return Request::Stop,
                _ = self.interrupt.recv() => return Request::Stop,
                _ = self.upgrade.recv() => return Request::Upgrade,
                _ = self.hangup.recv() => "SIGHUP",
                _ = self.user1.recv() => "SIGUSR1",
            };
            tracing::warn!(
                signal = ignored,
                "signal ignored: the dynamic config is reloaded when its file changes; \
                 to upgrade in place use SIGUSR2 (systemctl reload)"
            );
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            Request::Stop
        }
    }
}
