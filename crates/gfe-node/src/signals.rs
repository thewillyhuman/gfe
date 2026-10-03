//! The signals a node acts on.

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
            })
        }
        #[cfg(not(unix))]
        Ok(Signals {})
    }

    /// Wait for the next request.
    pub async fn next(&mut self) -> Request {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.terminate.recv() => Request::Stop,
                _ = self.interrupt.recv() => Request::Stop,
                _ = self.upgrade.recv() => Request::Upgrade,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            Request::Stop
        }
    }
}
