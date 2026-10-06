//! What the unit tests share: a [`Serve`] that records what it is given and
//! holds each connection open, and a client that waits for the server to
//! close its connection.

use crate::accept::{Accepted, Limit, Serve};
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// How long a test waits for something that should happen at once.
pub(crate) const PATIENCE: Duration = Duration::from_secs(5);

/// A connection as [`Recorder`] was given it.
#[derive(Debug)]
pub(crate) struct Seen<T> {
    /// What was attached to the listener when the connection was accepted.
    pub(crate) listener: T,
    pub(crate) peer: SocketAddr,
    pub(crate) local: SocketAddr,
    /// The handle the connection reads its listener through.
    pub(crate) handle: Arc<ArcSwap<T>>,
}

/// A [`Serve`] that reports every connection it is given and every one
/// refused, and holds each connection open until the client closes it or,
/// if it was made to [leave](Recorder::leaving), until the process drains.
#[derive(Debug)]
pub(crate) struct Recorder<T> {
    accepted: mpsc::UnboundedSender<Seen<T>>,
    refused: mpsc::UnboundedSender<(T, Limit)>,
    leaves_when_draining: bool,
}

/// The receiving end of what a [`Recorder`] reports.
#[derive(Debug)]
pub(crate) struct Record<T> {
    pub(crate) accepted: mpsc::UnboundedReceiver<Seen<T>>,
    pub(crate) refused: mpsc::UnboundedReceiver<(T, Limit)>,
}

impl<T> Record<T> {
    /// The next connection served, waited for.
    pub(crate) async fn next_accepted(&mut self) -> Seen<T> {
        tokio::time::timeout(PATIENCE, self.accepted.recv())
            .await
            .expect("a connection is served in time")
            .expect("the recorder is alive")
    }

    /// The next connection refused, waited for.
    pub(crate) async fn next_refused(&mut self) -> (T, Limit) {
        tokio::time::timeout(PATIENCE, self.refused.recv())
            .await
            .expect("a connection is refused in time")
            .expect("the recorder is alive")
    }
}

impl<T> Recorder<T> {
    /// A recorder that holds connections until their clients close them,
    /// draining or not.
    pub(crate) fn holding() -> (Arc<Self>, Record<T>) {
        Self::new(false)
    }

    /// A recorder that ends its connections as soon as the process drains.
    pub(crate) fn leaving() -> (Arc<Self>, Record<T>) {
        Self::new(true)
    }

    fn new(leaves_when_draining: bool) -> (Arc<Self>, Record<T>) {
        let (accepted_tx, accepted) = mpsc::unbounded_channel();
        let (refused_tx, refused) = mpsc::unbounded_channel();
        let recorder = Recorder {
            accepted: accepted_tx,
            refused: refused_tx,
            leaves_when_draining,
        };
        (Arc::new(recorder), Record { accepted, refused })
    }
}

impl<T: Clone + Send + Sync + 'static> Serve<T> for Recorder<T> {
    async fn serve(&self, accepted: Accepted<T>) {
        let Accepted {
            mut stream,
            peer,
            local,
            listener,
            mut drain,
        } = accepted;
        let _ = self.accepted.send(Seen {
            listener: T::clone(&listener.load()),
            peer,
            local,
            handle: listener,
        });
        let until_closed = async {
            let mut buf = [0u8; 64];
            while matches!(stream.read(&mut buf).await, Ok(read) if read > 0) {}
        };
        if self.leaves_when_draining {
            tokio::select! {
                () = until_closed => {}
                _ = drain.wait_for(|draining| *draining) => {}
            }
        } else {
            until_closed.await;
        }
    }

    fn refused(&self, listener: &T, limit: Limit) {
        let _ = self.refused.send((listener.clone(), limit));
    }
}

/// Whether `client` is closed by the server within [`PATIENCE`].
pub(crate) async fn closed_soon(client: &mut TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match tokio::time::timeout(PATIENCE, client.read(&mut buf)).await {
        Ok(Ok(read)) => read == 0,
        Ok(Err(_)) => true,
        Err(_) => false,
    }
}
