//! Per-socket accept loop with connection-limit enforcement.

use crate::connection;
use crate::server::{RequestHandler, ServerShared};
use arc_swap::ArcSwap;
use gfe_core::config::Listener;
use gfe_observability::RejectLabel;
use rustls::ServerConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

/// How long the accept loop waits after a failed `accept` before trying
/// again. The errors that persist (out of file descriptors or memory) would
/// otherwise spin the loop on a core and flood the log.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

/// Accept connections on one socket until `shutdown` flips to `true`. The
/// connections accepted until then watch the same signal, to leave in an
/// orderly way.
///
/// `config` is the listener as currently configured; it is read for every
/// accepted connection, and its id for every request, so its id and
/// protocol can change while the socket stays bound.
///
/// `global_sem` bounds total concurrent connections across all listeners; a
/// per-listener semaphore bounds this listener. When either is exhausted the
/// connection is dropped and counted as rejected.
pub async fn run_listener<H: RequestHandler>(
    config: Arc<ArcSwap<Listener>>,
    tcp: Arc<TcpListener>,
    shared: Arc<ServerShared>,
    handler: Arc<H>,
    server_config: Arc<ServerConfig>,
    global_sem: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) {
    let listener_sem = Arc::new(Semaphore::new(shared.limits.max_connections_listener));

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!(id = %config.load().id, "listener draining, stop accepting");
                    break;
                }
            }
            accepted = tcp.accept() => {
                let listener = config.load_full();
                let (stream, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, id = %listener.id, "accept error");
                        if pause_unless_shut_down(&mut shutdown, ACCEPT_ERROR_PAUSE).await {
                            tracing::info!(id = %listener.id, "listener draining, stop accepting");
                            break;
                        }
                        continue;
                    }
                };

                let global_permit = match global_sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        reject(&shared, "limit");
                        continue;
                    }
                };
                let listener_permit = match listener_sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        reject(&shared, "limit");
                        continue;
                    }
                };

                let shared = shared.clone();
                let handler = handler.clone();
                let tls = listener.is_tls().then(|| server_config.clone());
                let drain = shutdown.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    let _g = global_permit;
                    let _l = listener_permit;
                    connection::serve(stream, peer, config, shared, handler, tls, drain).await;
                });
            }
        }
    }
}

/// Wait for `pause`, unless `shutdown` turns `true` (or its sender goes away)
/// first. Returns `true` if the pause was cut short by the shutdown.
async fn pause_unless_shut_down(shutdown: &mut watch::Receiver<bool>, pause: Duration) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(pause) => false,
        _ = shutdown.wait_for(|shut_down| *shut_down) => true,
    }
}

fn reject(shared: &ServerShared, reason: &str) {
    shared
        .metrics
        .proxy
        .connections_rejected
        .get_or_create(&RejectLabel {
            reason: reason.to_string(),
        })
        .inc();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pause_lasts_its_whole_length_without_shutdown() {
        let (_tx, mut shutdown) = watch::channel(false);
        let started = std::time::Instant::now();

        let shut_down = pause_unless_shut_down(&mut shutdown, Duration::from_millis(50)).await;

        assert!(!shut_down);
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn pause_ends_as_soon_as_the_node_shuts_down() {
        let (tx, mut shutdown) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tx.send(true).unwrap();
        });

        let pause = pause_unless_shut_down(&mut shutdown, Duration::from_secs(60));
        let shut_down = tokio::time::timeout(Duration::from_secs(5), pause).await;

        assert_eq!(shut_down, Ok(true));
    }
}
