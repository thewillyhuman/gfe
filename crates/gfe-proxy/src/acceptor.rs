//! Per-socket accept loop with connection-limit enforcement.

use crate::connection;
use crate::ProxyShared;
use arc_swap::ArcSwap;
use gfe_metrics::RejectLabel;
use gfe_types::Listener;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

/// Accept connections on one socket until `shutdown` flips to `true`. The
/// connections accepted until then watch the same signal, to leave in an
/// orderly way.
///
/// `config` is the listener as currently configured; it is read for every
/// accepted connection, so its id and protocol can change while the socket
/// stays bound.
///
/// `global_sem` bounds total concurrent connections across all listeners; a
/// per-listener semaphore bounds this listener. When either is exhausted the
/// connection is dropped and counted as rejected.
pub async fn run_listener(
    config: Arc<ArcSwap<Listener>>,
    tcp: Arc<TcpListener>,
    shared: Arc<ProxyShared>,
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
                let tls = listener.is_tls().then(|| server_config.clone());
                let drain = shutdown.clone();
                tokio::spawn(async move {
                    let _g = global_permit;
                    let _l = listener_permit;
                    connection::serve(stream, peer, listener, shared, tls, drain).await;
                });
            }
        }
    }
}

fn reject(shared: &ProxyShared, reason: &str) {
    shared
        .metrics
        .proxy
        .connections_rejected
        .get_or_create(&RejectLabel {
            reason: reason.to_string(),
        })
        .inc();
}
