//! Per-listener accept loop with connection-limit enforcement.

use crate::connection;
use crate::ProxyShared;
use gfe_metrics::RejectLabel;
use gfe_types::Listener;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

/// Accept connections for one listener until `shutdown` flips to `true`.
///
/// `global_sem` bounds total concurrent connections across all listeners; a
/// per-listener semaphore bounds this listener. When either is exhausted the
/// connection is dropped and counted as rejected.
pub async fn run_listener(
    listener: Listener,
    tcp: TcpListener,
    shared: Arc<ProxyShared>,
    server_config: Option<Arc<ServerConfig>>,
    global_sem: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) {
    let listener_sem = Arc::new(Semaphore::new(shared.limits.max_connections_listener));

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!(id = %listener.id, "listener draining, stop accepting");
                    break;
                }
            }
            accepted = tcp.accept() => {
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
                let cfg = server_config.clone();
                let listener = listener.clone();
                tokio::spawn(async move {
                    let _g = global_permit;
                    let _l = listener_permit;
                    connection::serve(stream, peer, listener, shared, cfg).await;
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
