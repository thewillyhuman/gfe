//! A cap on the upstream connections a node holds open
//! (`max_upstream_connections`), and the count of them
//! (`gfe_upstream_connections`).
//!
//! The cap protects GFE and the backends from connection storms after a
//! reload or a failover. It is enforced where connections are made: a
//! request that finds a pooled connection is unaffected, one that would need
//! a new connection beyond the cap fails at once, with an error the proxy
//! answers `503` (`upstream_connection_limit`), never retries and does not
//! count against the backend.
//!
//! Pingora offers two hooks on the peer of an attempt: one called on the
//! socket of every new connection before it connects, the other told when
//! a connection is established and when it is closed. A place under the cap
//! is taken in the first; it belongs to the attempt, which hands it to the
//! connection when it is established. The place is given back when nothing
//! holds it any more: when the attempt is over if it never connected, when
//! the connection is closed otherwise.

use crate::proxy::failure::CONNECTION_LIMIT;
use gfe_observability::Gauge;
use netkit_rate_limiting::{ConcurrencyLimit, Permit};
use pingora_core::upstreams::peer::{PeerOptions, Tracer, Tracing};
use pingora_error::Error;
use std::sync::{Arc, OnceLock};

/// The upstream connections of a node: how many are open, and how many may
/// be.
#[derive(Debug)]
pub(crate) struct ConnectionCap {
    limit: Arc<ConcurrencyLimit>,
    /// Established connections, for `gfe_upstream_connections`.
    open: Gauge,
}

impl ConnectionCap {
    /// A cap of `max` connections, counted in `open`.
    pub(crate) fn new(max: usize, open: Gauge) -> Arc<Self> {
        Arc::new(ConnectionCap {
            limit: ConcurrencyLimit::new(Some(max)),
            open,
        })
    }

    /// Connections open or being opened. An attempt that is being refused
    /// is counted until it has been, so this may briefly read above the cap.
    #[cfg(test)]
    pub(crate) fn in_use(&self) -> usize {
        self.limit.in_use()
    }

    /// Put an attempt's connections under the cap: `options` are those of
    /// the peer of one attempt.
    pub(crate) fn arm(self: &Arc<Self>, options: &mut PeerOptions) {
        let place = Arc::new(Place::default());
        let cap = Arc::clone(self);
        let taking = Arc::clone(&place);
        options.upstream_tcp_sock_tweak_hook = Some(Arc::new(move |_socket| {
            let permit = cap.limit.try_acquire().map_err(|reached| {
                Error::explain(
                    CONNECTION_LIMIT,
                    format!("upstream connection limit of {} reached", reached.max),
                )
            })?;
            // A hook runs once per connection, and an attempt opens at most
            // one: the place is empty.
            let _ = taking.permit.set(permit);
            Ok(())
        }));
        options.tracer = Some(Tracer(Box::new(Connection {
            _place: place,
            open: self.open.clone(),
        })));
    }
}

/// The place an attempt took under the cap, if it took one.
#[derive(Debug, Default)]
struct Place {
    permit: OnceLock<Permit>,
}

/// A connection's hold on its place under the cap, and its share of
/// `gfe_upstream_connections`. Pingora keeps a clone of it in each
/// connection it establishes, for as long as that connection lives.
#[derive(Debug, Clone)]
struct Connection {
    _place: Arc<Place>,
    open: Gauge,
}

impl Tracing for Connection {
    fn on_connected(&self) {
        self.open.inc();
    }

    fn on_disconnected(&self) {
        self.open.dec();
    }

    fn boxed_clone(&self) -> Box<dyn Tracing> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
#[path = "connection_cap_test.rs"]
mod tests;
