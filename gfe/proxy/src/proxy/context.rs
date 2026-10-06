//! What the proxy knows about one request while Pingora carries it from
//! callback to callback (`ProxyHttp::CTX`).
//!
//! Everything here belongs to the one request; what requests share lives in
//! [`State`]. The context holds what must be given back when the request is
//! over (its place in flight on its connection, in its pool, on its
//! backend), and it is what makes sure the request is reported exactly once:
//! in `logging`, or, should the task serving it be cancelled first, when it
//! is dropped.

use crate::listener::{ConnInfo, RequestGuard};
use crate::proxy::State;
use crate::proxy::record::{CLIENT_CLOSED_REQUEST, RequestRecord, Termination};
use crate::proxy::respond::{Answer, Refusal};
use gfe_config::Scheme;
use netkit_load_balancing::{InflightGuard, Pool};
use netkit_observability::{Gauge, UpstreamDurationLabels};
use std::sync::Arc;
use std::time::Instant;

/// The per-request context.
pub struct RequestCtx {
    state: Arc<State>,
    /// The facts the request is reported with; `None` until its head has
    /// been looked at.
    pub(crate) record: Option<RequestRecord>,
    /// The request keeps its connection marked busy until it is over.
    in_flight: Option<RequestGuard>,
    /// The connection's server name, for the host rules.
    pub(crate) sni: Option<String>,
    /// Where the request is being forwarded, once its route says so.
    pub(crate) forward: Option<Forward>,
    /// Why GFE answers the request itself, once that is decided and until
    /// the answer is written.
    pub(crate) refusal: Option<Refusal>,
    /// Whether GFE tried to write an answer of its own.
    pub(crate) answer_attempted: bool,
    /// Whether that answer reached the client in full.
    pub(crate) answered: bool,
    reported: bool,
}

impl std::fmt::Debug for RequestCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestCtx")
            .field("record", &self.record)
            .field("refusal", &self.refusal)
            .finish_non_exhaustive()
    }
}

impl RequestCtx {
    /// An empty context for a request about to be read.
    pub(crate) fn new(state: Arc<State>) -> Self {
        RequestCtx {
            state,
            record: None,
            in_flight: None,
            sni: None,
            forward: None,
            refusal: None,
            answer_attempted: false,
            answered: false,
            reported: false,
        }
    }

    /// Start accounting for the request described by `record`, which
    /// arrived on `conn`.
    pub(crate) fn begin(&mut self, record: RequestRecord, conn: Option<&Arc<ConnInfo>>) {
        self.state.metrics().proxy.requests_in_flight.inc();
        self.in_flight = conn.map(ConnInfo::begin_request);
        self.sni = conn.and_then(|conn| conn.sni().map(str::to_string));
        self.record = Some(record);
    }

    /// The request's record. Pingora calls `early_request_filter` first, so
    /// every later callback has one.
    pub(crate) fn record(&mut self) -> &mut RequestRecord {
        self.record
            .as_mut()
            .expect("early_request_filter starts the record before any other callback")
    }

    /// GFE is about to write `answer` itself.
    pub(crate) fn answering(&mut self, answer: &Answer) {
        self.answer_attempted = true;
        let grpc = answer.grpc_status();
        let record = self.record();
        record.status = Some(answer.status());
        if grpc.is_some() {
            record.grpc_status = grpc;
        }
    }

    /// Report the request with what the end of the exchange says, and give
    /// back everything it held. Only the first call reports.
    pub(crate) fn finish(
        &mut self,
        status: Option<u16>,
        bytes: (u64, u64),
        termination: Termination,
    ) {
        if self.reported {
            return;
        }
        self.reported = true;
        // The backend and the pool are done with the request.
        self.forward = None;
        let Some(record) = self.record.as_mut() else {
            return;
        };
        if status.is_some() {
            record.status = status;
        }
        (record.request_bytes, record.response_bytes) = bytes;
        record.termination = termination;
        record.report(&self.state.metrics().proxy);
        self.in_flight = None;
    }
}

impl Drop for RequestCtx {
    /// A request whose task was cancelled before Pingora could finish it
    /// (its connection cut at the end of a drain) is still reported, as
    /// abandoned.
    fn drop(&mut self) {
        if !self.reported && self.record.is_some() {
            let status = self.record.as_ref().and_then(|r| r.status);
            let bytes = self
                .record
                .as_ref()
                .map_or((0, 0), |r| (r.request_bytes, r.response_bytes));
            self.finish(
                status.or(Some(CLIENT_CLOSED_REQUEST)),
                bytes,
                Termination::ClientAbort,
            );
        }
    }
}

/// A request on its way to a pool.
pub(crate) struct Forward {
    pub(crate) pool: Arc<Pool<Scheme>>,
    /// The request's place among the pool's `max_in_flight`, shared by
    /// every attempt so that a retry does not count, or get refused, as
    /// another request.
    _admitted: InflightGuard,
    /// Whether the request may be attempted again ([`crate::proxy::retry`]).
    pub(crate) replayable: bool,
    /// Whether the client asked for trailers (`TE: trailers`).
    pub(crate) asks_for_trailers: bool,
    /// The attempts made so far.
    pub(crate) attempts: u32,
    /// When the first attempt started.
    pub(crate) first_attempt: Option<Instant>,
    /// The attempt in progress, if one is.
    pub(crate) attempt: Option<Attempt>,
    /// Whether the backend has responded (response headers arrived).
    pub(crate) responded: bool,
}

impl Forward {
    /// A request admitted to `pool`.
    pub(crate) fn new(
        pool: Arc<Pool<Scheme>>,
        admitted: InflightGuard,
        replayable: bool,
        asks_for_trailers: bool,
    ) -> Self {
        Forward {
            pool,
            _admitted: admitted,
            replayable,
            asks_for_trailers,
            attempts: 0,
            first_attempt: None,
            attempt: None,
            responded: false,
        }
    }
}

/// One attempt against a backend. Marks the backend as busy with the
/// request (for least-request selection and `gfe_upstream_requests_in_flight`)
/// until dropped: when the response has been relayed to its end, the attempt
/// fails, or another attempt replaces it.
pub(crate) struct Attempt {
    /// `pool` and `backend`, the labels of the attempt's metrics.
    pub(crate) labels: UpstreamDurationLabels,
    pub(crate) started: Instant,
    in_flight: Gauge,
    _least_request: InflightGuard,
}

impl Attempt {
    /// An attempt starting now against `backend` of `pool`, counted in
    /// `in_flight`, and in `least_request` for selection.
    pub(crate) fn begin(
        labels: UpstreamDurationLabels,
        in_flight: Gauge,
        least_request: InflightGuard,
    ) -> Self {
        in_flight.inc();
        Attempt {
            labels,
            started: Instant::now(),
            in_flight,
            _least_request: least_request,
        }
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.in_flight.dec();
    }
}

#[cfg(test)]
#[path = "context_test.rs"]
mod tests;
