//! One forward: a request sent to a backend of its pool and the backend's
//! response handed back, from the pool's quota to the response head.
//!
//! In order: the request is refused if GFE cannot forward it (a target
//! that is not a path, a protocol upgrade); it takes a place among the
//! pool's `max_in_flight`; a healthy backend is selected (`ring_hash` keyed
//! by the client's address), the request is sent through the pooled client,
//! and the wait for the response head is bounded by the request's progress
//! (`progress`), except for a gRPC call, which its own client bounds with
//! its deadline. A bodyless idempotent request whose attempt fails before
//! any response is tried once more, against a backend selected afresh
//! (`retry`). Every attempt is counted against its backend.
//!
//! What the client is told when the forward fails is the caller's: a
//! failed forward says why ([`Unanswered`]). The response body, once the
//! head has arrived, is relayed for as long as it takes.

use crate::edge::ConnInfo;
use crate::handler::State;
use crate::handler::failure::{FailureKind, classify};
use crate::handler::progress::{CountedBody, SendProgress};
use crate::handler::record::RequestRecord;
use crate::handler::request::{self, Forwarding, X_REQUEST_ID};
use crate::handler::respond::Refusal;
use crate::handler::retry::{self, Attempted};
use crate::metrics::{PoolLabel, UpstreamDurationLabels, UpstreamErrorLabels, UpstreamLabels};
use gfe_config::Scheme;
use netkit_http::body::{self, Body, BoxBody, Incoming};
use netkit_http::client::Scheme as ClientScheme;
use netkit_http::header::STRICT_TRANSPORT_SECURITY;
use netkit_http::uri::PathAndQuery;
use netkit_http::{HeaderValue, Request, Response, Version};
use netkit_load_balancing::{InflightGuard, Limit, Pool};
use netkit_observability::Gauge;
use std::sync::Arc;
use std::time::Instant;

/// Why a forward ended without a response from a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unanswered {
    /// GFE answers the client itself, saying why.
    Refused(Refusal),
    /// The client went away, or broke its request body, while the request
    /// was being sent: there is nobody to answer, and the backend is not
    /// to blame.
    ClientGone,
}

impl From<Refusal> for Unanswered {
    fn from(refusal: Refusal) -> Self {
        Unanswered::Refused(refusal)
    }
}

/// Forward `request`, which arrived on `conn`, to a backend of `pool`, and
/// return the backend's response, ready for the client: its hop-by-hop
/// headers removed, HSTS added over TLS, and the request id added when the
/// backend gave none.
///
/// What happens is noted on `record`: the pool, each attempt and its
/// backend, the time to the response head, and the bytes of the request
/// body. The backend stays marked busy with the request, through `record`,
/// until the response ends or the forward fails.
pub(crate) async fn forward(
    state: &State,
    conn: &ConnInfo,
    pool: &Arc<Pool<Scheme>>,
    request: Request<Incoming>,
    record: &mut RequestRecord,
) -> Result<Response<BoxBody>, Unanswered> {
    if !request::names_a_path(request.uri()) {
        return Err(Refusal::UnsupportedTarget.into());
    }
    if request::asks_for_upgrade(request.headers()) {
        // GFE cannot relay an upgraded connection. Forwarded without its
        // hop-by-hop `Connection: upgrade`, the handshake would reach the
        // backend as a plain request; refusing it says what happened.
        return Err(Refusal::UpgradeNotSupported.into());
    }
    let metrics = &state.metrics().proxy;
    record.forwarding_to(pool.id.clone());
    // The pool's place is shared by every attempt, so that a retry does not
    // count, or get refused, as another request.
    let admitted = match pool.admit(Instant::now()) {
        Ok(admitted) => Arc::new(admitted),
        Err(Limit::MaxInFlight | Limit::MaxRequestsPerSecond) => {
            let label = PoolLabel {
                pool: pool.id.clone(),
            };
            metrics.upstream_pool_full.get_or_create(&label).inc();
            return Err(Refusal::PoolFull.into());
        }
    };

    let (mut head, content) = request.into_parts();
    let is_tls = conn.is_tls();
    request::to_backend(
        &mut head,
        &Forwarding {
            client: conn.client().ip(),
            proto: if is_tls { "https" } else { "http" },
            host: record.host(),
            request_id: record.request_id(),
        },
    );
    // gRPC needs HTTP/2 to the backend; anything else is left to the
    // client, which speaks what the pool's scheme says.
    let version = if record.is_grpc() {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    let path_and_query = head
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    // Whether there is a body is told by the body itself, not by headers:
    // an HTTP/1.1 body may be chunked, and an HTTP/2 body need not announce
    // a `content-length`.
    let replayable = retry::is_replayable(&head.method, !content.is_end_stream());
    let forwarding_started = Instant::now();
    let progress = SendProgress::begin(forwarding_started, !replayable);
    // A body that cannot be replayed is sent once, as it streams in.
    let mut streamed = (!replayable).then(|| {
        body::boxed(CountedBody::new(
            content,
            record.request_bytes(),
            Arc::clone(&progress),
        ))
    });
    let hash_key = Some(netkit_load_balancing::policy::hash64(conn.client().ip()));
    let scheme = client_scheme(*pool.payload());

    let mut attempts = 0;
    loop {
        let Some(selection) = pool.select(hash_key) else {
            metrics.no_healthy_upstream.inc();
            return Err(Refusal::NoHealthyUpstream.into());
        };
        attempts += 1;
        let authority = selection.backend.authority();
        let labels = UpstreamDurationLabels {
            pool: pool.id.clone(),
            backend: authority.clone(),
        };
        if attempts > 1 {
            let label = PoolLabel {
                pool: pool.id.clone(),
            };
            metrics.upstream_retries.get_or_create(&label).inc();
        }
        let in_flight = metrics
            .upstream_requests_in_flight
            .get_or_create(&labels)
            .clone();
        record.attempting(
            authority.clone(),
            BackendBusy::new(selection.guard, Arc::clone(&admitted), in_flight),
        );

        let mut attempt = Request::new(streamed.take().unwrap_or_else(body::empty));
        *attempt.method_mut() = head.method.clone();
        *attempt.version_mut() = version;
        *attempt.uri_mut() = path_and_query.clone().into();
        // Cloned only while another attempt may follow; the last one takes
        // the headers, so a request that is not retried copies nothing.
        let may_follow = replayable && attempts < retry::MAX_ATTEMPTS;
        *attempt.headers_mut() = if may_follow {
            head.headers.clone()
        } else {
            std::mem::take(&mut head.headers)
        };

        let started = Instant::now();
        progress.attempt_started(started);
        let sending = state.client().send(scheme, &authority, attempt);
        let outcome = if record.is_grpc() {
            // A gRPC stream may have nothing to say, not even headers, for
            // as long as it likes: how long a call may take is the deadline
            // its client sets and enforces, not a proxy timeout. A backend
            // that died is noticed by the HTTP/2 keep-alive instead.
            Some(sending.await)
        } else {
            tokio::select! {
                result = sending => Some(result),
                () = progress.overdue(state.timeouts()) => None,
            }
        };
        metrics
            .upstream_request_duration_seconds
            .get_or_create(&labels)
            .observe(started.elapsed().as_secs_f64());

        let count = |status: u16| {
            metrics
                .upstream_requests
                .get_or_create(&UpstreamLabels {
                    pool: labels.pool.clone(),
                    backend: labels.backend.clone(),
                    status: status.to_string(),
                })
                .inc();
        };
        let count_error = |kind: FailureKind| {
            metrics
                .upstream_errors
                .get_or_create(&UpstreamErrorLabels {
                    pool: labels.pool.clone(),
                    backend: labels.backend.clone(),
                    kind: kind.as_str().to_string(),
                })
                .inc();
        };
        match outcome {
            Some(Ok(response)) => {
                record.upstream_responded(forwarding_started.elapsed());
                count(response.status().as_u16());
                return Ok(to_client(
                    response,
                    is_tls,
                    state.hsts(),
                    record.request_id(),
                ));
            }
            Some(Err(_)) if progress.client_failed() => {
                // The request body failed: the client went away in the
                // middle of it, or sent what is not a body. Not the
                // backend's failure, and there is nobody to answer.
                tracing::debug!(target: "gfe::proxy", backend = %authority, "the client left while its request was sent");
                return Err(Unanswered::ClientGone);
            }
            Some(Err(failure)) => {
                let kind = classify(&failure);
                tracing::debug!(target: "gfe::proxy", error = %failure, backend = %authority, "request to the backend failed");
                count_error(kind);
                if !kind.is_the_backends() {
                    // The node is at `max_upstream_connections`: not the
                    // backend's failure, and no other backend would fare
                    // better.
                    return Err(Refusal::Upstream(kind).into());
                }
                metrics.upstream_connect_errors.inc();
                count(502);
                let again = retry::may_retry(Attempted {
                    replayable,
                    attempts,
                    response_started: false,
                    failure: kind,
                });
                if !again {
                    return Err(Refusal::Upstream(kind).into());
                }
            }
            None if progress.waiting_for_client() => {
                // Nothing has been sent to the backend for too long because
                // the client has not sent the rest of the body: the client
                // stalled, which is not the backend's failure. A backend
                // that stops taking the body is not: GFE does not ask the
                // client for more until the backend has taken what it has.
                tracing::debug!(target: "gfe::proxy", backend = %authority, "request body stalled");
                return Err(Refusal::RequestBodyTimeout.into());
            }
            None => {
                tracing::debug!(target: "gfe::proxy", backend = %authority, "the backend did not respond in time");
                count_error(FailureKind::Timeout);
                count(504);
                return Err(Refusal::Upstream(FailureKind::Timeout).into());
            }
        }
    }
}

/// How the client speaks to a pool's backends.
fn client_scheme(scheme: Scheme) -> ClientScheme {
    match scheme {
        Scheme::Http => ClientScheme::Http,
        Scheme::Https => ClientScheme::Https,
        Scheme::H2c => ClientScheme::H2c,
    }
}

/// The backend's `response`, as the client gets it: without the backend's
/// hop-by-hop headers, with `Strict-Transport-Security: hsts` when the
/// request arrived over TLS (`is_tls`) and `hsts` is not empty, and with
/// the request id when the backend gave none.
pub(crate) fn to_client(
    response: Response<Incoming>,
    is_tls: bool,
    hsts: &str,
    request_id: &str,
) -> Response<BoxBody> {
    let (mut head, content) = response.into_parts();
    let headers = &mut head.headers;
    request::strip_hop_by_hop(headers);
    if is_tls
        && !hsts.is_empty()
        && let Ok(value) = HeaderValue::from_str(hsts)
    {
        headers.insert(STRICT_TRANSPORT_SECURITY, value);
    }
    if !headers.contains_key(X_REQUEST_ID)
        && let Ok(id) = HeaderValue::from_str(request_id)
    {
        headers.insert(X_REQUEST_ID, id);
    }
    Response::from_parts(head, body::boxed(content))
}

/// Marks a backend as busy with one request, for least-request selection,
/// for its pool's `max_in_flight` and for
/// `gfe_upstream_requests_in_flight`, until dropped.
struct BackendBusy {
    _least_request: InflightGuard,
    _pool: Arc<InflightGuard>,
    in_flight: Gauge,
}

impl BackendBusy {
    fn new(least_request: InflightGuard, pool: Arc<InflightGuard>, in_flight: Gauge) -> Self {
        in_flight.inc();
        BackendBusy {
            _least_request: least_request,
            _pool: pool,
            in_flight,
        }
    }
}

impl Drop for BackendBusy {
    fn drop(&mut self) {
        self.in_flight.dec();
    }
}

#[cfg(test)]
#[path = "forward_test.rs"]
mod tests;
