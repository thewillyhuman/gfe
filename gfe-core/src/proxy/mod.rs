//! What happens to a request: which host it is for, the route it takes, the
//! backend it is sent to, what is retried, what the client is told when it
//! cannot be served, and what is counted and logged about it.
//!
//! Pingora's proxy engine carries every request from its head to the last
//! byte of its response, and calls [`GfeProxy`] at each stage
//! (`ProxyHttp`):
//!
//! | callback | what GFE does |
//! |---|---|
//! | `early_request_filter` | find the connection, start the record, the request id |
//! | `request_filter` | host rules, head size, route; fixed and redirect answers; what is refused before a backend is chosen; the pool's quota |
//! | `upstream_peer` | a healthy backend, its address, the peer to it |
//! | `upstream_request_filter` | forwarding headers, `Host` / `:authority` |
//! | `fail_to_connect`, `error_while_proxy` | why the attempt failed; whether to retry |
//! | `upstream_response_filter` | the backend's status, time to first byte |
//! | `response_filter` | hop-by-hop headers, HSTS, `X-Request-Id` |
//! | `upstream_response_trailer_filter` | `grpc-status` |
//! | `fail_to_proxy` | the answer GFE writes itself |
//! | `logging` | report the request: metrics and the `gfe::access` event |
//!
//! Pingora logs every failed request itself, through the `log` crate at
//! error level, and every retried attempt at warning level. GFE turns both
//! off ([`ProxyHttp::suppress_error_log`],
//! [`ProxyHttp::suppress_proxy_warn_log`]): each request already has one
//! `gfe::access` event saying why it failed (`error`), and the cause as
//! Pingora tells it is logged at debug level under `gfe::proxy`, as the old
//! proxy did.

mod connection_cap;
mod context;
mod dns;
mod error;
mod failure;
mod forward;
mod host;
mod peer;
mod record;
mod request;
mod respond;
mod retry;
mod state;
#[cfg(test)]
pub(crate) mod test_support;

pub use context::RequestCtx;
pub use error::ProxyError;
pub use state::State;

use crate::proxy::context::{Attempt, Forward};
use crate::proxy::failure::{Failure, FailureKind, classify};
use crate::proxy::forward::Forwarding;
use crate::proxy::record::{Arrival, RequestRecord, Side, Termination, UpstreamLeg};
use crate::proxy::respond::{Answer, Refusal};
use crate::proxy::retry::{Attempted, MAX_ATTEMPTS};
use async_trait::async_trait;
use gfe_config::{PoolId, RouteAction};
use gfe_observability::{PoolLabel, UpstreamDurationLabels, UpstreamErrorLabels, UpstreamLabels};
use http::header::USER_AGENT;
use pingora_core::apps::HttpServerOptions;
use pingora_core::protocols::http::v2::server::default_h2_options;
use pingora_core::server::configuration::ServerConf;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_error::{Error, ErrorSource, ErrorType, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::{FailToProxy, HttpProxy, ProxyHttp, ProxyWarnLogContext, Session};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The Pingora application the edge hands every client connection to.
pub type App = HttpProxy<GfeProxy>;

/// Build the Pingora application that serves requests with `state`.
///
/// This is the one place the node configures Pingora: its idle upstream
/// pool (`[upstream] idle_connections`, which Pingora multiplies by its
/// worker count, so it is divided by it here), how many attempts a request
/// may get, cleartext HTTP/2 by prior knowledge, and the HTTP/2 stream and
/// header-list limits.
///
/// Pingora's own HTTP/2 idle timeout is deliberately left unset: it drops
/// an idle connection without a `GOAWAY`. The edge asks an HTTP/2
/// connection idle for `client_idle` to leave instead, and records why.
/// `CONNECT` reaches GFE, which refuses it itself (`400`,
/// `unsupported_request_target`) rather than leaving Pingora to answer `405`.
pub fn app(state: Arc<State>) -> Arc<App> {
    let conf = ServerConf {
        threads: state.worker_threads,
        upstream_keepalive_pool_size: state.idle_connections.div_ceil(state.worker_threads).max(1),
        max_retries: MAX_ATTEMPTS as usize,
        ..ServerConf::default()
    };
    let mut server = HttpServerOptions::default();
    server.h2c = true;
    server.allow_connect_method_proxying = true;
    let mut h2 = default_h2_options();
    h2.max_concurrent_streams(state.max_h2_concurrent_streams);
    h2.max_header_list_size(u32::try_from(state.max_header_bytes).unwrap_or(u32::MAX));
    let mut proxy = pingora_proxy::http_proxy(&Arc::new(conf), GfeProxy { state });
    proxy.server_options = Some(server);
    proxy.h2_options = Some(h2);
    Arc::new(proxy)
}

/// GFE's request path, as Pingora's proxy engine drives it.
#[derive(Debug)]
pub struct GfeProxy {
    state: Arc<State>,
}

/// What `request_filter` decided.
enum Decision {
    /// Answer with GFE's own answer.
    Answer(Box<Answer>),
    /// Refuse, saying why.
    Refuse(Refusal),
    /// Forward to a backend.
    Forward,
}

impl GfeProxy {
    /// Route the request and decide what becomes of it. `has_body` says
    /// whether the request has a body, which only the body itself tells (an
    /// HTTP/1.1 body may be chunked, an HTTP/2 one need not announce a
    /// `content-length`).
    fn decide(&self, session: &Session, ctx: &mut RequestCtx, has_body: bool) -> Decision {
        let state = &self.state;
        let req = session.req_header();
        let sni = ctx.sni.as_deref();
        let host =
            host::request_host(&req.uri, &req.headers, req.version, sni).and_then(
                |host| match sni {
                    Some(_) => host::covered_by_sni(sni, host, &state.resolver().current()),
                    None => Ok(host),
                },
            );
        let record = ctx.record();
        match host {
            Ok(host) => record.host = host,
            Err(error) => {
                let refusal = error.refusal();
                record.host = error.into_host();
                return Decision::Refuse(refusal);
            }
        }
        if request::head_size(req) > state.max_header_bytes {
            return Decision::Refuse(Refusal::HeaderTooLarge);
        }

        let routing = state.routing.load();
        let listener = gfe_config::ListenerId(record.arrival.listener.clone());
        let path = req.uri.path();
        let Some(route) = routing.routes.match_request(&listener, &record.host, path) else {
            state.metrics().proxy.no_route.inc();
            return Decision::Refuse(Refusal::NoRoute);
        };
        record.route = Some(Arc::clone(route));
        let request_id = &record.request_id;
        match &route.action {
            RouteAction::Redirect(redirect) => {
                let path_and_query = req.uri.path_and_query().map_or("/", |pq| pq.as_str());
                Decision::Answer(Box::new(respond::redirect(
                    &redirect.scheme,
                    redirect.status,
                    &record.host,
                    path_and_query,
                    request_id,
                )))
            }
            RouteAction::Fixed(fixed) => Decision::Answer(Box::new(respond::fixed(
                fixed.status,
                &fixed.body,
                request_id,
            ))),
            RouteAction::Forward(pool) => {
                if !request::names_a_path(req.raw_path()) {
                    return Decision::Refuse(Refusal::UnsupportedTarget);
                }
                if request::asks_for_upgrade(&req.headers) {
                    // GFE cannot relay an upgraded connection. Forwarded
                    // without its hop-by-hop `Connection: upgrade`, the
                    // handshake would reach the backend as a plain request;
                    // refusing it says what happened.
                    return Decision::Refuse(Refusal::UpgradeNotSupported);
                }
                let Some(pool) = routing.pools.get(&PoolId(pool.clone())) else {
                    tracing::warn!(target: "gfe::proxy", %pool, "route references unknown pool");
                    return Decision::Refuse(Refusal::PoolNotFound);
                };
                record.upstream = Some(UpstreamLeg {
                    pool: pool.id.0.clone(),
                    backend: None,
                    attempts: 0,
                    time_to_first_byte: None,
                });
                let Some(admitted) = pool.admit() else {
                    let label = PoolLabel {
                        pool: pool.id.0.clone(),
                    };
                    state
                        .metrics()
                        .proxy
                        .upstream_pool_full
                        .get_or_create(&label)
                        .inc();
                    return Decision::Refuse(Refusal::PoolFull);
                };
                ctx.forward = Some(Forward::new(
                    Arc::clone(pool),
                    admitted,
                    retry::is_replayable(&req.method, has_body),
                    request::asks_for_trailers(&req.headers),
                ));
                Decision::Forward
            }
        }
    }

    /// End keep-alive on the response about to be written if the node
    /// drains. Pingora does so by itself only for requests that arrived
    /// after the drain began; without this, a request already in flight
    /// would be answered `Connection: keep-alive`, and its connection
    /// closed only when idle connections are, at half the drain deadline.
    /// HTTP/2 connections are told by a `GOAWAY` instead.
    fn end_keepalive_if_draining(&self, session: &mut Session) {
        if self.state.is_draining() {
            session.set_keepalive(None);
        }
    }

    /// Answer the request with `answer`, which GFE writes itself.
    async fn answer(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        answer: Answer,
    ) -> Result<bool> {
        self.end_keepalive_if_draining(session);
        ctx.answering(&answer);
        respond::send(session, answer).await?;
        ctx.answered = true;
        Ok(true)
    }

    /// The attempt in progress failed, with `kind`: count it, and give the
    /// backend back.
    fn attempt_failed(&self, ctx: &mut RequestCtx, kind: FailureKind) {
        let metrics = &self.state.metrics().proxy;
        let Some(attempt) = ctx.forward.as_mut().and_then(|f| f.attempt.take()) else {
            return;
        };
        let UpstreamDurationLabels { pool, backend } = &attempt.labels;
        metrics
            .upstream_errors
            .get_or_create(&UpstreamErrorLabels {
                pool: pool.clone(),
                backend: backend.clone(),
                kind: kind.as_str().to_string(),
            })
            .inc();
        if kind.is_the_backends() {
            let status = match kind {
                FailureKind::Timeout => 504,
                _ => {
                    metrics.upstream_connect_errors.inc();
                    502
                }
            };
            metrics
                .upstream_requests
                .get_or_create(&UpstreamLabels {
                    pool: pool.clone(),
                    backend: backend.clone(),
                    status: status.to_string(),
                })
                .inc();
        }
        metrics
            .upstream_request_duration_seconds
            .get_or_create(&attempt.labels)
            .observe(attempt.started.elapsed().as_secs_f64());
        ctx.refusal = Some(Refusal::Upstream(kind));
    }

    /// Whether the request may be retried after its attempt failed with
    /// `kind`.
    fn may_retry(&self, ctx: &RequestCtx, kind: FailureKind, response_started: bool) -> bool {
        ctx.forward.as_ref().is_some_and(|forward| {
            retry::may_retry(Attempted {
                replayable: forward.replayable,
                attempts: forward.attempts,
                response_started,
                failure: kind,
            })
        })
    }
}

#[async_trait]
impl ProxyHttp for GfeProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> RequestCtx {
        RequestCtx::new(Arc::clone(&self.state))
    }

    /// Find the connection the request arrived on, and start the record.
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<()> {
        let started = Instant::now();
        let state = &self.state;
        let addresses = (inet(session.client_addr()), inet(session.server_addr()));
        let conn = match addresses {
            (Some(client), Some(local)) => state.connections().lookup(client, local),
            _ => None,
        };
        if conn.is_none() {
            // A connection the edge did not register: a bug in how the node
            // is put together. The request is served as one that matches no
            // listener, so no route.
            tracing::error!(target: "gfe::proxy", client = ?addresses.0, local = ?addresses.1, "request on an unregistered connection");
        }
        let tls = conn.as_ref().and_then(|conn| conn.tls());
        let arrival = Arrival {
            client: addresses.0,
            listener: conn
                .as_ref()
                .map(|conn| conn.listener().id.0.clone())
                .unwrap_or_default(),
            is_tls: tls.is_some(),
            sni: tls.and_then(|tls| tls.sni.clone()),
            tls_version: tls.map(|tls| tls.version),
            tls_cipher: tls.map(|tls| tls.cipher.clone()),
        };
        let req = session.req_header();
        let is_grpc = request::is_grpc(&req.headers);
        let record = RequestRecord::begin(
            started,
            arrival,
            request::request_id(&req.headers),
            req.method.clone(),
            req.version,
            req.uri.path().to_string(),
            req.headers
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            is_grpc,
        );
        ctx.begin(record, conn.as_ref());

        let timeouts = &state.timeouts;
        // An HTTP/1 connection the engine would keep alive waits for the next
        // request a little longer than `client_idle` (Pingora counts in whole
        // seconds): the edge closes it at exactly `client_idle`, and records
        // why (`idle_timeout`); this is only a backstop.
        if session.get_keepalive().is_some() {
            session.set_keepalive(Some(keepalive_secs(timeouts.client_idle)));
        }
        if !is_grpc {
            // A client that stops sending the request body for this long
            // has stalled (`408`). A gRPC stream may be silent at will.
            session.set_read_timeout(Some(timeouts.upstream_first_byte));
        }
        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut RequestCtx) -> Result<bool> {
        let has_body = !session.as_mut().is_body_empty();
        match self.decide(session, ctx, has_body) {
            Decision::Forward => Ok(false),
            Decision::Answer(answer) => self.answer(session, ctx, *answer).await,
            Decision::Refuse(refusal) => {
                let record = ctx.record();
                record.error = Some(refusal.reason());
                let answer = respond::refusal(refusal, &record.request_id, record.is_grpc);
                self.answer(session, ctx, answer).await
            }
        }
    }

    /// Select a healthy backend of the request's pool, and the peer to it.
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<Box<HttpPeer>> {
        let state = &self.state;
        let now = Instant::now();
        let record = ctx
            .record
            .as_ref()
            .expect("early_request_filter starts the record");
        let since_received = now.saturating_duration_since(record.started);
        let client = record.arrival.client;
        let is_grpc = record.is_grpc;
        let forward = ctx
            .forward
            .as_mut()
            .expect("request_filter forwards only after setting the pool");
        let timeouts = &state.timeouts;
        if forward.attempts > 0 && since_received >= timeouts.request_total {
            ctx.refusal = Some(Refusal::Upstream(FailureKind::Timeout));
            return Err(Error::explain(
                ErrorType::HTTPStatus(504),
                "request_total elapsed before another attempt",
            ));
        }
        // The affinity key of `ring_hash` is the client's address.
        let hash_key = client.map(|client| gfe_load_balancing::policy::hash64(client.ip()));
        let Some(selection) = forward.pool.select(state.health(), hash_key) else {
            state.metrics().proxy.no_healthy_upstream.inc();
            ctx.refusal = Some(Refusal::NoHealthyUpstream);
            return Err(Error::explain(
                ErrorType::HTTPStatus(503),
                "no healthy upstream",
            ));
        };
        let upstream = selection.upstream;
        let backend = upstream.authority();
        let labels = UpstreamDurationLabels {
            pool: forward.pool.id.0.clone(),
            backend: backend.clone(),
        };
        let metrics = &state.metrics().proxy;
        if forward.attempts > 0 {
            let label = PoolLabel {
                pool: labels.pool.clone(),
            };
            metrics.upstream_retries.get_or_create(&label).inc();
        }
        let in_flight = metrics
            .upstream_requests_in_flight
            .get_or_create(&labels)
            .clone();
        forward.attempts += 1;
        forward.first_attempt.get_or_insert(now);
        forward.attempt = Some(Attempt::begin(labels, in_flight, selection.guard));
        let attempts = forward.attempts;
        let scheme = forward.pool.scheme;
        if let Some(leg) = ctx.record().upstream.as_mut() {
            leg.backend = Some(backend);
            leg.attempts = attempts;
        }

        let address: SocketAddr = match state.dns.address(&upstream.host, upstream.port, now).await
        {
            Ok(address) => address,
            Err(error) => {
                tracing::debug!(target: "gfe::proxy", host = %upstream.host, %error, "backend lookup failed");
                self.attempt_failed(ctx, FailureKind::ConnectError);
                let mut error =
                    Error::because(ErrorType::ConnectError, "looking up the backend", error);
                error.set_retry(self.may_retry(ctx, FailureKind::ConnectError, false));
                return Err(error.into_up());
            }
        };
        // A retry may not outlast `request_total`.
        let read_timeout = if attempts > 1 {
            timeouts
                .upstream_first_byte
                .min(timeouts.request_total.saturating_sub(since_received))
                .max(Duration::from_millis(1))
        } else {
            timeouts.upstream_first_byte
        };
        let mut peer = peer::build(
            address,
            &upstream.host,
            scheme,
            is_grpc,
            read_timeout,
            &state.waits,
            &state.upstream_tls,
        );
        state.cap.arm(&mut peer.options);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut RequestCtx,
    ) -> Result<()> {
        let record = ctx
            .record
            .as_ref()
            .expect("early_request_filter starts the record");
        let forward = ctx
            .forward
            .as_ref()
            .expect("forwarded requests have a pool");
        let backend = forward
            .attempt
            .as_ref()
            .map_or("", |attempt| attempt.labels.backend.as_str());
        let forwarding = Forwarding {
            client: record
                .arrival
                .client
                .map_or(std::net::Ipv4Addr::UNSPECIFIED.into(), |client| client.ip()),
            proto: if record.arrival.is_tls {
                "https"
            } else {
                "http"
            },
            host: &record.host,
            request_id: &record.request_id,
            asks_for_trailers: forward.asks_for_trailers,
        };
        forward::add_forwarding_headers(upstream_request, &forwarding)?;
        forward::set_target_and_host(upstream_request, backend)
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut RequestCtx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        let kind = match classify(&e, true, true) {
            Failure::Upstream(kind) => kind,
            Failure::ClientStalled | Failure::ClientGone => FailureKind::ConnectError,
        };
        tracing::debug!(target: "gfe::proxy", error = %e, %peer, "connecting to the backend failed");
        self.attempt_failed(ctx, kind);
        e.set_retry(self.may_retry(ctx, kind, false));
        e
    }

    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        mut e: Box<Error>,
        ctx: &mut RequestCtx,
        _client_reused: bool,
    ) -> Box<Error> {
        let responded = ctx.forward.as_ref().is_some_and(|f| f.responded)
            || session.response_written().is_some();
        if responded {
            // Nothing is retried once the response has started; the backend
            // stays busy with the request until it is reported.
            e.set_retry(false);
            return e;
        }
        tracing::debug!(target: "gfe::proxy", error = %e, %peer, "request to the backend failed");
        let request_complete = session.as_mut().is_body_done();
        match classify(&e, false, request_complete) {
            Failure::Upstream(kind) => {
                self.attempt_failed(ctx, kind);
                e.set_retry(self.may_retry(ctx, kind, false));
            }
            Failure::ClientStalled => {
                // Not the backend's failure: it is given back uncounted.
                if let Some(forward) = ctx.forward.as_mut() {
                    forward.attempt = None;
                }
                ctx.refusal = Some(Refusal::RequestBodyTimeout);
                e.set_retry(false);
            }
            Failure::ClientGone => {
                if let Some(forward) = ctx.forward.as_mut() {
                    forward.attempt = None;
                }
                e.set_retry(false);
            }
        }
        e
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> Result<()> {
        if upstream_response.status.is_informational() {
            return Ok(());
        }
        let metrics = &self.state.metrics().proxy;
        let Some(forward) = ctx.forward.as_mut() else {
            return Ok(());
        };
        forward.responded = true;
        let ttfb = forward.first_attempt.map(|first| first.elapsed());
        if let Some(attempt) = &forward.attempt {
            let UpstreamDurationLabels { pool, backend } = &attempt.labels;
            metrics
                .upstream_requests
                .get_or_create(&UpstreamLabels {
                    pool: pool.clone(),
                    backend: backend.clone(),
                    status: upstream_response.status.as_str().to_string(),
                })
                .inc();
            metrics
                .upstream_request_duration_seconds
                .get_or_create(&attempt.labels)
                .observe(attempt.started.elapsed().as_secs_f64());
        }
        let record = ctx.record();
        if let Some(leg) = record.upstream.as_mut() {
            leg.time_to_first_byte = ttfb;
        }
        if record.is_grpc {
            record.grpc_status = record::grpc_status(&upstream_response.headers);
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut RequestCtx,
    ) -> Result<()> {
        self.end_keepalive_if_draining(session);
        forward::strip_response_hop_by_hop(upstream_response);
        let record = ctx.record();
        if record.arrival.is_tls {
            forward::add_hsts(upstream_response, &self.state.hsts)?;
        }
        if !upstream_response.headers.contains_key("x-request-id")
            && let Ok(id) = http::HeaderValue::from_str(&record.request_id)
        {
            upstream_response.insert_header("x-request-id", id)?;
        }
        Ok(())
    }

    fn upstream_response_trailer_filter(
        &self,
        _session: &mut Session,
        upstream_trailers: &mut http::HeaderMap,
        ctx: &mut RequestCtx,
    ) -> Result<()> {
        let record = ctx.record();
        if record.is_grpc
            && let Some(status) = record::grpc_status(upstream_trailers)
        {
            record.grpc_status = Some(status);
        }
        Ok(())
    }

    /// Answer a request that failed, unless the client is gone or a
    /// response has started (then there is nobody, or no way, to tell).
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut RequestCtx,
    ) -> FailToProxy {
        let refusal = ctx
            .refusal
            .take()
            .or_else(|| match classify(e, false, true) {
                Failure::Upstream(kind) => Some(Refusal::Upstream(kind)),
                Failure::ClientStalled => Some(Refusal::RequestBodyTimeout),
                Failure::ClientGone => None,
            });
        if let Some(record) = ctx.record.as_ref() {
            tracing::debug!(target: "gfe::proxy", request_id = %record.request_id, error = %e, "request failed");
        }
        let cannot_answer = ctx.answer_attempted || session.response_written().is_some();
        let (Some(refusal), false) = (refusal, cannot_answer) else {
            return FailToProxy {
                error_code: 0,
                can_reuse_downstream: false,
            };
        };
        let record = ctx.record();
        record.error = Some(refusal.reason());
        let answer = respond::refusal(refusal, &record.request_id, record.is_grpc);
        let status = answer.status();
        self.end_keepalive_if_draining(session);
        ctx.answering(&answer);
        if respond::send(session, answer).await.is_ok() {
            ctx.answered = true;
        }
        FailToProxy {
            error_code: status,
            can_reuse_downstream: false,
        }
    }

    /// Report the request: the exchange is over.
    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut RequestCtx) {
        let written = session
            .response_written()
            .map(|resp| resp.status)
            .filter(|status| !status.is_informational())
            .map(|status| status.as_u16());
        let side = e.map(|e| match e.esource() {
            ErrorSource::Downstream => Side::Client,
            _ => Side::Upstream,
        });
        let termination = Termination::of(side, ctx.answered, written.is_some());
        let bytes = (
            session.body_bytes_read() as u64,
            session.body_bytes_sent() as u64,
        );
        ctx.finish(written, bytes, termination);
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &RequestCtx, _error: &Error) -> bool {
        true
    }

    fn suppress_proxy_warn_log(
        &self,
        _session: &Session,
        _ctx: &RequestCtx,
        _error: &Error,
        _context: ProxyWarnLogContext,
    ) -> bool {
        true
    }
}

/// Pingora's HTTP/1 keep-alive timeout, in whole seconds, for `client_idle`:
/// rounded up, plus one, so that it never fires before the edge's own.
fn keepalive_secs(client_idle: Duration) -> u64 {
    let whole = client_idle.as_secs() + u64::from(client_idle.subsec_nanos() > 0);
    whole + 1
}

/// The Internet address of a socket address Pingora reports, if it is one.
fn inet(address: Option<&pingora_core::protocols::l4::socket::SocketAddr>) -> Option<SocketAddr> {
    address.and_then(|address| address.as_inet()).copied()
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod tests;
