//! What happens to a request once the edge has handed it over, on
//! `netkit-http`: which host it is for, the route it takes, the route's
//! action, and for a forward the backend it is sent to; what the client is
//! told when it cannot be served; and what is counted and logged about it.
//!
//! [`Proxy`] answers every request, in this order (see [`Proxy::handle`]):
//!
//! 1. The host the request is for (`host`): the target's authority, the
//!    `Host` header or the connection's SNI; the two first must agree, and
//!    over TLS the certificate the client accepted must cover it.
//! 2. Its record starts (`record`): it counts as in flight from here, and
//!    is reported once, as metrics and a `gfe::access` event, when its
//!    response body ends or is dropped, or when the client goes away first.
//! 3. The route that matches its listener, host and path ([`crate::routing`]).
//! 4. The route's action: a redirect or a fixed answer GFE writes itself
//!    (`respond`), or a forward to a pool (`forward`), which shapes the
//!    request for the backend (`request`), bounds the wait for it
//!    (`progress`), says why it failed (`failure`) and retries what may
//!    be retried (`retry`).
//!
//! A request that cannot be served at any step gets a small answer saying
//! why, in gRPC's terms for a gRPC call. What requests share, and a reload
//! swaps, is the [`State`].
//!
//! What hyper answers by itself never reaches the handler: a malformed head
//! (`400`), a head over `max_header_bytes` (`431`). Connections, TLS
//! termination and draining are the edge's ([`crate::edge`]).
//!
//! Nothing serves through this module yet: it replaces [`crate::proxy`],
//! which runs on Pingora, when the node switches over.

mod error;
mod failure;
mod forward;
mod host;
mod progress;
mod record;
mod request;
mod respond;
mod retry;
mod state;
#[cfg(test)]
pub(crate) mod test_support;

pub use error::ProxyError;
pub use state::State;

use crate::edge::{ConnInfo, RequestHandler};
use crate::handler::forward::Unanswered;
use crate::handler::record::RequestRecord;
use crate::handler::respond::Refusal;
use gfe_config::RouteAction;
use netkit_http::body::{self, BoxBody, Incoming};
use netkit_http::{Request, Response, StatusCode};
use std::sync::Arc;

/// GFE's answer to every request the edge hands over.
#[derive(Debug, Clone)]
pub struct Proxy {
    state: Arc<State>,
}

impl Proxy {
    /// A handler answering requests with what `state` holds at the time of
    /// each request.
    pub fn new(state: Arc<State>) -> Proxy {
        Proxy { state }
    }
}

impl RequestHandler for Proxy {
    /// Answer `request`, which arrived on `conn`. A request that cannot be
    /// served is answered with why; every request is reported once.
    async fn handle(&self, conn: Arc<ConnInfo>, request: Request<Incoming>) -> Response<BoxBody> {
        let state = &self.state;
        let sni = conn.sni();
        let host = host::request_host(request.uri(), request.headers(), request.version(), sni)
            .and_then(|host| match sni {
                Some(_) => host::covered_by_sni(sni, host, &state.resolver().current()),
                None => Ok(host),
            });
        // A request refused for its host is still logged under one.
        let (host, refused) = match host {
            Ok(host) => (host, None),
            Err(error) => {
                let refusal = error.refusal();
                (error.into_host(), Some(refusal))
            }
        };
        let record = RequestRecord::begin(
            Arc::clone(state.metrics()),
            Arc::clone(&conn),
            &request,
            host,
            request::request_id(request.headers()),
        );
        if let Some(refusal) = refused {
            return refuse(record, refusal);
        }
        route(state, &conn, request, record).await
    }
}

/// Answer `request`, whose host is known, as the route it matches says.
async fn route(
    state: &State,
    conn: &ConnInfo,
    request: Request<Incoming>,
    mut record: RequestRecord,
) -> Response<BoxBody> {
    let pool = {
        // Loaded once, and let go before anything is awaited.
        let routing = state.routing();
        let listener = conn.listener();
        let path = request.uri().path();
        let Some(route) = routing
            .routes
            .match_request(&listener.id, record.host(), path)
        else {
            state.metrics().proxy.no_route.inc();
            return refuse(record, Refusal::NoRoute);
        };
        record.matched(Arc::clone(route));
        match &route.action {
            RouteAction::Redirect(redirect) => {
                let path_and_query = request.uri().path_and_query().map_or("/", |pq| pq.as_str());
                let answer = respond::redirect(
                    &redirect.scheme,
                    redirect.status,
                    record.host(),
                    path_and_query,
                    record.request_id(),
                );
                return record.respond(answer);
            }
            RouteAction::Fixed(fixed) => {
                let answer = respond::fixed(fixed.status, &fixed.body, record.request_id());
                return record.respond(answer);
            }
            RouteAction::Forward(pool) => match routing.pools.get(pool) {
                Some(pool) => Arc::clone(pool),
                None => {
                    tracing::warn!(target: "gfe::proxy", %pool, "route references unknown pool");
                    return refuse(record, Refusal::PoolNotFound);
                }
            },
        }
    };
    match forward::forward(state, conn, &pool, request, &mut record).await {
        Ok(response) => record.respond(response),
        Err(Unanswered::Refused(refusal)) => refuse(record, refusal),
        Err(Unanswered::ClientGone) => abandoned(record),
    }
}

/// Answer the request of `record` with `refusal`, in gRPC's terms for a
/// gRPC call, and note why.
fn refuse(mut record: RequestRecord, refusal: Refusal) -> Response<BoxBody> {
    record.failed(refusal.reason());
    let answer = respond::refusal(refusal, record.request_id(), record.is_grpc());
    record.respond(answer)
}

/// The client of `record` went away, or broke its request body, before
/// there was a response. The request is reported now, as abandoned; the
/// `400` returned reaches nobody, or a client whose connection is closing
/// for the body it broke.
fn abandoned(record: RequestRecord) -> Response<BoxBody> {
    drop(record);
    let mut response = Response::new(body::empty());
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod tests;
