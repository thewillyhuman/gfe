//! What the edge asks of whoever answers requests.
use crate::edge::ConnInfo;
use netkit_http::body::{BoxBody, Incoming};
use netkit_http::{Request, Response};
use std::future::Future;
use std::sync::Arc;

/// Whoever answers the requests that arrive at the edge.
///
/// The edge knows connections and nothing of what a request is answered
/// with; a handler knows requests and nothing of sockets. This trait is all
/// the two share, with [`ConnInfo`].
pub trait RequestHandler: Send + Sync + 'static {
    /// Answer `request`, which arrived on `conn`.
    ///
    /// There is always an answer: a request that cannot be served gets a
    /// response that says so. The request counts as in flight on its
    /// connection until the body of the response has been sent to its end
    /// or dropped. The future is dropped when the client goes away, or the
    /// node cuts the connection, before the response is ready.
    fn handle(
        &self,
        conn: Arc<ConnInfo>,
        request: Request<Incoming>,
    ) -> impl Future<Output = Response<BoxBody>> + Send;
}
