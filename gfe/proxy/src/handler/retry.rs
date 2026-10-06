//! What may be retried: conservatively, so that a failing backend is not
//! sent more load than it was, and no request is ever performed twice.
//!
//! A request is retried only if all of these hold:
//!
//! - it can be replayed: its method is idempotent and it has no body (a
//!   body has been streamed to the failed backend and is gone);
//! - nothing of the response has reached the client;
//! - the failure is one another backend could fare better at (not the
//!   node's own connection limit, not a timeout);
//! - it is the first attempt: there is at most one retry, against a backend
//!   selected afresh.
//!
//! How long a request may go on being retried is bounded by the timeouts
//! (`progress`), not here.

use crate::handler::failure::FailureKind;
use netkit_http::Method;

/// The most attempts a request gets: the first, and one retry.
pub(crate) const MAX_ATTEMPTS: u32 = 2;

/// Whether a request with `method` can be replayed: an idempotent method
/// (the methods GFE has always retried) and no body.
pub(crate) fn is_replayable(method: &Method, has_body: bool) -> bool {
    let idempotent = matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::DELETE
    );
    idempotent && !has_body
}

/// What the retry decision is made from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Attempted {
    /// Whether the request can be replayed ([`is_replayable`]).
    pub(crate) replayable: bool,
    /// How many attempts have been made, the failed one included.
    pub(crate) attempts: u32,
    /// Whether any of the response has been sent to the client.
    pub(crate) response_started: bool,
    /// Why the last attempt failed.
    pub(crate) failure: FailureKind,
}

/// Whether the request may be attempted again, against a new selection.
pub(crate) fn may_retry(attempted: Attempted) -> bool {
    attempted.replayable
        && !attempted.response_started
        && attempted.failure.is_retryable()
        && attempted.attempts < MAX_ATTEMPTS
}

#[cfg(test)]
#[path = "retry_test.rs"]
mod tests;
