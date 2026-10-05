//! The client timeouts of one connection, decided from its request activity.
//!
//! Pingora bounds the wait for an HTTP/1 request head by a keep-alive
//! timeout in whole seconds, waits 60 s for the first one whatever the
//! config says, and cannot tell a connection that never sent a request from
//! one waiting between keep-alive requests. The edge therefore decides
//! itself, from the one fact needed for all of it: whether a request is in
//! flight ([`ConnInfo`]), and since when none has been.
//!
//! A request is *in flight* from its parsed head until its response has been
//! written to its end (or abandoned). A connection with one in flight is
//! never closed by these timeouts: a slow backend is not an idle client.

use crate::listener::ConnInfo;
use gfe_config::TimeoutsConfig;
use std::time::Instant;

/// Why the edge ended a connection, or asked it to end, on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Expiry {
    /// No request head arrived within `request_header` of the connection
    /// being established (after its TLS handshake).
    Header,
    /// No request was in flight for `client_idle`.
    Idle,
    /// The node is draining and the connection sent no request within half
    /// the drain deadline.
    Drain,
}

/// What a connection's request activity looks like at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Activity {
    pub(crate) established: Instant,
    pub(crate) requests: u64,
    pub(crate) in_flight: bool,
    /// Since when no request has been in flight; meaningful only when none
    /// is.
    pub(crate) idle_since: Instant,
}

impl Activity {
    pub(crate) fn of(conn: &ConnInfo) -> Self {
        // In-flight first: whoever sees none in flight also sees since when.
        let in_flight = conn.has_request_in_flight();
        Activity {
            established: conn.established(),
            requests: conn.requests(),
            in_flight,
            idle_since: conn.idle_since(),
        }
    }
}

/// What the edge must do about a connection, given its activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// End it, for this reason.
    Expired(Expiry),
    /// Within limits; nothing can expire before this instant.
    CheckAgainAt(Instant),
    /// A request is in flight: nothing can expire until it has ended.
    WaitUntilIdle,
}

/// Decide what to do at `now` about a connection whose activity is
/// `activity`. `leave_by` is set once the node drains: until when the
/// connection may still send a request.
pub(crate) fn verdict(
    activity: Activity,
    now: Instant,
    timeouts: &TimeoutsConfig,
    leave_by: Option<Instant>,
) -> Verdict {
    if activity.in_flight {
        return Verdict::WaitUntilIdle;
    }
    if leave_by.is_some_and(|leave_by| now >= leave_by) {
        return Verdict::Expired(Expiry::Drain);
    }
    let (deadline, expiry) = if activity.requests == 0 {
        (
            activity.established + timeouts.request_header,
            Expiry::Header,
        )
    } else {
        (activity.idle_since + timeouts.client_idle, Expiry::Idle)
    };
    if now >= deadline {
        return Verdict::Expired(expiry);
    }
    Verdict::CheckAgainAt(leave_by.map_or(deadline, |leave_by| leave_by.min(deadline)))
}

#[cfg(test)]
#[path = "activity_test.rs"]
mod tests;
