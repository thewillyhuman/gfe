//! The bodies of requests and responses.
//!
//! A body is anything that implements [`Body`]: a stream of data frames,
//! possibly ended by trailers. What arrives from a peer is an [`Incoming`].
//! What is sent can be any body; [`BoxBody`] is the one type that holds
//! whichever it is, so that a handler can answer with a fixed text on one
//! path and relay a stream on another.
use bytes::Bytes;

pub use http_body::{Body, Frame, SizeHint};
pub use http_body_util::BodyExt;
pub use hyper::body::Incoming;

/// What a body fails with: any error, whatever produced the body.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A body of any kind.
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// A body with nothing in it.
pub fn empty() -> BoxBody {
    boxed(http_body_util::Empty::new())
}

/// A body that is `bytes`, sent at once.
pub fn full(bytes: impl Into<Bytes>) -> BoxBody {
    boxed(http_body_util::Full::new(bytes.into()))
}

/// `body` as a [`BoxBody`], frame for frame.
pub fn boxed<B>(body: B) -> BoxBody
where
    B: Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed()
}

#[cfg(test)]
#[path = "body_test.rs"]
mod tests;
