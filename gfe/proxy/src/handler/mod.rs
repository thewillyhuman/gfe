//! What happens to a request once the edge has handed it over, built on
//! `netkit-http` to replace [`crate::proxy`], which runs on Pingora.
//!
//! Nothing serves through this module yet: it is built part by part, next
//! to the request handling that runs today, until it can take its place.

mod error;
pub mod failure;
pub mod forward;
pub mod host;
pub mod progress;
pub mod record;
pub mod request;
pub mod respond;
pub mod retry;
mod state;
#[cfg(test)]
pub(crate) mod test_support;

pub use error::ProxyError;
pub use state::State;
