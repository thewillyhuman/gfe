//! What happens to a request once the edge has handed it over, built on
//! `netkit-http` to replace [`crate::proxy`], which runs on Pingora.
//!
//! Nothing serves through this module yet: it is built part by part, next
//! to the request handling that runs today, until it can take its place.

pub mod failure;
pub mod respond;
