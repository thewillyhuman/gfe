//! `gfe-cp` — the GFE control plane.
//!
//! Holds the desired state of every fleet, renders the node-facing
//! configuration, captures it as immutable revisions, and orchestrates rollout
//! onto nodes via the pull agent. See `.docs/gfe-cp-spec.md`.
//!
//! This crate is organized as cohesive modules rather than separate crates, but
//! each maps to a section of the spec:
//!
//! * [`crypto`] — content hashing + envelope encryption of cert material (§6, §9).
//! * [`store`] — desired-state persistence; the Postgres swap seam (§3).

pub mod crypto;
pub mod store;

pub use store::{Store, StoreError};
