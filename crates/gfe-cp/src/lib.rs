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
//! * [`render`] — desired state → node-facing dynamic JSON + bootstrap TOML (§4).
//! * [`validate`] — controller-side validation, incl. node-identical checks (§5).
//! * [`publish`] — render + validate + persist a revision + set the target (§8).
//! * [`rollout`] — which revision a node may advance to (canary/wave gating, §8).
//! * [`server`] — the HTTP operator + pull-agent API (§9).

pub mod crypto;
pub mod publish;
pub mod render;
pub mod rollout;
pub mod server;
pub mod store;
pub mod validate;

pub use publish::{prepare, publish, Prepared, PublishError};
pub use render::{render, render_node_toml, Rendered};
pub use server::{serve, ApiState, Auth};
pub use store::{Store, StoreError};
pub use validate::{validate, Report, ValidateError};
