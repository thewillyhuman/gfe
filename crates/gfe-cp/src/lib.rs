//! `gfe-cp` — the GFE control plane.
//!
//! Holds the desired state of every fleet, renders the node-facing
//! configuration, captures it as immutable revisions, and orchestrates rollout
//! onto nodes via the pull agent. See `.docs/gfe-cp-spec.md`.
//!
//! This crate is organized as cohesive modules rather than separate crates, but
//! each maps to a section of the spec:
//!
//! * [`mod@crypto`] — content hashing + envelope encryption of cert material (§6, §9).
//! * [`mod@store`] — desired-state persistence; the Postgres swap seam (§3).
//! * [`mod@render`] — desired state → node-facing dynamic JSON + bootstrap TOML (§4).
//! * [`mod@validate`] — controller-side validation, incl. node-identical checks (§5).
//! * [`mod@publish`] — render + validate + persist a revision + set the target (§8).
//! * [`mod@rollout`] — which revision a node may advance to (canary/wave gating, §8).
//! * [`mod@auto`] — backend (de)registration debounce/coalescing (§9).
//! * [`mod@diff`] — desired-vs-target line diff for `fleet diff` (§9).
//! * [`mod@server`] — the HTTP operator + pull-agent API (§9).

pub mod auto;
pub mod crypto;
pub mod diff;
pub mod publish;
pub mod render;
pub mod rollout;
pub mod server;
pub mod store;
pub mod validate;

pub use auto::Debouncer;
pub use publish::{diff, prepare, publish, Diff, Prepared, PublishError};
pub use render::{render, render_node_toml, Rendered};
pub use server::{serve, serve_on, ApiState, Auth};
pub use store::{Store, StoreError};
pub use validate::{validate, Report, ValidateError};
