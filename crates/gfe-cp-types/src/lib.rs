//! Canonical domain types for the GFE control plane (`gfe-cp`).
//!
//! These mirror the desired-state data model in the control-plane spec (§3)
//! and the agent/operator wire protocol (§7, §9). They are pure data + serde,
//! with no I/O. The control-plane crates (store, render, rollout, server) and
//! the clients (`gfe-agent`, `gfectl`) all share these definitions so the
//! request/response shapes never drift between sides.
//!
//! Where a field feeds a node-facing file it maps 1:1 onto a `gfe-types`
//! struct; the renderer ([`gfe-cp`'s `render` module]) performs that mapping so
//! the bytes a node receives are produced from the very structs the node
//! deserializes.

pub mod fleet;
pub mod node;
pub mod resource;
pub mod revision;
pub mod rolloutstate;
pub mod state;
pub mod wire;

pub use fleet::{Fleet, LimitsSpec, RolloutPolicy, TimeoutsSpec, UpstreamSpec};
pub use node::{Node, ReloadState};
pub use resource::{
    Backend, Certificate, FixedSpec, ListenerSpec, PoolSpec, RedirectSpec, RouteActionSpec,
    RouteSpec,
};
pub use revision::{CertRef, Revision};
pub use rolloutstate::{RolloutPhase, RolloutState};
pub use state::FleetState;
pub use wire::{
    GetTargetRequest, GetTargetResponse, ReportStatusRequest, ReportStatusResponse, TargetCert,
    TargetRevision,
};
