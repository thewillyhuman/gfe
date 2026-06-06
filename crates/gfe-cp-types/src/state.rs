//! The desired-state bundle for one fleet: everything the renderer needs to
//! produce the node-facing files. Assembled by the store from the individual
//! resource tables.

use crate::fleet::Fleet;
use crate::resource::{Certificate, ListenerSpec, PoolSpec, RouteSpec};
use serde::{Deserialize, Serialize};

/// All desired configuration for one fleet, the input to the renderer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FleetState {
    pub fleet: Fleet,
    #[serde(default)]
    pub listeners: Vec<ListenerSpec>,
    #[serde(default)]
    pub certificates: Vec<Certificate>,
    #[serde(default)]
    pub pools: Vec<PoolSpec>,
    #[serde(default)]
    pub routes: Vec<RouteSpec>,
}

impl FleetState {
    /// An empty fleet state carrying only fleet identity + policy.
    pub fn new(fleet: Fleet) -> Self {
        FleetState {
            fleet,
            listeners: Vec::new(),
            certificates: Vec::new(),
            pools: Vec::new(),
            routes: Vec::new(),
        }
    }
}
