//! Desired-state storage for the control plane.
//!
//! The spec (§3) calls for PostgreSQL holding normalized desired state, cert
//! blobs, and revisions. This module is the persistence *seam*: a concrete
//! store with the exact method surface a Postgres-backed implementation would
//! expose, but backed by an in-memory data model that optionally snapshots to a
//! JSON file. That keeps the whole control plane buildable and unit-testable
//! with no external services, while leaving a clean swap point for Postgres.
//!
//! Invariants enforced here (the ones the node cannot enforce for itself):
//! at most one default certificate per fleet (spec §6); content-addressed,
//! deduplicated cert storage; monotonic per-fleet revision sequences; and
//! immutable revisions (created, never mutated).

use crate::crypto::{cert_content_sha, Sealed, Sealer};
use gfe_cp_types::{
    Backend, Certificate, Fleet, FleetState, ListenerSpec, Node, PoolSpec, ReloadState, Revision,
    RolloutState, RouteSpec,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors surfaced by the store.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(String),
}

type Result<T> = std::result::Result<T, StoreError>;

/// Current unix time in seconds.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A stored certificate: public metadata plus the sealed PEM material.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CertRecord {
    meta: Certificate,
    sealed_cert: Sealed,
    sealed_key: Sealed,
}

/// Everything stored for one fleet. Resources are keyed by their stable name
/// (certs by content hash) so iteration order is deterministic.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FleetRecord {
    fleet: Fleet,
    nodes: BTreeMap<String, Node>,
    listeners: BTreeMap<String, ListenerSpec>,
    certificates: BTreeMap<String, CertRecord>,
    pools: BTreeMap<String, PoolSpec>,
    routes: BTreeMap<String, RouteSpec>,
    revisions: BTreeMap<i64, Revision>,
    next_seq: i64,
    target_seq: Option<i64>,
    /// Live rollout progress for the current target (spec §8.2).
    #[serde(default)]
    rollout: Option<RolloutState>,
}

impl FleetRecord {
    /// An empty record for a freshly created fleet (revision sequence starts
    /// at 1; no resources, nodes, or target yet).
    fn empty(fleet: Fleet) -> Self {
        FleetRecord {
            fleet,
            nodes: BTreeMap::new(),
            listeners: BTreeMap::new(),
            certificates: BTreeMap::new(),
            pools: BTreeMap::new(),
            routes: BTreeMap::new(),
            revisions: BTreeMap::new(),
            next_seq: 1,
            target_seq: None,
            rollout: None,
        }
    }
}

/// The serializable database snapshot.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Db {
    fleets: BTreeMap<String, FleetRecord>,
}

/// The desired-state store. Cheaply cloneable handle (`Arc` inside).
#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Db>>,
    sealer: Arc<dyn Sealer>,
    path: Option<PathBuf>,
}

impl Store {
    /// An empty in-memory store (no file persistence).
    pub fn in_memory(sealer: Arc<dyn Sealer>) -> Self {
        Store {
            inner: Arc::new(Mutex::new(Db::default())),
            sealer,
            path: None,
        }
    }

    /// Open a file-backed store, loading an existing snapshot if present.
    pub fn open(path: PathBuf, sealer: Arc<dyn Sealer>) -> Result<Self> {
        let db = if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            serde_json::from_str(&text).map_err(|e| StoreError::Serde(e.to_string()))?
        } else {
            Db::default()
        };
        Ok(Store {
            inner: Arc::new(Mutex::new(db)),
            sealer,
            path: Some(path),
        })
    }

    /// Run `f` under the lock, then snapshot to disk if file-backed.
    fn with_mut<T>(&self, f: impl FnOnce(&mut Db) -> Result<T>) -> Result<T> {
        let mut db = self.inner.lock().expect("store mutex poisoned");
        let out = f(&mut db)?;
        if let Some(path) = &self.path {
            let text =
                serde_json::to_string_pretty(&*db).map_err(|e| StoreError::Serde(e.to_string()))?;
            // Atomic-ish: write a temp file then rename into place.
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, text)?;
            std::fs::rename(&tmp, path)?;
        }
        Ok(out)
    }

    fn with<T>(&self, f: impl FnOnce(&Db) -> Result<T>) -> Result<T> {
        let db = self.inner.lock().expect("store mutex poisoned");
        f(&db)
    }

    // ───────────────────────── fleets ─────────────────────────

    /// Create a fleet. Errors if one with the same name exists.
    pub fn create_fleet(&self, mut fleet: Fleet) -> Result<Fleet> {
        self.with_mut(|db| {
            if db.fleets.contains_key(&fleet.name) {
                return Err(StoreError::AlreadyExists(format!("fleet {}", fleet.name)));
            }
            fleet.created_at = now();
            fleet.updated_at = fleet.created_at;
            db.fleets
                .insert(fleet.name.clone(), FleetRecord::empty(fleet.clone()));
            Ok(fleet)
        })
    }

    /// Replace a fleet's policy fields (identity stays). Errors if missing.
    pub fn update_fleet(&self, mut fleet: Fleet) -> Result<()> {
        self.with_mut(|db| {
            let rec = fleet_rec_mut(db, &fleet.name)?;
            fleet.created_at = rec.fleet.created_at;
            fleet.updated_at = now();
            rec.fleet = fleet;
            Ok(())
        })
    }

    /// Get a fleet by name.
    pub fn get_fleet(&self, name: &str) -> Result<Fleet> {
        self.with(|db| Ok(fleet_rec(db, name)?.fleet.clone()))
    }

    /// List all fleets, sorted by name.
    pub fn list_fleets(&self) -> Vec<Fleet> {
        let db = self.inner.lock().expect("store mutex poisoned");
        db.fleets.values().map(|r| r.fleet.clone()).collect()
    }

    /// Delete a fleet and everything in it.
    pub fn delete_fleet(&self, name: &str) -> Result<()> {
        self.with_mut(|db| {
            db.fleets
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(format!("fleet {name}")))
        })
    }

    // ───────────────────────── nodes ─────────────────────────

    /// Register (or overwrite) a node's desired identity.
    pub fn put_node(&self, node: Node) -> Result<()> {
        self.with_mut(|db| {
            let rec = fleet_rec_mut(db, &node.fleet)?;
            rec.nodes.insert(node.gfe_node_id.clone(), node);
            Ok(())
        })
    }

    /// List a fleet's nodes, sorted by id.
    pub fn list_nodes(&self, fleet: &str) -> Result<Vec<Node>> {
        self.with(|db| Ok(fleet_rec(db, fleet)?.nodes.values().cloned().collect()))
    }

    /// Get one node.
    pub fn get_node(&self, fleet: &str, node_id: &str) -> Result<Node> {
        self.with(|db| {
            fleet_rec(db, fleet)?
                .nodes
                .get(node_id)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(format!("node {fleet}/{node_id}")))
        })
    }

    /// Apply an agent's status report to a node's observed state.
    pub fn report_node_status(
        &self,
        fleet: &str,
        node_id: &str,
        applied_seq: i64,
        reload_state: ReloadState,
        healthy: bool,
    ) -> Result<()> {
        self.with_mut(|db| {
            let rec = fleet_rec_mut(db, fleet)?;
            let node = rec
                .nodes
                .get_mut(node_id)
                .ok_or_else(|| StoreError::NotFound(format!("node {fleet}/{node_id}")))?;
            node.applied_seq = Some(applied_seq);
            node.reload_state = reload_state;
            node.healthy = healthy;
            node.last_seen = now();
            Ok(())
        })
    }

    /// Remove a node.
    pub fn remove_node(&self, fleet: &str, node_id: &str) -> Result<()> {
        self.with_mut(|db| {
            fleet_rec_mut(db, fleet)?
                .nodes
                .remove(node_id)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(format!("node {fleet}/{node_id}")))
        })
    }

    // ───────────────────────── listeners ─────────────────────────

    /// Add or replace a listener.
    pub fn put_listener(&self, fleet: &str, listener: ListenerSpec) -> Result<()> {
        self.with_mut(|db| {
            fleet_rec_mut(db, fleet)?
                .listeners
                .insert(listener.name.clone(), listener);
            Ok(())
        })
    }

    /// Remove a listener by name.
    pub fn remove_listener(&self, fleet: &str, name: &str) -> Result<()> {
        self.with_mut(|db| {
            fleet_rec_mut(db, fleet)?
                .listeners
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(format!("listener {fleet}/{name}")))
        })
    }

    // ───────────────────────── certificates ─────────────────────────

    /// Store a certificate. The blobs are sealed; the row is keyed by
    /// `sha256(cert||key)` so identical material deduplicates. Enforces at most
    /// one default per fleet. Returns the content hash.
    pub fn add_certificate(
        &self,
        fleet: &str,
        sni: Vec<String>,
        is_default: bool,
        not_after: i64,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<String> {
        let content_sha = cert_content_sha(cert_pem, key_pem);
        let sealed_cert = self.sealer.seal(cert_pem)?;
        let sealed_key = self.sealer.seal(key_pem)?;
        self.with_mut(|db| {
            let rec = fleet_rec_mut(db, fleet)?;
            if is_default {
                if let Some(existing) = rec
                    .certificates
                    .values()
                    .find(|c| c.meta.is_default && c.meta.content_sha != content_sha)
                {
                    return Err(StoreError::Conflict(format!(
                        "fleet {fleet} already has a default certificate {}",
                        existing.meta.content_sha
                    )));
                }
            }
            let meta = Certificate {
                content_sha: content_sha.clone(),
                sni,
                is_default,
                not_after,
                created_at: now(),
            };
            rec.certificates.insert(
                content_sha.clone(),
                CertRecord {
                    meta,
                    sealed_cert,
                    sealed_key,
                },
            );
            Ok(content_sha)
        })
    }

    /// Remove a certificate by content hash.
    pub fn remove_certificate(&self, fleet: &str, content_sha: &str) -> Result<()> {
        self.with_mut(|db| {
            fleet_rec_mut(db, fleet)?
                .certificates
                .remove(content_sha)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(format!("cert {fleet}/{content_sha}")))
        })
    }

    /// Decrypt and return a certificate's `(cert_pem, key_pem)`.
    pub fn open_certificate(&self, fleet: &str, content_sha: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let (sc, sk) = self.with(|db| {
            let rec = fleet_rec(db, fleet)?
                .certificates
                .get(content_sha)
                .ok_or_else(|| StoreError::NotFound(format!("cert {fleet}/{content_sha}")))?;
            Ok((rec.sealed_cert.clone(), rec.sealed_key.clone()))
        })?;
        Ok((self.sealer.open(&sc)?, self.sealer.open(&sk)?))
    }

    // ───────────────────────── pools + backends ─────────────────────────

    /// Add or replace a pool (preserving nothing; backends come via the pool).
    pub fn put_pool(&self, fleet: &str, pool: PoolSpec) -> Result<()> {
        self.with_mut(|db| {
            fleet_rec_mut(db, fleet)?
                .pools
                .insert(pool.name.clone(), pool);
            Ok(())
        })
    }

    /// Remove a pool by name.
    pub fn remove_pool(&self, fleet: &str, name: &str) -> Result<()> {
        self.with_mut(|db| {
            fleet_rec_mut(db, fleet)?
                .pools
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(format!("pool {fleet}/{name}")))
        })
    }

    /// Add or update a backend in a pool (idempotent on host:port).
    pub fn put_backend(&self, fleet: &str, pool: &str, backend: Backend) -> Result<()> {
        self.with_mut(|db| {
            let p = fleet_rec_mut(db, fleet)?
                .pools
                .get_mut(pool)
                .ok_or_else(|| StoreError::NotFound(format!("pool {fleet}/{pool}")))?;
            match p
                .backends
                .iter_mut()
                .find(|b| b.host == backend.host && b.port == backend.port)
            {
                Some(existing) => *existing = backend,
                None => p.backends.push(backend),
            }
            Ok(())
        })
    }

    /// Remove a backend from a pool by host:port. Returns `Ok(false)` if absent.
    pub fn remove_backend(&self, fleet: &str, pool: &str, host: &str, port: u16) -> Result<bool> {
        self.with_mut(|db| {
            let p = fleet_rec_mut(db, fleet)?
                .pools
                .get_mut(pool)
                .ok_or_else(|| StoreError::NotFound(format!("pool {fleet}/{pool}")))?;
            let before = p.backends.len();
            p.backends.retain(|b| !(b.host == host && b.port == port));
            Ok(p.backends.len() != before)
        })
    }

    // ───────────────────────── routes ─────────────────────────

    /// Add or replace a route.
    pub fn put_route(&self, fleet: &str, route: RouteSpec) -> Result<()> {
        self.with_mut(|db| {
            fleet_rec_mut(db, fleet)?
                .routes
                .insert(route.name.clone(), route);
            Ok(())
        })
    }

    /// Remove a route by name.
    pub fn remove_route(&self, fleet: &str, name: &str) -> Result<()> {
        self.with_mut(|db| {
            fleet_rec_mut(db, fleet)?
                .routes
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(format!("route {fleet}/{name}")))
        })
    }

    // ───────────────────────── aggregate ─────────────────────────

    /// Assemble the full desired state for a fleet (renderer input). Certificate
    /// metadata only — PEM material stays sealed until distribution.
    pub fn fleet_state(&self, fleet: &str) -> Result<FleetState> {
        self.with(|db| {
            let rec = fleet_rec(db, fleet)?;
            Ok(FleetState {
                fleet: rec.fleet.clone(),
                listeners: rec.listeners.values().cloned().collect(),
                certificates: rec.certificates.values().map(|c| c.meta.clone()).collect(),
                pools: rec.pools.values().cloned().collect(),
                routes: rec.routes.values().cloned().collect(),
            })
        })
    }

    // ───────────────────────── revisions ─────────────────────────

    /// Persist a revision, assigning the next per-fleet sequence. If the latest
    /// revision has the same `content_hash`, no new revision is created and the
    /// existing one is returned (renders are deduplicated).
    pub fn create_revision(
        &self,
        fleet: &str,
        dynamic_json: String,
        cert_set: Vec<gfe_cp_types::CertRef>,
        static_template: String,
        content_hash: String,
        created_by: String,
    ) -> Result<Revision> {
        self.with_mut(|db| {
            let rec = fleet_rec_mut(db, fleet)?;
            if let Some((_, latest)) = rec.revisions.iter().next_back() {
                if latest.content_hash == content_hash {
                    return Ok(latest.clone());
                }
            }
            let seq = rec.next_seq;
            rec.next_seq += 1;
            let rev = Revision {
                fleet: fleet.to_string(),
                seq,
                dynamic_json,
                cert_set,
                static_template,
                content_hash,
                created_by,
                created_at: now(),
            };
            rec.revisions.insert(seq, rev.clone());
            Ok(rev)
        })
    }

    /// Get a revision by sequence.
    pub fn get_revision(&self, fleet: &str, seq: i64) -> Result<Revision> {
        self.with(|db| {
            fleet_rec(db, fleet)?
                .revisions
                .get(&seq)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(format!("revision {fleet}#{seq}")))
        })
    }

    /// List a fleet's revisions, ascending by sequence.
    pub fn list_revisions(&self, fleet: &str) -> Result<Vec<Revision>> {
        self.with(|db| Ok(fleet_rec(db, fleet)?.revisions.values().cloned().collect()))
    }

    /// The highest-sequence revision, if any.
    pub fn latest_revision(&self, fleet: &str) -> Result<Option<Revision>> {
        self.with(|db| {
            Ok(fleet_rec(db, fleet)?
                .revisions
                .values()
                .next_back()
                .cloned())
        })
    }

    /// Set the rollout target to an existing revision sequence and (re)start a
    /// staged rollout toward it, admitting the fleet's canary set first.
    pub fn set_target(&self, fleet: &str, seq: i64) -> Result<()> {
        self.with_mut(|db| {
            let rec = fleet_rec_mut(db, fleet)?;
            if !rec.revisions.contains_key(&seq) {
                return Err(StoreError::NotFound(format!("revision {fleet}#{seq}")));
            }
            rec.target_seq = Some(seq);
            let canary = rec.fleet.rollout_policy.canary_size;
            rec.rollout = Some(RolloutState::new(seq, canary, now()));
            Ok(())
        })
    }

    /// The current rollout-target sequence, if a target has been published.
    pub fn target_seq(&self, fleet: &str) -> Result<Option<i64>> {
        self.with(|db| Ok(fleet_rec(db, fleet)?.target_seq))
    }

    /// The current rollout state, if a target has been published.
    pub fn rollout(&self, fleet: &str) -> Result<Option<RolloutState>> {
        self.with(|db| Ok(fleet_rec(db, fleet)?.rollout.clone()))
    }

    /// Replace the rollout state (used by the reconciler).
    pub fn set_rollout(&self, fleet: &str, state: RolloutState) -> Result<()> {
        self.with_mut(|db| {
            fleet_rec_mut(db, fleet)?.rollout = Some(state);
            Ok(())
        })
    }
}

fn fleet_rec<'a>(db: &'a Db, name: &str) -> Result<&'a FleetRecord> {
    db.fleets
        .get(name)
        .ok_or_else(|| StoreError::NotFound(format!("fleet {name}")))
}

fn fleet_rec_mut<'a>(db: &'a mut Db, name: &str) -> Result<&'a mut FleetRecord> {
    db.fleets
        .get_mut(name)
        .ok_or_else(|| StoreError::NotFound(format!("fleet {name}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AeadSealer;

    fn store() -> Store {
        let sealer = Arc::new(AeadSealer::new(&[3u8; 32]).unwrap());
        Store::in_memory(sealer)
    }

    fn fleet() -> Fleet {
        Fleet::new("atlas-prod", "188.184.100.10".parse().unwrap())
    }

    #[test]
    fn create_and_get_fleet() {
        let s = store();
        s.create_fleet(fleet()).unwrap();
        assert_eq!(s.get_fleet("atlas-prod").unwrap().name, "atlas-prod");
        assert!(s.create_fleet(fleet()).is_err()); // duplicate
    }

    #[test]
    fn certificate_dedup_and_open() {
        let s = store();
        s.create_fleet(fleet()).unwrap();
        let sha1 = s
            .add_certificate(
                "atlas-prod",
                vec!["a.example.org".into()],
                false,
                0,
                b"CERT",
                b"KEY",
            )
            .unwrap();
        let sha2 = s
            .add_certificate(
                "atlas-prod",
                vec!["a.example.org".into()],
                false,
                0,
                b"CERT",
                b"KEY",
            )
            .unwrap();
        assert_eq!(sha1, sha2); // content-addressed dedup
        let (cert, key) = s.open_certificate("atlas-prod", &sha1).unwrap();
        assert_eq!(cert, b"CERT");
        assert_eq!(key, b"KEY");
    }

    #[test]
    fn at_most_one_default_cert() {
        let s = store();
        s.create_fleet(fleet()).unwrap();
        s.add_certificate("atlas-prod", vec![], true, 0, b"C1", b"K1")
            .unwrap();
        let err = s.add_certificate("atlas-prod", vec![], true, 0, b"C2", b"K2");
        assert!(err.is_err());
    }

    #[test]
    fn backends_are_idempotent_on_authority() {
        let s = store();
        s.create_fleet(fleet()).unwrap();
        s.put_pool(
            "atlas-prod",
            PoolSpec {
                name: "web".into(),
                scheme: Default::default(),
                lb_policy: Default::default(),
                health_check: None,
                backends: vec![],
            },
        )
        .unwrap();
        let b = Backend {
            host: "10.0.0.1".into(),
            port: 8443,
            weight: 1,
            enabled: true,
        };
        s.put_backend("atlas-prod", "web", b.clone()).unwrap();
        s.put_backend(
            "atlas-prod",
            "web",
            Backend {
                weight: 5,
                ..b.clone()
            },
        )
        .unwrap();
        let pools = s.fleet_state("atlas-prod").unwrap().pools;
        assert_eq!(pools[0].backends.len(), 1);
        assert_eq!(pools[0].backends[0].weight, 5);
        assert!(s
            .remove_backend("atlas-prod", "web", "10.0.0.1", 8443)
            .unwrap());
        assert!(!s
            .remove_backend("atlas-prod", "web", "10.0.0.1", 8443)
            .unwrap());
    }

    #[test]
    fn revisions_get_monotonic_seq_and_dedup() {
        let s = store();
        s.create_fleet(fleet()).unwrap();
        let r1 = s
            .create_revision(
                "atlas-prod",
                "{}".into(),
                vec![],
                "".into(),
                "h1".into(),
                "me".into(),
            )
            .unwrap();
        assert_eq!(r1.seq, 1);
        // Same content hash ⇒ same revision, no new seq.
        let r1b = s
            .create_revision(
                "atlas-prod",
                "{}".into(),
                vec![],
                "".into(),
                "h1".into(),
                "me".into(),
            )
            .unwrap();
        assert_eq!(r1b.seq, 1);
        let r2 = s
            .create_revision(
                "atlas-prod",
                "{}".into(),
                vec![],
                "".into(),
                "h2".into(),
                "me".into(),
            )
            .unwrap();
        assert_eq!(r2.seq, 2);
        s.set_target("atlas-prod", 2).unwrap();
        assert_eq!(s.target_seq("atlas-prod").unwrap(), Some(2));
        assert!(s.set_target("atlas-prod", 99).is_err());
    }

    #[test]
    fn node_status_round_trips() {
        let s = store();
        s.create_fleet(fleet()).unwrap();
        s.put_node(Node::new(
            "atlas-prod",
            "gfe-node-01",
            "10.0.0.1".parse().unwrap(),
        ))
        .unwrap();
        s.report_node_status("atlas-prod", "gfe-node-01", 3, ReloadState::Ok, true)
            .unwrap();
        let n = s.get_node("atlas-prod", "gfe-node-01").unwrap();
        assert_eq!(n.applied_seq, Some(3));
        assert_eq!(n.reload_state, ReloadState::Ok);
        assert!(n.healthy);
    }

    #[test]
    fn file_backed_persists_and_reloads() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("gfe-cp-store-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sealer = Arc::new(AeadSealer::new(&[5u8; 32]).unwrap());
        {
            let s = Store::open(path.clone(), sealer.clone()).unwrap();
            s.create_fleet(fleet()).unwrap();
            s.add_certificate("atlas-prod", vec![], true, 0, b"CERT", b"KEY")
                .unwrap();
        }
        // Reopen with the same master key: data survives and decrypts.
        let s2 = Store::open(path.clone(), sealer).unwrap();
        let certs = s2.fleet_state("atlas-prod").unwrap().certificates;
        assert_eq!(certs.len(), 1);
        let (cert, _) = s2
            .open_certificate("atlas-prod", &certs[0].content_sha)
            .unwrap();
        assert_eq!(cert, b"CERT");
        let _ = std::fs::remove_file(&path);
    }
}
