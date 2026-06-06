//! Publishing: render the fleet, validate it, persist an immutable revision,
//! and make it the rollout target (spec §8.1). In the MVP this is "all at
//! once" — the target is set and every node converges; Phase 2 layers staged
//! rollout on top by gating which nodes may advance.

use crate::render::{render, RenderError};
use crate::store::{Store, StoreError};
use crate::validate::{validate, Report, ValidateError};
use gfe_cp_types::Revision;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors from preparing or publishing a revision.
#[derive(Debug, Error)]
pub enum PublishError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Render(#[from] RenderError),
    #[error(transparent)]
    Validate(#[from] ValidateError),
}

/// The result of preparing a revision: the (possibly pre-existing, when the
/// render was unchanged) revision plus any non-blocking validation warnings.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub revision: Revision,
    pub report: Report,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Render + validate the fleet's current desired state and persist it as a
/// revision (deduplicated: an unchanged render returns the existing revision).
/// Does **not** change the rollout target.
pub fn prepare(store: &Store, fleet: &str, created_by: &str) -> Result<Prepared, PublishError> {
    let state = store.fleet_state(fleet)?;
    let rendered = render(&state)?;
    let report = validate(&state, &rendered.dynamic, now())?;
    let revision = store.create_revision(
        fleet,
        rendered.dynamic_json,
        rendered.cert_refs,
        rendered.static_template,
        rendered.content_hash,
        created_by.to_string(),
    )?;
    Ok(Prepared { revision, report })
}

/// Prepare a revision and publish it as the fleet's rollout target.
pub fn publish(store: &Store, fleet: &str, created_by: &str) -> Result<Prepared, PublishError> {
    let prepared = prepare(store, fleet, created_by)?;
    store.set_target(fleet, prepared.revision.seq)?;
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AeadSealer;
    use gfe_cp_types::{Backend, Fleet, ListenerSpec, PoolSpec, RouteActionSpec, RouteSpec};
    use gfe_types::{ListenProtocol, Scheme};
    use std::sync::Arc;

    fn store() -> Store {
        Store::in_memory(Arc::new(AeadSealer::new(&[1u8; 32]).unwrap()))
    }

    fn seed(s: &Store) {
        s.create_fleet(Fleet::new("f", "10.0.0.1".parse().unwrap()))
            .unwrap();
        s.put_listener(
            "f",
            ListenerSpec {
                name: "http".into(),
                address: "10.0.0.1".parse().unwrap(),
                port: 80,
                protocol: ListenProtocol::Http,
            },
        )
        .unwrap();
        s.put_pool(
            "f",
            PoolSpec {
                name: "web".into(),
                scheme: Scheme::Http,
                lb_policy: Default::default(),
                health_check: None,
                backends: vec![Backend {
                    host: "10.0.0.2".into(),
                    port: 8080,
                    weight: 1,
                    enabled: true,
                }],
            },
        )
        .unwrap();
        s.put_route(
            "f",
            RouteSpec {
                name: "r".into(),
                listener: "http".into(),
                host: "a.example.org".into(),
                path_prefix: "/".into(),
                action: RouteActionSpec::Forward("web".into()),
            },
        )
        .unwrap();
    }

    #[test]
    fn publish_sets_target_to_new_revision() {
        let s = store();
        seed(&s);
        let p = publish(&s, "f", "alice").unwrap();
        assert_eq!(p.revision.seq, 1);
        assert_eq!(s.target_seq("f").unwrap(), Some(1));
    }

    #[test]
    fn republish_without_change_is_idempotent() {
        let s = store();
        seed(&s);
        let a = publish(&s, "f", "alice").unwrap();
        let b = publish(&s, "f", "alice").unwrap();
        assert_eq!(a.revision.seq, b.revision.seq);
        assert_eq!(s.list_revisions("f").unwrap().len(), 1);
    }

    #[test]
    fn change_then_publish_makes_new_revision() {
        let s = store();
        seed(&s);
        publish(&s, "f", "alice").unwrap();
        s.put_backend(
            "f",
            "web",
            Backend {
                host: "10.0.0.3".into(),
                port: 8080,
                weight: 1,
                enabled: true,
            },
        )
        .unwrap();
        let b = publish(&s, "f", "alice").unwrap();
        assert_eq!(b.revision.seq, 2);
        assert_eq!(s.target_seq("f").unwrap(), Some(2));
    }

    #[test]
    fn invalid_state_blocks_publish() {
        let s = store();
        seed(&s);
        // Point the route at a non-existent pool → node-layer validation fails.
        s.put_route(
            "f",
            RouteSpec {
                name: "r".into(),
                listener: "http".into(),
                host: "a.example.org".into(),
                path_prefix: "/".into(),
                action: RouteActionSpec::Forward("ghost".into()),
            },
        )
        .unwrap();
        assert!(matches!(
            publish(&s, "f", "alice"),
            Err(PublishError::Validate(ValidateError::Node(_)))
        ));
        // No revision created, no target set.
        assert!(s.list_revisions("f").unwrap().is_empty());
        assert_eq!(s.target_seq("f").unwrap(), None);
    }
}
