//! The render engine (spec §4): a pure function from a fleet's desired state to
//! the node-facing files — the shared dynamic JSON and the bootstrap TOML.
//!
//! Rendering depends on the real `gfe-types` structs the node deserializes, so
//! `serde(deny_unknown_fields)` on the node side guarantees no stray keys slip
//! through. Ordering is deterministic (everything sorted by its stable name or
//! authority) so identical desired state always renders byte-identical output —
//! stable content hashes and clean diffs.

use crate::crypto::sha256_hex;
use gfe_cp_types::{CertRef, FleetState, RouteActionSpec};
use gfe_types::{
    CertEntry, DynamicConfig, FixedAction, HealthCheckConfig, Listener, ListenerId, MinVersion,
    RedirectAction, Route, RouteAction, RouteId, Upstream, UpstreamPool,
};
use serde::Serialize;
use thiserror::Error;

/// On-node convention paths (controller-owned, never user-supplied). Cert
/// paths themselves are produced by `Certificate::cert_path` / `key_path`.
const CONFIG_FILE: &str = "/etc/gfe/gfe-dynamic.json";
const LOCAL_CACHE: &str = "/var/lib/gfe/config-cache.json";
const RELOAD_DEBOUNCE: &str = "250ms";

/// Errors from rendering.
#[derive(Debug, Error)]
pub enum RenderError {
    #[error("serializing dynamic config: {0}")]
    Json(String),
    #[error("serializing static config: {0}")]
    Toml(String),
}

/// The rendered output for a fleet revision.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The compiled dynamic config (for in-process validation / assertions).
    pub dynamic: DynamicConfig,
    /// The exact JSON bytes shipped to nodes.
    pub dynamic_json: String,
    /// The fleet portion of the bootstrap TOML (per-node `[node]` injected later).
    pub static_template: String,
    /// Certs referenced by this render (on-node path + content hash).
    pub cert_refs: Vec<CertRef>,
    /// Stable hash over the rendered output; the rollout-target id.
    pub content_hash: String,
}

/// Render a fleet's desired state into its node-facing files.
pub fn render(state: &FleetState) -> Result<Rendered, RenderError> {
    let dynamic = render_dynamic(state);
    let dynamic_json =
        serde_json::to_string_pretty(&dynamic).map_err(|e| RenderError::Json(e.to_string()))?;
    let static_template = render_static_template(state)?;

    let mut cert_refs: Vec<CertRef> = state
        .certificates
        .iter()
        .map(|c| CertRef {
            path: c.cert_path(),
            key_path: c.key_path(),
            content_sha: c.content_sha.clone(),
        })
        .collect();
    cert_refs.sort_by(|a, b| a.content_sha.cmp(&b.content_sha));

    // Hash over everything a node would observe. The dynamic JSON already
    // embeds cert paths (content hashes), so cert changes flow into the hash.
    let mut hash_input = String::new();
    hash_input.push_str(&dynamic_json);
    hash_input.push('\n');
    hash_input.push_str(&static_template);
    let content_hash = sha256_hex(hash_input.as_bytes());

    Ok(Rendered {
        dynamic,
        dynamic_json,
        static_template,
        cert_refs,
        content_hash,
    })
}

/// Build the `DynamicConfig` (spec §4.1). Deterministic ordering throughout.
pub fn render_dynamic(state: &FleetState) -> DynamicConfig {
    // Certificates: sorted by content hash; SNI lists sorted.
    let mut certificates: Vec<CertEntry> = state
        .certificates
        .iter()
        .map(|c| {
            let mut sni = c.sni.clone();
            sni.sort();
            CertEntry {
                sni,
                default: c.is_default,
                cert_file: c.cert_path().into(),
                key_file: c.key_path().into(),
            }
        })
        .collect();
    certificates.sort_by(|a, b| a.cert_file.cmp(&b.cert_file));

    // Listeners: sorted by name.
    let mut listeners: Vec<Listener> = state
        .listeners
        .iter()
        .map(|l| Listener {
            id: ListenerId(l.name.clone()),
            address: l.address,
            port: l.port,
            protocol: l.protocol,
        })
        .collect();
    listeners.sort_by(|a, b| a.id.0.cmp(&b.id.0));

    // Routes: sorted by name.
    let mut routes: Vec<Route> = state
        .routes
        .iter()
        .map(|r| Route {
            id: RouteId(r.name.clone()),
            listener: ListenerId(r.listener.clone()),
            host: r.host.clone(),
            path_prefix: r.path_prefix.clone(),
            action: map_action(&r.action),
        })
        .collect();
    routes.sort_by(|a, b| a.id.0.cmp(&b.id.0));

    // Pools: sorted by name; only enabled backends, sorted by authority.
    let mut pools: Vec<UpstreamPool> = state
        .pools
        .iter()
        .map(|p| {
            let mut upstreams: Vec<Upstream> = p
                .backends
                .iter()
                .filter(|b| b.enabled)
                .map(|b| Upstream {
                    host: b.host.clone(),
                    port: b.port,
                    weight: b.weight,
                })
                .collect();
            upstreams.sort_by_key(|u| u.authority());
            UpstreamPool {
                id: gfe_types::PoolId(p.name.clone()),
                scheme: p.scheme,
                lb_policy: p.lb_policy,
                upstreams,
                health_check: p.health_check.clone(),
            }
        })
        .collect();
    pools.sort_by(|a, b| a.id.0.cmp(&b.id.0));

    DynamicConfig {
        certificates,
        listeners,
        routes,
        pools,
    }
}

fn map_action(a: &RouteActionSpec) -> RouteAction {
    match a {
        RouteActionSpec::Forward(pool) => RouteAction::Forward(pool.clone()),
        RouteActionSpec::Redirect(r) => RouteAction::Redirect(RedirectAction {
            scheme: r.scheme.clone(),
            status: r.status,
        }),
        RouteActionSpec::Fixed(f) => RouteAction::Fixed(FixedAction {
            status: f.status,
            body: f.body.clone(),
        }),
    }
}

// ───────────────────────── static TOML ─────────────────────────

/// Render the fleet portion of the bootstrap TOML (spec §4.2). The per-node
/// `[node]` section is injected by [`render_node_toml`] when serving a node.
pub fn render_static_template(state: &FleetState) -> Result<String, RenderError> {
    let f = &state.fleet;
    let frag = StaticFragment {
        control_plane: ControlPlaneToml {
            config_file: CONFIG_FILE.into(),
            local_cache: LOCAL_CACHE.into(),
            reload_debounce: RELOAD_DEBOUNCE.into(),
        },
        tls: TlsToml {
            min_version: f.tls_min_version,
            hsts: f.hsts.clone(),
        },
        limits: LimitsToml::from(&f.limits),
        timeouts: TimeoutsToml::from(&f.timeouts),
        upstream: UpstreamToml::from(&f.upstream),
        health_check_defaults: f.health_defaults.clone(),
    };
    toml::to_string(&frag).map_err(|e| RenderError::Toml(e.to_string()))
}

/// Render the full bootstrap TOML for one node: its `[node]` identity section
/// prepended to the fleet template.
pub fn render_node_toml(
    node: &gfe_cp_types::Node,
    fleet_vip: std::net::IpAddr,
    template: &str,
) -> String {
    let mut out = String::new();
    out.push_str("[node]\n");
    out.push_str(&format!("id = \"{}\"\n", node.gfe_node_id));
    out.push_str(&format!("loopback_vip = \"{fleet_vip}\"\n"));
    out.push_str(&format!("metrics_addr = \"{}\"\n", node.metrics_addr));
    out.push_str(&format!("worker_threads = {}\n", node.worker_threads));
    out.push('\n');
    out.push_str(template);
    out
}

#[derive(Serialize)]
struct StaticFragment {
    control_plane: ControlPlaneToml,
    tls: TlsToml,
    limits: LimitsToml,
    timeouts: TimeoutsToml,
    upstream: UpstreamToml,
    health_check_defaults: HealthCheckConfig,
}

#[derive(Serialize)]
struct ControlPlaneToml {
    config_file: String,
    local_cache: String,
    reload_debounce: String,
}

#[derive(Serialize)]
struct TlsToml {
    #[serde(rename = "min_version")]
    min_version: MinVersion,
    hsts: String,
}

#[derive(Serialize)]
struct LimitsToml {
    max_connections: usize,
    max_connections_listener: usize,
    max_header_bytes: usize,
    max_h2_concurrent_streams: u32,
    max_upstream_connections: usize,
}

impl From<&gfe_cp_types::LimitsSpec> for LimitsToml {
    fn from(l: &gfe_cp_types::LimitsSpec) -> Self {
        LimitsToml {
            max_connections: l.max_connections,
            max_connections_listener: l.max_connections_listener,
            max_header_bytes: l.max_header_bytes,
            max_h2_concurrent_streams: l.max_h2_concurrent_streams,
            max_upstream_connections: l.max_upstream_connections,
        }
    }
}

#[derive(Serialize)]
struct TimeoutsToml {
    tls_handshake: String,
    request_header: String,
    upstream_connect: String,
    upstream_first_byte: String,
    request_total: String,
    client_idle: String,
    drain_deadline: String,
}

impl From<&gfe_cp_types::TimeoutsSpec> for TimeoutsToml {
    fn from(t: &gfe_cp_types::TimeoutsSpec) -> Self {
        TimeoutsToml {
            tls_handshake: secs(t.tls_handshake),
            request_header: secs(t.request_header),
            upstream_connect: secs(t.upstream_connect),
            upstream_first_byte: secs(t.upstream_first_byte),
            request_total: secs(t.request_total),
            client_idle: secs(t.client_idle),
            drain_deadline: secs(t.drain_deadline),
        }
    }
}

#[derive(Serialize)]
struct UpstreamToml {
    #[serde(skip_serializing_if = "Option::is_none")]
    idle_per_host: Option<usize>,
}

impl From<&gfe_cp_types::UpstreamSpec> for UpstreamToml {
    fn from(u: &gfe_cp_types::UpstreamSpec) -> Self {
        UpstreamToml {
            idle_per_host: u.idle_per_host,
        }
    }
}

/// Format a duration in the node's friendly form (whole seconds / millis).
fn secs(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{ms}ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gfe_cp_types::{
        Backend, Certificate, Fleet, ListenerSpec, PoolSpec, RedirectSpec, RouteSpec,
    };
    use gfe_types::{ListenProtocol, NodeConfig, Scheme};

    fn state() -> FleetState {
        let mut s = FleetState::new(Fleet::new("atlas-prod", "188.184.100.10".parse().unwrap()));
        s.listeners.push(ListenerSpec {
            name: "https".into(),
            address: "188.184.100.10".parse().unwrap(),
            port: 443,
            protocol: ListenProtocol::Https,
        });
        s.listeners.push(ListenerSpec {
            name: "http".into(),
            address: "188.184.100.10".parse().unwrap(),
            port: 80,
            protocol: ListenProtocol::Http,
        });
        s.certificates.push(Certificate {
            content_sha: "abc123".into(),
            sni: vec!["atlas.example.org".into(), "*.atlas.example.org".into()],
            is_default: true,
            not_after: 0,
            created_at: 0,
        });
        s.pools.push(PoolSpec {
            name: "web".into(),
            scheme: Scheme::Https,
            lb_policy: Default::default(),
            health_check: None,
            backends: vec![
                Backend {
                    host: "10.0.0.2".into(),
                    port: 8443,
                    weight: 1,
                    enabled: true,
                },
                Backend {
                    host: "10.0.0.1".into(),
                    port: 8443,
                    weight: 1,
                    enabled: true,
                },
                Backend {
                    host: "10.0.0.9".into(),
                    port: 8443,
                    weight: 1,
                    enabled: false, // disabled: omitted
                },
            ],
        });
        s.routes.push(RouteSpec {
            name: "atlas-web".into(),
            listener: "https".into(),
            host: "atlas.example.org".into(),
            path_prefix: "/".into(),
            action: RouteActionSpec::Forward("web".into()),
        });
        s.routes.push(RouteSpec {
            name: "atlas-redirect".into(),
            listener: "http".into(),
            host: "*".into(),
            path_prefix: "/".into(),
            action: RouteActionSpec::Redirect(RedirectSpec {
                scheme: "https".into(),
                status: 308,
            }),
        });
        s
    }

    #[test]
    fn dynamic_uses_content_addressed_cert_paths() {
        let r = render(&state()).unwrap();
        let c = &r.dynamic.certificates[0];
        assert_eq!(
            c.cert_file.to_str().unwrap(),
            "/etc/gfe/certs/abc123.crt.pem"
        );
        // SNI list rendered sorted.
        assert_eq!(c.sni, vec!["*.atlas.example.org", "atlas.example.org"]);
    }

    #[test]
    fn disabled_backends_are_omitted_and_sorted() {
        let r = render(&state()).unwrap();
        let pool = &r.dynamic.pools[0];
        assert_eq!(pool.upstreams.len(), 2);
        assert_eq!(pool.upstreams[0].authority(), "10.0.0.1:8443");
        assert_eq!(pool.upstreams[1].authority(), "10.0.0.2:8443");
    }

    #[test]
    fn render_is_deterministic() {
        let a = render(&state()).unwrap();
        let b = render(&state()).unwrap();
        assert_eq!(a.dynamic_json, b.dynamic_json);
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn dynamic_json_reparses_and_validates() {
        let r = render(&state()).unwrap();
        let parsed: DynamicConfig = serde_json::from_str(&r.dynamic_json).unwrap();
        assert_eq!(parsed.listeners.len(), 2);
        gfe_config::validate(&parsed).unwrap();
    }

    #[test]
    fn node_toml_parses_as_node_config() {
        let r = render(&state()).unwrap();
        let node =
            gfe_cp_types::Node::new("atlas-prod", "gfe-node-07", "10.0.0.1".parse().unwrap());
        let toml_str =
            render_node_toml(&node, "188.184.100.10".parse().unwrap(), &r.static_template);
        let cfg: NodeConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.node.id, "gfe-node-07");
        assert_eq!(cfg.node.loopback_vip.to_string(), "188.184.100.10");
        assert_eq!(cfg.control_plane.config_file.to_str().unwrap(), CONFIG_FILE);
        assert_eq!(
            cfg.timeouts.upstream_connect,
            std::time::Duration::from_secs(3)
        );
    }
}
