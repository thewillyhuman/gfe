//! The control-plane HTTP API (spec §9): a JSON operator surface under `/v1`
//! and the pull-agent surface under `/agent`.
//!
//! The spec specifies gRPC with a REST gateway; this implementation serves
//! HTTP/JSON directly with hyper (already the workspace's HTTP stack), which
//! keeps the build free of a protobuf toolchain while exposing the same
//! operations. mTLS / OAuth2-SSO (spec §10) reduce to an optional bearer token
//! here; the [`Auth`] seam is where per-node mTLS identity and SSO group RBAC
//! would attach.

use crate::publish::{publish, PublishError};
use crate::render::render_node_toml;
use crate::rollout;
use crate::store::{Store, StoreError};
use bytes::Bytes;
use gfe_cp_types::{
    Backend, Fleet, GetTargetRequest, GetTargetResponse, ListenerSpec, Node, PoolSpec,
    ReportStatusRequest, ReportStatusResponse, RouteSpec, TargetCert, TargetRevision,
};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Shared server state.
pub struct ApiState {
    pub store: Store,
    pub auth: Auth,
}

/// Optional bearer-token authentication. `None` token disables auth (dev/test).
#[derive(Default)]
pub struct Auth {
    pub token: Option<String>,
}

impl Auth {
    /// Whether a request bearing `header` is authorized.
    fn check(&self, header: Option<&str>) -> bool {
        match &self.token {
            None => true,
            Some(t) => header
                .and_then(|h| h.strip_prefix("Bearer "))
                .map(|got| got == t)
                .unwrap_or(false),
        }
    }
}

/// Run the API server on `addr` until the process exits.
pub async fn serve(addr: SocketAddr, state: Arc<ApiState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_on(listener, state).await
}

/// Run the API server on an already-bound listener (lets callers choose an
/// ephemeral port and learn it before serving — used in tests).
pub async fn serve_on(listener: TcpListener, state: Arc<ApiState>) -> std::io::Result<()> {
    tracing::info!(addr = ?listener.local_addr().ok(), "gfe-cp API listening (/v1 operator, /agent pull)");
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept error");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(state, req).await) }
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

/// Top-level request dispatcher. Never fails (errors become HTTP responses).
pub async fn handle(state: Arc<ApiState>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Unauthenticated liveness probe.
    if path == "/healthz" {
        return text(StatusCode::OK, "ok");
    }
    if !state.auth.check(auth_header.as_deref()) {
        return text(StatusCode::UNAUTHORIZED, "unauthorized");
    }

    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return text(StatusCode::BAD_REQUEST, "failed to read body"),
    };

    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segs.first().copied() {
        Some("v1") => operator(&state.store, &method, &segs[1..], &body),
        Some("agent") => agent(&state.store, &method, &segs[1..], &body),
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

// ───────────────────────── operator API (/v1) ─────────────────────────

fn operator(store: &Store, method: &Method, segs: &[&str], body: &[u8]) -> Response<Full<Bytes>> {
    use Method as M;
    match (method, segs) {
        (&M::POST, ["fleets"]) => match parse::<Fleet>(body) {
            Ok(f) => result(store.create_fleet(f)),
            Err(r) => r,
        },
        (&M::GET, ["fleets"]) => json(StatusCode::OK, &store.list_fleets()),
        (&M::GET, ["fleets", f]) => result(store.get_fleet(f)),
        (&M::PUT, ["fleets", f]) => match parse::<Fleet>(body) {
            Ok(mut fl) => {
                fl.name = (*f).to_string();
                result(store.update_fleet(fl).map(|_| ()))
            }
            Err(r) => r,
        },
        (&M::DELETE, ["fleets", f]) => result(store.delete_fleet(f)),

        (&M::POST, ["fleets", f, "nodes"]) => match parse::<Node>(body) {
            Ok(mut n) => {
                n.fleet = (*f).to_string();
                result(store.put_node(n))
            }
            Err(r) => r,
        },
        (&M::GET, ["fleets", f, "nodes"]) => result(store.list_nodes(f)),
        (&M::DELETE, ["fleets", f, "nodes", id]) => result(store.remove_node(f, id)),

        (&M::POST, ["fleets", f, "listeners"]) => match parse::<ListenerSpec>(body) {
            Ok(l) => result(store.put_listener(f, l)),
            Err(r) => r,
        },
        (&M::DELETE, ["fleets", f, "listeners", n]) => result(store.remove_listener(f, n)),

        (&M::POST, ["fleets", f, "certificates"]) => add_cert(store, f, body),
        (&M::GET, ["fleets", f, "certificates"]) => {
            result(store.fleet_state(f).map(|s| s.certificates))
        }
        (&M::DELETE, ["fleets", f, "certificates", sha]) => {
            result(store.remove_certificate(f, sha))
        }

        (&M::POST, ["fleets", f, "pools"]) => match parse::<PoolSpec>(body) {
            Ok(p) => result(store.put_pool(f, p)),
            Err(r) => r,
        },
        (&M::DELETE, ["fleets", f, "pools", n]) => result(store.remove_pool(f, n)),
        (&M::POST, ["fleets", f, "pools", p, "backends"]) => match parse::<Backend>(body) {
            Ok(b) => result(store.put_backend(f, p, b)),
            Err(r) => r,
        },
        (&M::DELETE, ["fleets", f, "pools", p, "backends", host, port]) => match port.parse() {
            Ok(port) => result(store.remove_backend(f, p, host, port)),
            Err(_) => text(StatusCode::BAD_REQUEST, "invalid port"),
        },

        (&M::POST, ["fleets", f, "routes"]) => match parse::<RouteSpec>(body) {
            Ok(rt) => result(store.put_route(f, rt)),
            Err(r) => r,
        },
        (&M::DELETE, ["fleets", f, "routes", n]) => result(store.remove_route(f, n)),

        (&M::POST, ["fleets", f, "publish"]) => do_publish(store, f),
        (&M::POST, ["fleets", f, "rollback"]) => do_rollback(store, f, body),
        (&M::GET, ["fleets", f, "diff"]) => do_diff(store, f),
        (&M::GET, ["fleets", f, "status"]) => fleet_status(store, f),
        (&M::GET, ["fleets", f, "revisions"]) => result(store.list_revisions(f)),

        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

/// Request body for adding a certificate (PEM material inline).
#[derive(Deserialize)]
struct AddCertRequest {
    #[serde(default)]
    sni: Vec<String>,
    #[serde(default)]
    is_default: bool,
    #[serde(default)]
    not_after: i64,
    cert_pem: String,
    key_pem: String,
}

/// Response after adding a certificate.
#[derive(Serialize)]
struct AddCertResponse {
    content_sha: String,
}

fn add_cert(store: &Store, fleet: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let req: AddCertRequest = match parse(body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    match store.add_certificate(
        fleet,
        req.sni,
        req.is_default,
        req.not_after,
        req.cert_pem.as_bytes(),
        req.key_pem.as_bytes(),
    ) {
        Ok(content_sha) => json(StatusCode::OK, &AddCertResponse { content_sha }),
        Err(e) => store_error(&e),
    }
}

/// Publish response: the resulting revision sequence and any warnings.
#[derive(Serialize)]
struct PublishResponse {
    seq: i64,
    content_hash: String,
    warnings: Vec<String>,
}

fn do_publish(store: &Store, fleet: &str) -> Response<Full<Bytes>> {
    match publish(store, fleet, "operator") {
        Ok(p) => json(
            StatusCode::OK,
            &PublishResponse {
                seq: p.revision.seq,
                content_hash: p.revision.content_hash,
                warnings: p.report.warnings,
            },
        ),
        Err(PublishError::Validate(e)) => text(StatusCode::BAD_REQUEST, &e.to_string()),
        Err(PublishError::Render(e)) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        Err(PublishError::Store(e)) => store_error(&e),
    }
}

/// Per-node rollout status for a fleet (spec §9 `fleet status`).
#[derive(Serialize)]
struct StatusResponse {
    fleet: String,
    target_seq: Option<i64>,
    rollout: Option<gfe_cp_types::RolloutState>,
    nodes: Vec<Node>,
}

fn fleet_status(store: &Store, fleet: &str) -> Response<Full<Bytes>> {
    // Reconcile so the reported phase reflects the latest observed node state.
    if let Err(e) = rollout::reconcile(store, fleet, now()) {
        return store_error(&e);
    }
    let target_seq = match store.target_seq(fleet) {
        Ok(t) => t,
        Err(e) => return store_error(&e),
    };
    let rollout = match store.rollout(fleet) {
        Ok(r) => r,
        Err(e) => return store_error(&e),
    };
    match store.list_nodes(fleet) {
        Ok(nodes) => json(
            StatusCode::OK,
            &StatusResponse {
                fleet: fleet.to_string(),
                target_seq,
                rollout,
                nodes,
            },
        ),
        Err(e) => store_error(&e),
    }
}

/// Diff response: whether desired differs from target, and the line diff.
#[derive(Serialize)]
struct DiffResponse {
    changed: bool,
    current_seq: Option<i64>,
    diff: String,
}

fn do_diff(store: &Store, fleet: &str) -> Response<Full<Bytes>> {
    match crate::publish::diff(store, fleet) {
        Ok(d) => json(
            StatusCode::OK,
            &DiffResponse {
                changed: d.changed,
                current_seq: d.current_seq,
                diff: d.text,
            },
        ),
        Err(PublishError::Store(e)) => store_error(&e),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

/// Request body for a rollback (spec §8.4).
#[derive(Deserialize)]
struct RollbackRequest {
    to: i64,
}

fn do_rollback(store: &Store, fleet: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let req: RollbackRequest = match parse(body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    // Rollback is just re-targeting an earlier immutable revision (spec §8.4).
    match store.set_target(fleet, req.to) {
        Ok(()) => fleet_status(store, fleet),
        Err(e) => store_error(&e),
    }
}

/// Current unix seconds.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ───────────────────────── agent API (/agent) ─────────────────────────

fn agent(store: &Store, method: &Method, segs: &[&str], body: &[u8]) -> Response<Full<Bytes>> {
    use Method as M;
    match (method, segs) {
        (&M::POST, ["get-target"]) => match parse::<GetTargetRequest>(body) {
            Ok(req) => get_target(store, &req),
            Err(r) => r,
        },
        (&M::POST, ["report-status"]) => match parse::<ReportStatusRequest>(body) {
            Ok(req) => report_status(store, &req),
            Err(r) => r,
        },
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

fn get_target(store: &Store, req: &GetTargetRequest) -> Response<Full<Bytes>> {
    // Which revision is this node allowed to advance to right now?
    let allowed = match rollout::allowed_target(store, &req.fleet, &req.node_id, now()) {
        Ok(a) => a,
        Err(e) => return store_error(&e),
    };
    let Some(seq) = allowed else {
        return json(StatusCode::OK, &GetTargetResponse::UpToDate);
    };
    if req.current_seq == Some(seq) {
        return json(StatusCode::OK, &GetTargetResponse::UpToDate);
    }

    let revision = match store.get_revision(&req.fleet, seq) {
        Ok(r) => r,
        Err(e) => return store_error(&e),
    };
    let fleet = match store.get_fleet(&req.fleet) {
        Ok(f) => f,
        Err(e) => return store_error(&e),
    };
    let node = match store.get_node(&req.fleet, &req.node_id) {
        Ok(n) => n,
        Err(e) => return store_error(&e),
    };

    // Materialize cert blobs for this revision.
    let mut certs = Vec::with_capacity(revision.cert_set.len());
    for cref in &revision.cert_set {
        let (cert_pem, key_pem) = match store.open_certificate(&req.fleet, &cref.content_sha) {
            Ok(p) => p,
            Err(e) => return store_error(&e),
        };
        certs.push(TargetCert {
            path: cref.path.clone(),
            key_path: cref.key_path.clone(),
            content_sha: cref.content_sha.clone(),
            cert_pem: String::from_utf8_lossy(&cert_pem).into_owned(),
            key_pem: String::from_utf8_lossy(&key_pem).into_owned(),
        });
    }

    let static_toml = render_node_toml(&node, fleet.vip, &revision.static_template);
    let target = TargetRevision {
        seq: revision.seq,
        content_hash: revision.content_hash,
        dynamic_json: revision.dynamic_json,
        static_toml,
        certs,
        static_only: false,
    };
    json(StatusCode::OK, &GetTargetResponse::Target(Box::new(target)))
}

fn report_status(store: &Store, req: &ReportStatusRequest) -> Response<Full<Bytes>> {
    match store.report_node_status(
        &req.fleet,
        &req.node_id,
        req.applied_seq,
        req.reload_state,
        req.healthy,
    ) {
        Ok(()) => json(StatusCode::OK, &ReportStatusResponse { ok: true }),
        Err(e) => store_error(&e),
    }
}

// ───────────────────────── response helpers ─────────────────────────

/// Map a `Result<T, StoreError>` to a JSON 200 or an error response.
fn result<T: Serialize>(r: std::result::Result<T, StoreError>) -> Response<Full<Bytes>> {
    match r {
        Ok(v) => json(StatusCode::OK, &v),
        Err(e) => store_error(&e),
    }
}

fn store_error(e: &StoreError) -> Response<Full<Bytes>> {
    let status = match e {
        StoreError::NotFound(_) => StatusCode::NOT_FOUND,
        StoreError::AlreadyExists(_) | StoreError::Conflict(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    text(status, &e.to_string())
}

// The `Err` arm carries a ready-made HTTP response (intentionally large) so
// every call site can early-return it directly; boxing here would only add an
// allocation on the error path.
#[allow(clippy::result_large_err)]
fn parse<T: for<'de> Deserialize<'de>>(
    body: &[u8],
) -> std::result::Result<T, Response<Full<Bytes>>> {
    serde_json::from_slice(body)
        .map_err(|e| text(StatusCode::BAD_REQUEST, &format!("bad body: {e}")))
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(bytes) => {
            let mut r = Response::new(Full::new(Bytes::from(bytes)));
            *r.status_mut() = status;
            r.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            r
        }
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(format!("{body}\n"))));
    *r.status_mut() = status;
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AeadSealer;

    fn state() -> Arc<ApiState> {
        Arc::new(ApiState {
            store: Store::in_memory(Arc::new(AeadSealer::new(&[2u8; 32]).unwrap())),
            auth: Auth::default(),
        })
    }

    // The dispatch functions (`operator`, `agent`) take an already-read body,
    // so unit tests drive them directly rather than constructing a hyper
    // `Incoming` body. End-to-end HTTP is covered by `gfe-agent`'s tests.
    fn body_string(r: Response<Full<Bytes>>) -> String {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let bytes = rt.block_on(async { r.into_body().collect().await.unwrap().to_bytes() });
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn auth_allows_when_no_token() {
        let a = Auth::default();
        assert!(a.check(None));
        assert!(a.check(Some("Bearer whatever")));
    }

    #[test]
    fn auth_requires_matching_bearer() {
        let a = Auth {
            token: Some("s3cret".into()),
        };
        assert!(!a.check(None));
        assert!(!a.check(Some("Bearer nope")));
        assert!(a.check(Some("Bearer s3cret")));
    }

    #[test]
    fn operator_crud_and_publish_flow() {
        let s = state();
        // create fleet
        let r = operator(
            &s.store,
            &Method::POST,
            &["fleets"],
            br#"{"name":"f","vip":"10.0.0.1"}"#,
        );
        assert_eq!(r.status(), StatusCode::OK);
        // add http listener
        let r = operator(
            &s.store,
            &Method::POST,
            &["fleets", "f", "listeners"],
            br#"{"name":"http","address":"10.0.0.1","port":80,"protocol":"http"}"#,
        );
        assert_eq!(r.status(), StatusCode::OK);
        // add pool + backend
        operator(
            &s.store,
            &Method::POST,
            &["fleets", "f", "pools"],
            br#"{"name":"web","backends":[]}"#,
        );
        operator(
            &s.store,
            &Method::POST,
            &["fleets", "f", "pools", "web", "backends"],
            br#"{"host":"10.0.0.2","port":8080}"#,
        );
        // add route
        operator(
            &s.store,
            &Method::POST,
            &["fleets", "f", "routes"],
            br#"{"name":"r","listener":"http","host":"a.example.org","action":{"forward":"web"}}"#,
        );
        // publish
        let r = operator(&s.store, &Method::POST, &["fleets", "f", "publish"], b"");
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(s.store.target_seq("f").unwrap(), Some(1));
    }

    #[test]
    fn duplicate_fleet_conflicts() {
        let s = state();
        let body = br#"{"name":"f","vip":"10.0.0.1"}"#;
        operator(&s.store, &Method::POST, &["fleets"], body);
        let r = operator(&s.store, &Method::POST, &["fleets"], body);
        assert_eq!(r.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn agent_get_target_and_report() {
        let s = state();
        // Minimal fleet + node + publish.
        operator(
            &s.store,
            &Method::POST,
            &["fleets"],
            br#"{"name":"f","vip":"10.0.0.1"}"#,
        );
        operator(
            &s.store,
            &Method::POST,
            &["fleets", "f", "nodes"],
            br#"{"fleet":"f","gfe_node_id":"n1","mgmt_addr":"10.0.0.5"}"#,
        );
        operator(
            &s.store,
            &Method::POST,
            &["fleets", "f", "listeners"],
            br#"{"name":"http","address":"10.0.0.1","port":80,"protocol":"http"}"#,
        );
        operator(
            &s.store,
            &Method::POST,
            &["fleets", "f", "pools"],
            br#"{"name":"web","backends":[{"host":"10.0.0.2","port":8080}]}"#,
        );
        operator(
            &s.store,
            &Method::POST,
            &["fleets", "f", "routes"],
            br#"{"name":"r","listener":"http","host":"a.example.org","action":{"forward":"web"}}"#,
        );
        operator(&s.store, &Method::POST, &["fleets", "f", "publish"], b"");

        // Agent fetches target (current_seq null → should get Target seq 1).
        let r = agent(
            &s.store,
            &Method::POST,
            &["get-target"],
            br#"{"fleet":"f","node_id":"n1","current_seq":null}"#,
        );
        assert_eq!(r.status(), StatusCode::OK);
        let body = body_string(r);
        assert!(body.contains("\"status\":\"target\""), "got {body}");
        assert!(body.contains("\"seq\":1"));

        // Report applied, then a second fetch is UpToDate.
        let r = agent(
            &s.store,
            &Method::POST,
            &["report-status"],
            br#"{"fleet":"f","node_id":"n1","applied_seq":1,"reload_state":"OK","healthy":true}"#,
        );
        assert_eq!(r.status(), StatusCode::OK);
        let r = agent(
            &s.store,
            &Method::POST,
            &["get-target"],
            br#"{"fleet":"f","node_id":"n1","current_seq":1}"#,
        );
        assert!(body_string(r).contains("up_to_date"));

        // Node observed state reflects the report.
        let n = s.store.get_node("f", "n1").unwrap();
        assert_eq!(n.applied_seq, Some(1));
    }
}
