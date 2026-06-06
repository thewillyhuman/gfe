//! `gfe-agent` — the per-node pull agent (spec §7).
//!
//! Runs next to `gfe-node` and owns the local config files. The controller
//! never reaches into a node; the agent pulls. Each cycle:
//!
//! 1. `GetTarget(fleet, node, current_seq)` — ask what this node should run.
//! 2. **Materialize certs first** to their content-addressed paths (cheap and
//!    idempotent — already-present files are skipped), `fsync`.
//! 3. Write `dynamic.json` to a temp file on the same filesystem, `fsync`, then
//!    **atomic `rename()`** into place so inotify sees one event and the node's
//!    `ArcSwap` reload never observes a torn file.
//! 4. `ReportStatus` the applied sequence and reload result.
//!
//! If the controller is unreachable the agent does nothing and the node keeps
//! serving its current config — no `gfe-cp` outage can affect the data plane.

use bytes::Bytes;
use gfe_cp_types::{
    GetTargetRequest, GetTargetResponse, ReloadState, ReportStatusRequest, ReportStatusResponse,
    TargetRevision,
};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors from an agent cycle.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("http error: {0}")]
    Http(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, AgentError>;

/// Where the agent writes node-facing files.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Destination for the dynamic JSON (the node's `control_plane.config_file`).
    pub config_file: PathBuf,
    /// Destination for the bootstrap TOML, if the agent manages it.
    pub static_toml: Option<PathBuf>,
    /// Optional path prefix applied to absolute cert paths (for tests / chroot).
    pub prefix: Option<PathBuf>,
}

/// The agent: a controller endpoint, this node's identity, and local paths.
pub struct Agent {
    client: Client<HttpConnector, Full<Bytes>>,
    base_url: String,
    token: Option<String>,
    fleet: String,
    node_id: String,
    paths: Paths,
}

/// The outcome of one [`Agent::tick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tick {
    /// Already at the allowed target; nothing to do.
    UpToDate,
    /// Applied the given revision sequence.
    Applied(i64),
}

impl Agent {
    /// Build an agent. `base_url` is the controller root (e.g. `http://cp:8080`).
    pub fn new(
        base_url: impl Into<String>,
        token: Option<String>,
        fleet: impl Into<String>,
        node_id: impl Into<String>,
        paths: Paths,
    ) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Agent {
            client,
            base_url: base_url.into(),
            token,
            fleet: fleet.into(),
            node_id: node_id.into(),
            paths,
        }
    }

    /// Run one fetch → apply → report cycle. `current_seq` is the revision the
    /// node currently has applied (`None` before the first apply). Returns the
    /// new state.
    pub async fn tick(&self, current_seq: Option<i64>) -> Result<Tick> {
        let req = GetTargetRequest {
            fleet: self.fleet.clone(),
            node_id: self.node_id.clone(),
            current_seq,
        };
        match self.get_target(&req).await? {
            GetTargetResponse::UpToDate => Ok(Tick::UpToDate),
            GetTargetResponse::Target(target) => {
                let seq = target.seq;
                let reload_state = match apply(&target, &self.paths) {
                    Ok(()) => ReloadState::Ok,
                    Err(e) => {
                        tracing::error!(error = %e, seq, "failed to apply revision");
                        ReloadState::Failed
                    }
                };
                // Report regardless: a FAILED report drives the orchestrator's
                // auto-halt (spec §8.2).
                let healthy = matches!(reload_state, ReloadState::Ok);
                self.report_status(&ReportStatusRequest {
                    fleet: self.fleet.clone(),
                    node_id: self.node_id.clone(),
                    applied_seq: seq,
                    reload_state,
                    healthy,
                })
                .await?;
                match reload_state {
                    ReloadState::Ok => Ok(Tick::Applied(seq)),
                    _ => Err(AgentError::Io(std::io::Error::other(format!(
                        "revision {seq} failed to apply"
                    )))),
                }
            }
        }
    }

    async fn get_target(&self, req: &GetTargetRequest) -> Result<GetTargetResponse> {
        let bytes = self.post("/agent/get-target", req).await?;
        serde_json::from_slice(&bytes).map_err(|e| AgentError::Decode(e.to_string()))
    }

    async fn report_status(&self, req: &ReportStatusRequest) -> Result<ReportStatusResponse> {
        let bytes = self.post("/agent/report-status", req).await?;
        serde_json::from_slice(&bytes).map_err(|e| AgentError::Decode(e.to_string()))
    }

    async fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> Result<Bytes> {
        let payload = serde_json::to_vec(body).map_err(|e| AgentError::Decode(e.to_string()))?;
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(format!("{}{}", self.base_url, path))
            .header(hyper::header::CONTENT_TYPE, "application/json");
        if let Some(token) = &self.token {
            builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = builder
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| AgentError::Http(e.to_string()))?;
        let resp = self
            .client
            .request(request)
            .await
            .map_err(|e| AgentError::Http(e.to_string()))?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| AgentError::Http(e.to_string()))?
            .to_bytes();
        if !status.is_success() {
            return Err(AgentError::Http(format!(
                "{status}: {}",
                String::from_utf8_lossy(&bytes)
            )));
        }
        Ok(bytes)
    }
}

/// Apply a target to the local filesystem: certs first (content-addressed,
/// idempotent), then an atomic swap of the dynamic JSON.
pub fn apply(target: &TargetRevision, paths: &Paths) -> Result<()> {
    // 1. Materialize certs to their content-addressed paths.
    for cert in &target.certs {
        write_if_absent(&resolve(paths, &cert.path), cert.cert_pem.as_bytes())?;
        write_if_absent(&resolve(paths, &cert.key_path), cert.key_pem.as_bytes())?;
    }

    // 2/3. For a static-only change, write the TOML and signal restart-required.
    if target.static_only {
        if let Some(toml_path) = &paths.static_toml {
            atomic_write(toml_path, target.static_toml.as_bytes())?;
            tracing::warn!(
                seq = target.seq,
                "static config changed — node restart required to apply"
            );
        }
        return Ok(());
    }

    // Hot path: optionally refresh the TOML, then atomic-swap the dynamic JSON.
    if let Some(toml_path) = &paths.static_toml {
        atomic_write(toml_path, target.static_toml.as_bytes())?;
    }
    atomic_write(&paths.config_file, target.dynamic_json.as_bytes())?;
    Ok(())
}

/// Apply the optional path prefix to an absolute on-node path.
fn resolve(paths: &Paths, abs: &str) -> PathBuf {
    match &paths.prefix {
        Some(prefix) => prefix.join(abs.trim_start_matches('/')),
        None => PathBuf::from(abs),
    }
}

/// Write a content-addressed file only if it is not already present. Skipping
/// existing files is safe because the path *is* the content hash.
fn write_if_absent(path: &Path, contents: &[u8]) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    atomic_write(path, contents)
}

/// Write `contents` to `path` atomically: temp file on the same directory,
/// `fsync`, then `rename`. Restricts the file to `0600` on unix.
fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gfe_cp_types::TargetCert;

    fn target(json: &str, static_only: bool) -> TargetRevision {
        TargetRevision {
            seq: 7,
            content_hash: "h".into(),
            dynamic_json: json.into(),
            static_toml: "[node]\nid=\"n\"\n".into(),
            certs: vec![TargetCert {
                path: "/etc/gfe/certs/abc.crt.pem".into(),
                key_path: "/etc/gfe/certs/abc.key.pem".into(),
                content_sha: "abc".into(),
                cert_pem: "CERTDATA".into(),
                key_pem: "KEYDATA".into(),
            }],
            static_only,
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gfe-agent-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn apply_writes_certs_then_dynamic_json() {
        let dir = tmpdir("apply-writes");
        let paths = Paths {
            config_file: dir.join("gfe-dynamic.json"),
            static_toml: None,
            prefix: Some(dir.clone()),
        };
        apply(&target(r#"{"ok":true}"#, false), &paths).unwrap();

        let cert = std::fs::read_to_string(dir.join("etc/gfe/certs/abc.crt.pem")).unwrap();
        assert_eq!(cert, "CERTDATA");
        let key = std::fs::read_to_string(dir.join("etc/gfe/certs/abc.key.pem")).unwrap();
        assert_eq!(key, "KEYDATA");
        let dynamic = std::fs::read_to_string(dir.join("gfe-dynamic.json")).unwrap();
        assert_eq!(dynamic, r#"{"ok":true}"#);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn certs_are_not_rewritten_when_present() {
        let dir = tmpdir("certs-not-rewritten");
        let paths = Paths {
            config_file: dir.join("d.json"),
            static_toml: None,
            prefix: Some(dir.clone()),
        };
        apply(&target("{}", false), &paths).unwrap();
        // Tamper with the cert; a second apply must NOT overwrite it (content-
        // addressed paths are immutable, so an existing file is authoritative).
        let cert_path = dir.join("etc/gfe/certs/abc.crt.pem");
        std::fs::write(&cert_path, "TAMPERED").unwrap();
        apply(&target("{}", false), &paths).unwrap();
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), "TAMPERED");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn static_only_writes_toml_not_json() {
        let dir = tmpdir("static-only");
        let toml = dir.join("gfe.toml");
        let paths = Paths {
            config_file: dir.join("should-not-exist.json"),
            static_toml: Some(toml.clone()),
            prefix: Some(dir.clone()),
        };
        apply(&target("{}", true), &paths).unwrap();
        assert!(toml.exists());
        assert!(!dir.join("should-not-exist.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
