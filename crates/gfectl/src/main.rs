//! `gfectl` — the operator CLI for the GFE control plane (spec §9). A thin,
//! declarative client over the gfe-cp operator HTTP API.

mod client;

use anyhow::Result;
use clap::{Parser, Subcommand};
use client::{print_json, Client};
use serde_json::json;

#[derive(Parser, Debug)]
#[command(name = "gfectl", version, about = "GFE control plane CLI")]
struct Cli {
    /// Controller base URL. Falls back to `GFE_CP_URL`.
    #[arg(long, env = "GFE_CP_URL", default_value = "http://127.0.0.1:8080")]
    cp_url: String,
    /// Bearer token. Falls back to `GFE_CP_TOKEN`.
    #[arg(long, env = "GFE_CP_TOKEN")]
    token: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Manage fleets.
    Fleet {
        #[command(subcommand)]
        cmd: FleetCmd,
    },
    /// Manage nodes within a fleet.
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Manage listeners.
    Listener {
        #[command(subcommand)]
        cmd: ListenerCmd,
    },
    /// Manage certificates.
    Cert {
        #[command(subcommand)]
        cmd: CertCmd,
    },
    /// Manage upstream pools.
    Pool {
        #[command(subcommand)]
        cmd: PoolCmd,
    },
    /// Manage backends within a pool.
    Backend {
        #[command(subcommand)]
        cmd: BackendCmd,
    },
    /// Manage routes.
    Route {
        #[command(subcommand)]
        cmd: RouteCmd,
    },
}

#[derive(Subcommand, Debug)]
enum FleetCmd {
    /// Create a fleet.
    Create {
        name: String,
        #[arg(long)]
        vip: String,
        #[arg(long, default_value = "1.2")]
        tls_min: String,
        #[arg(long, default_value = "")]
        hsts: String,
    },
    /// List all fleets.
    List,
    /// Show one fleet.
    Get { name: String },
    /// Delete a fleet.
    Delete { name: String },
    /// Show the rendered diff between desired state and the current target.
    Diff { name: String },
    /// Validate, create a revision, and start rollout.
    Publish { name: String },
    /// Re-target an earlier revision (rollback).
    Rollback {
        name: String,
        #[arg(long)]
        to: i64,
    },
    /// Show per-node applied revision + reload state.
    Status { name: String },
    /// List a fleet's revisions.
    Revisions { name: String },
}

#[derive(Subcommand, Debug)]
enum NodeCmd {
    /// Register a node.
    Add {
        fleet: String,
        node_id: String,
        #[arg(long)]
        mgmt_addr: String,
        #[arg(long, default_value = "127.0.0.1:9101")]
        metrics_addr: String,
    },
    /// List a fleet's nodes.
    List { fleet: String },
    /// Remove a node.
    Remove { fleet: String, node_id: String },
}

#[derive(Subcommand, Debug)]
enum ListenerCmd {
    /// Add a listener.
    Add {
        fleet: String,
        name: String,
        #[arg(long)]
        addr: String,
        #[arg(long)]
        port: u16,
        /// Terminate TLS (HTTPS). Default is plaintext HTTP.
        #[arg(long)]
        https: bool,
    },
    /// Remove a listener.
    Remove { fleet: String, name: String },
}

#[derive(Subcommand, Debug)]
enum CertCmd {
    /// Add a certificate from PEM files.
    Add {
        fleet: String,
        /// Comma-separated SNI names.
        #[arg(long, value_delimiter = ',')]
        sni: Vec<String>,
        /// Mark as the fleet default certificate.
        #[arg(long)]
        default: bool,
        #[arg(long)]
        cert: std::path::PathBuf,
        #[arg(long)]
        key: std::path::PathBuf,
    },
    /// Remove a certificate by content hash.
    Remove { fleet: String, content_sha: String },
    /// List certificates.
    List { fleet: String },
}

#[derive(Subcommand, Debug)]
enum PoolCmd {
    /// Add a pool.
    Add {
        fleet: String,
        name: String,
        #[arg(long, default_value = "http")]
        scheme: String,
        #[arg(long, default_value = "round_robin")]
        lb: String,
    },
    /// Remove a pool.
    Remove { fleet: String, name: String },
}

#[derive(Subcommand, Debug)]
enum BackendCmd {
    /// Add (or update) a backend `host:port`.
    Add {
        fleet: String,
        pool: String,
        addr: String,
        #[arg(long, default_value_t = 1)]
        weight: u32,
    },
    /// Remove a backend `host:port`.
    Remove {
        fleet: String,
        pool: String,
        addr: String,
    },
}

#[derive(Subcommand, Debug)]
enum RouteCmd {
    /// Add a forwarding route.
    Add {
        fleet: String,
        name: String,
        #[arg(long)]
        listener: String,
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "/")]
        path: String,
        /// Forward to this pool.
        #[arg(long)]
        forward: String,
    },
    /// Remove a route.
    Remove { fleet: String, name: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let c = Client::new(cli.cp_url, cli.token)?;
    let out = run(&c, cli.cmd)?;
    print_json(&out);
    Ok(())
}

fn run(c: &Client, cmd: Cmd) -> Result<String> {
    match cmd {
        Cmd::Fleet { cmd } => fleet(c, cmd),
        Cmd::Node { cmd } => node(c, cmd),
        Cmd::Listener { cmd } => listener(c, cmd),
        Cmd::Cert { cmd } => cert(c, cmd),
        Cmd::Pool { cmd } => pool(c, cmd),
        Cmd::Backend { cmd } => backend(c, cmd),
        Cmd::Route { cmd } => route(c, cmd),
    }
}

fn fleet(c: &Client, cmd: FleetCmd) -> Result<String> {
    match cmd {
        FleetCmd::Create {
            name,
            vip,
            tls_min,
            hsts,
        } => c.post(
            "/v1/fleets",
            &json!({"name": name, "vip": vip, "tls_min_version": tls_min, "hsts": hsts}),
        ),
        FleetCmd::List => c.get("/v1/fleets"),
        FleetCmd::Get { name } => c.get(&format!("/v1/fleets/{name}")),
        FleetCmd::Delete { name } => c.delete(&format!("/v1/fleets/{name}")),
        FleetCmd::Diff { name } => {
            let body = c.get(&format!("/v1/fleets/{name}/diff"))?;
            let v: serde_json::Value = serde_json::from_str(&body)?;
            let changed = v.get("changed").and_then(|c| c.as_bool()).unwrap_or(false);
            if !changed {
                return Ok("no changes (desired state matches the current target)".into());
            }
            // Print the line diff unescaped.
            print!("{}", v.get("diff").and_then(|d| d.as_str()).unwrap_or(""));
            Ok(String::new())
        }
        FleetCmd::Publish { name } => c.post(&format!("/v1/fleets/{name}/publish"), &json!({})),
        FleetCmd::Rollback { name, to } => {
            c.post(&format!("/v1/fleets/{name}/rollback"), &json!({ "to": to }))
        }
        FleetCmd::Status { name } => c.get(&format!("/v1/fleets/{name}/status")),
        FleetCmd::Revisions { name } => c.get(&format!("/v1/fleets/{name}/revisions")),
    }
}

fn node(c: &Client, cmd: NodeCmd) -> Result<String> {
    match cmd {
        NodeCmd::Add {
            fleet,
            node_id,
            mgmt_addr,
            metrics_addr,
        } => c.post(
            &format!("/v1/fleets/{fleet}/nodes"),
            &json!({
                "fleet": fleet, "gfe_node_id": node_id,
                "mgmt_addr": mgmt_addr, "metrics_addr": metrics_addr
            }),
        ),
        NodeCmd::List { fleet } => c.get(&format!("/v1/fleets/{fleet}/nodes")),
        NodeCmd::Remove { fleet, node_id } => {
            c.delete(&format!("/v1/fleets/{fleet}/nodes/{node_id}"))
        }
    }
}

fn listener(c: &Client, cmd: ListenerCmd) -> Result<String> {
    match cmd {
        ListenerCmd::Add {
            fleet,
            name,
            addr,
            port,
            https,
        } => c.post(
            &format!("/v1/fleets/{fleet}/listeners"),
            &json!({
                "name": name, "address": addr, "port": port,
                "protocol": if https { "https" } else { "http" }
            }),
        ),
        ListenerCmd::Remove { fleet, name } => {
            c.delete(&format!("/v1/fleets/{fleet}/listeners/{name}"))
        }
    }
}

fn cert(c: &Client, cmd: CertCmd) -> Result<String> {
    match cmd {
        CertCmd::Add {
            fleet,
            sni,
            default,
            cert,
            key,
        } => {
            let cert_pem = std::fs::read_to_string(&cert)?;
            let key_pem = std::fs::read_to_string(&key)?;
            c.post(
                &format!("/v1/fleets/{fleet}/certificates"),
                &json!({
                    "sni": sni, "is_default": default,
                    "cert_pem": cert_pem, "key_pem": key_pem
                }),
            )
        }
        CertCmd::Remove { fleet, content_sha } => {
            c.delete(&format!("/v1/fleets/{fleet}/certificates/{content_sha}"))
        }
        CertCmd::List { fleet } => c.get(&format!("/v1/fleets/{fleet}/certificates")),
    }
}

fn pool(c: &Client, cmd: PoolCmd) -> Result<String> {
    match cmd {
        PoolCmd::Add {
            fleet,
            name,
            scheme,
            lb,
        } => c.post(
            &format!("/v1/fleets/{fleet}/pools"),
            &json!({"name": name, "scheme": scheme, "lb_policy": lb, "backends": []}),
        ),
        PoolCmd::Remove { fleet, name } => c.delete(&format!("/v1/fleets/{fleet}/pools/{name}")),
    }
}

fn backend(c: &Client, cmd: BackendCmd) -> Result<String> {
    match cmd {
        BackendCmd::Add {
            fleet,
            pool,
            addr,
            weight,
        } => {
            let (host, port) = split_authority(&addr)?;
            c.post(
                &format!("/v1/fleets/{fleet}/pools/{pool}/backends"),
                &json!({"host": host, "port": port, "weight": weight}),
            )
        }
        BackendCmd::Remove { fleet, pool, addr } => {
            let (host, port) = split_authority(&addr)?;
            c.delete(&format!(
                "/v1/fleets/{fleet}/pools/{pool}/backends/{host}/{port}"
            ))
        }
    }
}

fn route(c: &Client, cmd: RouteCmd) -> Result<String> {
    match cmd {
        RouteCmd::Add {
            fleet,
            name,
            listener,
            host,
            path,
            forward,
        } => c.post(
            &format!("/v1/fleets/{fleet}/routes"),
            &json!({
                "name": name, "listener": listener, "host": host,
                "path_prefix": path, "action": {"forward": forward}
            }),
        ),
        RouteCmd::Remove { fleet, name } => c.delete(&format!("/v1/fleets/{fleet}/routes/{name}")),
    }
}

/// Split `host:port` into its parts.
fn split_authority(addr: &str) -> Result<(String, u16)> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("expected host:port, got {addr}"))?;
    Ok((host.to_string(), port.parse()?))
}
