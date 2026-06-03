//! `gfe-trace` — offline routing-decision tracer.
//!
//! Loads the same dynamic config a node would, then reports which listener and
//! route a given request matches, the target pool, its backends, and which
//! backend the pool's LB policy would select. Invaluable for debugging
//! misrouted requests without touching production traffic.

use anyhow::{Context, Result};
use clap::Parser;
use gfe_router::RouteTable;
use gfe_types::{ListenerId, RouteAction};
use gfe_upstream::{HealthMap, PoolSet};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "gfe-trace",
    version,
    about = "Trace how GFE would route a request"
)]
struct Args {
    /// Path to the bootstrap node config (TOML); its config_file is loaded.
    #[arg(long)]
    config: PathBuf,
    /// Request host (SNI / Host header).
    #[arg(long)]
    host: String,
    /// Request path.
    #[arg(long, default_value = "/")]
    path: String,
    /// Restrict to a single listener id (default: try all).
    #[arg(long)]
    listener: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let node = gfe_config::load_node_config(&args.config)
        .with_context(|| format!("loading node config {}", args.config.display()))?;
    let dynamic =
        gfe_config::load_dynamic_config(&node.control_plane.config_file).with_context(|| {
            format!(
                "loading dynamic config {}",
                node.control_plane.config_file.display()
            )
        })?;
    gfe_config::validate(&dynamic).context("validating dynamic config")?;

    let table = RouteTable::compile(&dynamic);
    let pools = PoolSet::build(&dynamic.pools);
    // Optimistic health view: trace shows configured intent, not live health.
    let health = HealthMap::new(true);

    let listener_ids: Vec<ListenerId> = match &args.listener {
        Some(id) => vec![ListenerId(id.clone())],
        None => dynamic.listeners.iter().map(|l| l.id.clone()).collect(),
    };

    println!("trace: host={} path={}", args.host, args.path);
    let mut any = false;
    for lid in listener_ids {
        match table.match_request(&lid, &args.host, &args.path) {
            Some(route) => {
                any = true;
                println!("  listener {lid}: matched route '{}'", route.id);
                match &route.action {
                    RouteAction::Forward(pool_id) => {
                        println!("    action: forward → pool '{pool_id}'");
                        match pools.get(&gfe_types::PoolId(pool_id.clone())) {
                            Some(pool) => {
                                println!(
                                    "    pool: scheme={:?} policy={:?} backends={}",
                                    pool.scheme,
                                    pool.policy,
                                    pool.upstreams.len()
                                );
                                for u in &pool.upstreams {
                                    println!("      - {}", u.authority());
                                }
                                let key = Some(gfe_upstream::policy::hash64(args.host.as_str()));
                                if let Some(sel) = pool.select(&health, key) {
                                    println!(
                                        "    selected (for host-keyed hash): {}",
                                        sel.upstream.authority()
                                    );
                                }
                            }
                            None => println!("    pool '{pool_id}' NOT FOUND"),
                        }
                    }
                    RouteAction::Redirect(rd) => {
                        println!(
                            "    action: redirect → {}://{}{} ({})",
                            rd.scheme, args.host, args.path, rd.status
                        );
                    }
                    RouteAction::Fixed(f) => {
                        println!("    action: fixed status {}", f.status);
                    }
                }
            }
            None => {
                println!("  listener {lid}: no route matched");
            }
        }
    }

    if !any {
        println!("no route matched on any listener → request would receive 404");
    }
    Ok(())
}
