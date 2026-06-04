//! `gfe-trace` — offline routing-decision tracer.
//!
//! Loads the same dynamic config a node would, then renders, as a tree, the
//! *journey* a request would take: which listener and route it matches, any
//! redirect it follows (e.g. http→https) into the next listener, and finally
//! the upstream pool and the backend it would be sent to. Invaluable for
//! debugging misrouted requests without touching production traffic.

use anyhow::{Context, Result};
use clap::Parser;
use gfe_router::RouteTable;
use gfe_types::{LbPolicy, ListenProtocol, Listener, ListenerId, PoolId, RouteAction};
use gfe_upstream::policy::hash64;
use gfe_upstream::{HealthMap, PoolSet};
use std::path::PathBuf;

/// Guard against redirect loops / pathological chains.
const MAX_HOPS: usize = 8;

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
    /// Restrict the trace to a single entry listener id (default: every listener).
    #[arg(long)]
    listener: Option<String>,
}

struct Ctx<'a> {
    table: &'a RouteTable,
    pools: &'a PoolSet,
    health: &'a HealthMap,
    listeners: &'a [Listener],
    host: &'a str,
    path: &'a str,
}

fn scheme_of(p: ListenProtocol) -> &'static str {
    match p {
        ListenProtocol::Http => "http",
        ListenProtocol::Https => "https",
    }
}

fn proto_of(scheme: &str) -> Option<ListenProtocol> {
    match scheme {
        "http" => Some(ListenProtocol::Http),
        "https" => Some(ListenProtocol::Https),
        _ => None,
    }
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

    let ctx = Ctx {
        table: &table,
        pools: &pools,
        health: &health,
        listeners: &dynamic.listeners,
        host: &args.host,
        path: &args.path,
    };

    println!("trace  host={}  path={}", args.host, args.path);

    let entries: Vec<&Listener> = match &args.listener {
        Some(id) => dynamic.listeners.iter().filter(|l| l.id.0 == *id).collect(),
        None => dynamic.listeners.iter().collect(),
    };
    if entries.is_empty() {
        println!("\n(no matching entry listener)");
        return Ok(());
    }

    for l in entries {
        let url = format!("{}://{}{}", scheme_of(l.protocol), args.host, args.path);
        println!("\n▶ {url}");
        let mut visited = vec![l.id.clone()];
        render(&ctx, "  ", &l.id, 0, &mut visited);
    }

    println!("\nnote: health is shown as configured intent (all backends assumed up);");
    println!("      query a live node's /metrics for actual backend health.");
    Ok(())
}

/// Render one listener hop and recurse through any redirect it issues.
fn render(
    ctx: &Ctx,
    prefix: &str,
    listener_id: &ListenerId,
    hop: usize,
    visited: &mut Vec<ListenerId>,
) {
    let route = match ctx.table.match_request(listener_id, ctx.host, ctx.path) {
        Some(r) => r,
        None => {
            println!("{prefix}└─ listener \"{listener_id}\": no route matched → 404");
            return;
        }
    };
    println!(
        "{prefix}└─ listener \"{listener_id}\" → route \"{}\"",
        route.id
    );
    let child = format!("{prefix}   ");

    match &route.action {
        RouteAction::Forward(pool_id) => render_forward(ctx, &child, pool_id),
        RouteAction::Fixed(f) => {
            println!("{child}└─ respond {} (fixed, no upstream)", f.status);
        }
        RouteAction::Redirect(rd) => {
            let target = format!("{}://{}{}", rd.scheme, ctx.host, ctx.path);
            println!("{child}└─ redirect {} → {target}", rd.status);
            render_redirect(ctx, &child, &rd.scheme, hop, visited);
        }
    }
}

fn render_forward(ctx: &Ctx, prefix: &str, pool_id: &str) {
    let pool = match ctx.pools.get(&PoolId(pool_id.to_string())) {
        Some(p) => p,
        None => {
            println!("{prefix}└─ forward → pool \"{pool_id}\"  NOT FOUND → 502");
            return;
        }
    };
    println!(
        "{prefix}└─ forward → pool \"{pool_id}\"  (scheme={}, policy={}, {} backend{})",
        scheme_label(pool.scheme),
        policy_label(pool.policy),
        pool.upstreams.len(),
        if pool.upstreams.len() == 1 { "" } else { "s" },
    );
    let bp = format!("{prefix}   ");

    // For ring_hash the choice is deterministic given the host key — show it.
    let selected = if pool.policy == LbPolicy::RingHash {
        pool.select(ctx.health, Some(hash64(ctx.host)))
            .map(|s| s.upstream.authority())
    } else {
        None
    };

    for (i, u) in pool.upstreams.iter().enumerate() {
        let last = i + 1 == pool.upstreams.len();
        let branch = if last { "└─" } else { "├─" };
        let auth = u.authority();
        let weight = if pool.upstreams.iter().any(|x| x.weight != 1) {
            format!("  (weight {})", u.weight)
        } else {
            String::new()
        };
        let mark = if selected.as_deref() == Some(auth.as_str()) {
            "   ◀ selected for this host (ring-hash)"
        } else {
            ""
        };
        println!("{bp}{branch} {auth}{weight}{mark}");
    }

    let how = match pool.policy {
        LbPolicy::RoundRobin => "round-robin across healthy backends (weighted by weight)",
        LbPolicy::LeastRequest => "least-request: the backend with fewest in-flight wins",
        LbPolicy::RingHash => "ring-hash: same host/key sticks to the marked backend",
    };
    println!("{bp}   ↳ {how}");
}

fn render_redirect(
    ctx: &Ctx,
    prefix: &str,
    scheme: &str,
    hop: usize,
    visited: &mut Vec<ListenerId>,
) {
    let gchild = format!("{prefix}   ");
    if hop + 1 >= MAX_HOPS {
        println!("{gchild}(stopped: too many redirect hops)");
        return;
    }
    let proto = match proto_of(scheme) {
        Some(p) => p,
        None => {
            println!("{gchild}({scheme}:// is external — not traced further)");
            return;
        }
    };
    let targets: Vec<&Listener> = ctx
        .listeners
        .iter()
        .filter(|l| l.protocol == proto)
        .collect();
    if targets.is_empty() {
        println!("{gchild}(no {scheme} listener configured to receive this)");
        return;
    }
    for l in targets {
        if visited.contains(&l.id) {
            println!(
                "{gchild}└─ (redirect loop: listener \"{}\" already on this path)",
                l.id
            );
            continue;
        }
        visited.push(l.id.clone());
        render(ctx, &gchild, &l.id, hop + 1, visited);
        visited.pop();
    }
}

fn scheme_label(s: gfe_types::Scheme) -> &'static str {
    match s {
        gfe_types::Scheme::Http => "http",
        gfe_types::Scheme::Https => "https",
    }
}

fn policy_label(p: LbPolicy) -> &'static str {
    match p {
        LbPolicy::RoundRobin => "round_robin",
        LbPolicy::LeastRequest => "least_request",
        LbPolicy::RingHash => "ring_hash",
    }
}
