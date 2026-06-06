//! `gfe-cp` — the control-plane server binary.
//!
//! Loads (or generates) the master key, opens the desired-state store, and
//! serves the operator + agent HTTP API. Stateless beyond the store, matching
//! the spec's "all state external" property (§2).

use anyhow::{Context, Result};
use clap::Parser;
use gfe_cp::crypto::{decode_hex, AeadSealer};
use gfe_cp::server::Auth;
use gfe_cp::{serve, ApiState, Store};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "gfe-cp", version, about = "GFE control plane server")]
struct Args {
    /// Address to serve the operator + agent API on.
    #[arg(long, default_value = "0.0.0.0:8080")]
    addr: SocketAddr,
    /// File-backed store path (JSON snapshot). Omit for an in-memory store.
    #[arg(long)]
    store: Option<PathBuf>,
    /// File holding the hex-encoded 32-byte master key (envelope encryption).
    /// Falls back to the `GFE_CP_MASTER_KEY` env var.
    #[arg(long)]
    master_key_file: Option<PathBuf>,
    /// Optional bearer token required on all API calls (besides `/healthz`).
    /// Falls back to the `GFE_CP_TOKEN` env var.
    #[arg(long)]
    token: Option<String>,
    /// Print a freshly generated hex master key and exit.
    #[arg(long)]
    gen_master_key: bool,
    /// Debounce window (ms) for coalescing backend (de)registration bursts.
    #[arg(long, default_value_t = 500)]
    debounce_ms: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.gen_master_key {
        println!("{}", AeadSealer::generate_master_key_hex()?);
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let master_hex = load_master_key(&args)?;
    let master = decode_hex(&master_hex).context("decoding master key")?;
    let sealer = Arc::new(AeadSealer::new(&master).context("building sealer")?);

    let store = match &args.store {
        Some(path) => Store::open(path.clone(), sealer).context("opening store")?,
        None => {
            tracing::warn!("no --store given: using an in-memory store (state is not persisted)");
            Store::in_memory(sealer)
        }
    };

    let token = args.token.or_else(|| std::env::var("GFE_CP_TOKEN").ok());
    if token.is_none() {
        tracing::warn!("no API token set: the operator + agent API is unauthenticated");
    }
    let debouncer = Arc::new(gfe_cp::Debouncer::new(
        store.clone(),
        std::time::Duration::from_millis(args.debounce_ms),
    ));
    let state = Arc::new(ApiState {
        store,
        auth: Auth { token },
        debouncer,
    });

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(serve(args.addr, state))?;
    Ok(())
}

/// Load the master key hex from the file flag or the `GFE_CP_MASTER_KEY` env.
fn load_master_key(args: &Args) -> Result<String> {
    if let Some(path) = &args.master_key_file {
        return std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .with_context(|| format!("reading master key file {}", path.display()));
    }
    std::env::var("GFE_CP_MASTER_KEY").context(
        "no master key: pass --master-key-file or set GFE_CP_MASTER_KEY \
         (generate one with `gfe-cp --gen-master-key`)",
    )
}
