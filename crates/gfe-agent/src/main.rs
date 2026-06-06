//! `gfe-agent` binary: the per-node pull loop.

use anyhow::Result;
use clap::Parser;
use gfe_agent::{Agent, Paths, Tick};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "gfe-agent", version, about = "GFE per-node config pull agent")]
struct Args {
    /// Controller base URL, e.g. `http://gfe-cp:8080`.
    #[arg(long)]
    cp_url: String,
    /// This node's fleet name.
    #[arg(long)]
    fleet: String,
    /// This node's id (matches the node row in the control plane).
    #[arg(long)]
    node_id: String,
    /// Where to write the dynamic JSON (the node's `control_plane.config_file`).
    #[arg(long)]
    config_file: PathBuf,
    /// Where to write the bootstrap TOML, if this agent manages it.
    #[arg(long)]
    static_toml: Option<PathBuf>,
    /// Optional prefix applied to absolute cert paths (chroot / staging).
    #[arg(long)]
    cert_prefix: Option<PathBuf>,
    /// Bearer token for the agent API. Falls back to `GFE_AGENT_TOKEN`.
    #[arg(long)]
    token: Option<String>,
    /// Shell command to restart gfe-node after a static (cold) config change
    /// (e.g. `systemctl restart gfe-node`). Without it, a static change is
    /// written but the agent only logs that a restart is required.
    #[arg(long)]
    restart_cmd: Option<String>,
    /// Poll interval in seconds.
    #[arg(long, default_value_t = 5)]
    interval: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let token = args.token.or_else(|| std::env::var("GFE_AGENT_TOKEN").ok());
    let agent = Agent::new(
        args.cp_url.clone(),
        token,
        args.fleet.clone(),
        args.node_id.clone(),
        Paths {
            config_file: args.config_file,
            static_toml: args.static_toml,
            prefix: args.cert_prefix,
        },
    )
    .with_restart_cmd(args.restart_cmd);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(agent, Duration::from_secs(args.interval)));
    Ok(())
}

/// The pull loop. Errors are logged and retried; the node keeps serving its
/// current config no matter what the controller does.
async fn run(agent: Agent, interval: Duration) {
    let mut current_seq: Option<i64> = None;
    tracing::info!("gfe-agent started");
    loop {
        match agent.tick(current_seq).await {
            Ok(Tick::Applied(seq)) => {
                tracing::info!(seq, "applied revision");
                current_seq = Some(seq);
            }
            Ok(Tick::UpToDate) => {}
            Err(e) => tracing::warn!(error = %e, "agent cycle failed; keeping current config"),
        }
        tokio::time::sleep(interval).await;
    }
}
