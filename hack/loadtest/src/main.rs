//! `gfe-loadtest`: a self-contained end-to-end load harness for GFE.
//!
//! Two subcommands:
//!   * `upstream`: a fast mock backend returning a fixed body.
//!   * `run`: a concurrent load client measuring req/s and latency.
//!
//! Not a runtime component; a development tool. See hack/loadtest.sh.

mod client;
mod cpu;
mod outcome;
mod tls;
mod upstream;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "gfe-loadtest", about = "End-to-end load harness for GFE")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a fast mock upstream returning a fixed body.
    Upstream {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: String,
        #[arg(long, default_value_t = 64)]
        body_bytes: usize,
    },
    /// Drive load against a target URL.
    Run {
        #[arg(long)]
        target: String,
        #[arg(long, default_value_t = 64)]
        connections: usize,
        #[arg(long, default_value_t = 8)]
        duration_secs: u64,
        /// `keepalive` (reuse each connection) or `reconnect` (new conn/request).
        #[arg(long, default_value = "keepalive")]
        mode: String,
        /// Do not resume TLS sessions across connections: every `reconnect`
        /// is then a full handshake, as from a client without a session,
        /// instead of a resumed one, as from a browser.
        #[arg(long)]
        no_resume: bool,
        /// Label for the printed result row.
        #[arg(long, default_value = "")]
        label: String,
        /// A process (the node) whose CPU per answered request the row
        /// reports: user and system time, over the run.
        #[arg(long, value_name = "PID")]
        cpu_of: Option<u32>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cli.cmd {
            Cmd::Upstream { listen, body_bytes } => upstream::serve(&listen, body_bytes).await,
            Cmd::Run {
                target,
                connections,
                duration_secs,
                mode,
                no_resume,
                label,
                cpu_of,
            } => {
                let scenario = client::Scenario {
                    target: Arc::new(client::parse_target(&target)?),
                    connections,
                    duration: Duration::from_secs(duration_secs),
                    reconnect: mode == "reconnect",
                    resume: !no_resume,
                    label,
                    cpu_of,
                };
                println!("{}", client::run(&scenario).await?);
                Ok(())
            }
        }
    })
}
