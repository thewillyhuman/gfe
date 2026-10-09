//! `gfe-loadtest`: a self-contained end-to-end load harness for GFE.
//!
//! Three subcommands:
//!   * `upstream`: a fast mock backend returning a fixed body.
//!   * `run`: a concurrent load client measuring req/s and latency.
//!   * `compare`: whether a run made the node slower than a base run.
//!
//! Not a runtime component; a development tool. See hack/loadtest.sh.

mod client;
mod compare;
mod cpu;
mod outcome;
mod tls;
mod upstream;

use anyhow::Result;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
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
        /// `keepalive` (reuse each connection), `reconnect` (new
        /// conn/request) or `refused` (a new connection per attempt that
        /// the server is expected to close unread, as a node does over a
        /// connection limit; counted when it does).
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
        /// Upload this many bytes with each request, as a POST; the
        /// requests are GETs without a body otherwise.
        #[arg(long, default_value_t = 0, value_name = "BYTES")]
        upload_bytes: usize,
        /// Open this many connections before the run and hold them idle
        /// through it, each having carried one request: the kept
        /// connections of clients that seldom send.
        #[arg(long, default_value_t = 0, value_name = "N")]
        idle_connections: usize,
        /// A process (the node) whose CPU per answered request the row
        /// reports: user and system time, over the run.
        #[arg(long, value_name = "PID")]
        cpu_of: Option<u32>,
        /// Also append the outcome to this file as one JSON line, for
        /// `compare`.
        #[arg(long, value_name = "FILE")]
        json_out: Option<PathBuf>,
    },
    /// Compare the outcomes of a run with those of a base run, scenario
    /// by scenario, on the node's CPU per request; fail when one is
    /// slower than the base by more than the tolerance.
    Compare {
        /// The outcomes of the base run, as `run --json-out` wrote them.
        #[arg(long, value_name = "FILE")]
        base: PathBuf,
        /// The outcomes of the run under test.
        #[arg(long, value_name = "FILE")]
        head: PathBuf,
        /// How much slower than the base, in percent, a scenario may be.
        #[arg(long, default_value_t = 10.0, value_name = "PERCENT")]
        tolerance: f64,
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
                upload_bytes,
                idle_connections,
                cpu_of,
                json_out,
            } => {
                let scenario = client::Scenario {
                    target: Arc::new(client::parse_target(&target)?),
                    connections,
                    duration: Duration::from_secs(duration_secs),
                    reconnect: mode == "reconnect",
                    expect_refusal: mode == "refused",
                    resume: !no_resume,
                    label,
                    cpu_of,
                    upload: Bytes::from(vec![b'u'; upload_bytes]),
                    idle_connections,
                };
                let outcome = client::run(&scenario).await?;
                println!("{outcome}");
                if let Some(path) = json_out {
                    outcome.append_to(&path)?;
                }
                Ok(())
            }
            Cmd::Compare {
                base,
                head,
                tolerance,
            } => {
                let comparison = compare::Comparison::of(
                    &outcome::Outcome::read_all(&base)?,
                    &outcome::Outcome::read_all(&head)?,
                    tolerance,
                );
                print!("{comparison}");
                if !comparison.passed() {
                    std::process::exit(1);
                }
                Ok(())
            }
        }
    })
}
