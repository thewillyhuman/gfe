//! Loading the kernel program, attaching it to the node's cgroup, and reading
//! what it reports.

use crate::wire::{self, CLOSED_LEN, KEY_LEN, OPEN_LEN};
use crate::{ClosedConnection, Unavailable};
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::{CgroupAttachMode, SockOps};
use aya::{Ebpf, EbpfLoader};
use rustix::time::{ClockId, clock_gettime};
use std::collections::VecDeque;
use std::error::Error;
use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

/// The compiled kernel program, built by `build.rs`.
static PROGRAM: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tcp_events.bpf.o"));

/// Where cgroup v2 is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The directory of the cgroup (v2) this process runs in, given the content
/// of `/proc/self/cgroup`.
fn own_cgroup(proc_self_cgroup: &str) -> Option<PathBuf> {
    // The cgroup v2 entry is the one with an empty hierarchy and controller
    // list: `0::/system.slice/gfe-node.service`.
    let path = proc_self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?;
    Some(Path::new(CGROUP_ROOT).join(path.trim_start_matches('/')))
}

// Capability numbers, as in <linux/capability.h>.
const CAP_NET_ADMIN: u32 = 12;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_BPF: u32 = 39;

/// Which of the capabilities the kernel program needs this process lacks,
/// given the content of `/proc/self/status`. `None` if it has them all, or
/// if the status cannot be read (then the kernel has the last word).
///
/// Checked up front because the kernel's own refusal is not always a clear
/// "not permitted": where unprivileged eBPF is partly allowed, the first
/// thing to fail is an unrelated-looking "invalid argument".
fn missing_capabilities(proc_self_status: &str) -> Option<&'static str> {
    let effective = proc_self_status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?;
    let effective = u64::from_str_radix(effective.trim(), 16).ok()?;
    let has = |capability: u32| effective & (1 << capability) != 0;
    // CAP_SYS_ADMIN covers both, as it did before CAP_BPF existed.
    let bpf = has(CAP_BPF) || has(CAP_SYS_ADMIN);
    let net_admin = has(CAP_NET_ADMIN) || has(CAP_SYS_ADMIN);
    match (bpf, net_admin) {
        (true, true) => None,
        (false, true) => Some("the process lacks CAP_BPF"),
        (true, false) => Some("the process lacks CAP_NET_ADMIN"),
        (false, false) => Some("the process lacks CAP_BPF and CAP_NET_ADMIN"),
    }
}

/// Whether `error` comes down to the process lacking the privilege to use
/// eBPF, as opposed to the kernel rejecting the program. Both surface as
/// "permission denied": lacking privilege is `EPERM`, a verifier rejection
/// is `EACCES`.
fn lacks_permission(error: &(dyn Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(current) = cause {
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            return io.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error());
        }
        cause = current.source();
    }
    false
}

/// `error` followed by what caused it: the libraries' own messages name the
/// failed call, the cause says why it failed.
fn with_causes(error: &(dyn Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(current) = cause {
        text.push_str(": ");
        text.push_str(&current.to_string());
        cause = current.source();
    }
    text
}

/// Nanoseconds on the monotonic clock: the clock the kernel program stamps
/// its records with.
fn monotonic_ns() -> u64 {
    let now = clock_gettime(ClockId::Monotonic);
    (now.tv_sec as u64) * 1_000_000_000 + now.tv_nsec as u64
}

/// The kernel program, attached to the node's cgroup for as long as this
/// lives.
pub struct TcpProbe {
    /// Owns the loaded program and its attachment.
    _ebpf: Ebpf,
    open_conns: HashMap<MapData, [u8; KEY_LEN], [u8; OPEN_LEN]>,
    lost: Array<MapData, u64>,
}

/// The connections the kernel reports as closed, in the order they closed.
pub struct ClosedConnections {
    ring: AsyncFd<RingBuf<MapData>>,
    /// Decoded but not yet handed out: the kernel wakes the reader once for
    /// any number of records.
    pending: VecDeque<ClosedConnection>,
}

impl TcpProbe {
    /// Load the kernel program and attach it to the cgroup of this process.
    ///
    /// `connections` is how many open connections the program must be able
    /// to keep track of at once: the node's client and upstream connection
    /// limits together. Must be called from within a Tokio runtime.
    pub fn attach(connections: u32) -> Result<(TcpProbe, ClosedConnections), Unavailable> {
        let kernel = |e: &(dyn Error + 'static)| {
            if lacks_permission(e) {
                Unavailable::NotPermitted(with_causes(e))
            } else {
                Unavailable::Kernel(with_causes(e))
            }
        };
        let missing = |what: String| Unavailable::Kernel(what);

        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        if let Some(missing) = missing_capabilities(&status) {
            return Err(Unavailable::NotPermitted(missing.to_string()));
        }

        let membership = std::fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| Unavailable::Cgroup(e.to_string()))?;
        let cgroup = own_cgroup(&membership)
            .ok_or_else(|| Unavailable::Cgroup("no cgroup v2 entry in /proc/self/cgroup".into()))?;
        let cgroup = File::open(&cgroup)
            .map_err(|e| Unavailable::Cgroup(format!("{}: {e}", cgroup.display())))?;

        let mut ebpf = EbpfLoader::new()
            .map_max_entries("open_conns", connections.max(1))
            .load(PROGRAM)
            .map_err(|e| kernel(&e))?;

        let program: &mut SockOps = ebpf
            .program_mut("tcp_events")
            .ok_or_else(|| missing("the object has no tcp_events program".into()))?
            .try_into()
            .map_err(|e| kernel(&e))?;
        program.load().map_err(|e| kernel(&e))?;
        // Attached through a link, which every kernel recent enough for the
        // rest of this program supports. A link always coexists with other
        // programs on the cgroup (the service manager's, for instance) and
        // takes no mode flags, hence the default mode.
        program
            .attach(cgroup, CgroupAttachMode::default())
            .map_err(|e| kernel(&e))?;

        let mut take = |name: &str| {
            ebpf.take_map(name)
                .ok_or_else(|| missing(format!("the object has no {name} map")))
        };
        let open_conns = HashMap::try_from(take("open_conns")?).map_err(|e| kernel(&e))?;
        let lost = Array::try_from(take("lost")?).map_err(|e| kernel(&e))?;
        let ring = RingBuf::try_from(take("closed_conns")?).map_err(|e| kernel(&e))?;
        let ring = AsyncFd::new(ring).map_err(|e| kernel(&e))?;

        Ok((
            TcpProbe {
                _ebpf: ebpf,
                open_conns,
                lost,
            },
            ClosedConnections {
                ring,
                pending: VecDeque::new(),
            },
        ))
    }

    /// How long a connection that `accept` has just returned had been
    /// waiting, handshake complete, to be accepted. `None` if the kernel
    /// program has no record of it.
    pub fn accept_queue_wait(&self, local: SocketAddr, peer: SocketAddr) -> Option<Duration> {
        let open = self
            .open_conns
            .get(&wire::encode_key(local, peer), 0)
            .ok()?;
        let waited = monotonic_ns().saturating_sub(wire::established_ns(&open));
        Some(Duration::from_nanos(waited))
    }

    /// Closed connections the kernel could not report because the reader
    /// had fallen behind, since the program was attached.
    pub fn lost_events(&self) -> u64 {
        self.lost.get(&0, 0).unwrap_or(0)
    }
}

impl ClosedConnections {
    /// The next closed connection. `None` only if the kernel side is gone.
    pub async fn next(&mut self) -> Option<ClosedConnection> {
        loop {
            if let Some(closed) = self.pending.pop_front() {
                return Some(closed);
            }
            let mut ready = self.ring.readable_mut().await.ok()?;
            let ring = ready.get_inner_mut();
            while let Some(record) = ring.next() {
                // A record of another size would be a layout mismatch with
                // the kernel program; skip it rather than misread it.
                if record.len() == CLOSED_LEN {
                    self.pending.extend(wire::decode_closed(&record));
                }
            }
            ready.clear_ready();
        }
    }
}

#[cfg(test)]
#[path = "linux_test.rs"]
mod tests;
