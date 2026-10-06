//! The byte layouts shared with the kernel program (`bpf/tcp_events.bpf.c`).
//!
//! Everything crossing the kernel boundary is read and written here, field
//! by field, from plain bytes: no struct is ever reinterpreted. The layouts
//! are little-endian, which the kernel program asserts at compile time.

use crate::{ClosedConnection, Ending, Origin};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// `struct conn_key`: both addresses as 16 bytes, then both ports.
pub(crate) const KEY_LEN: usize = 36;
/// `struct conn_open`.
pub(crate) const OPEN_LEN: usize = 16;
/// `struct conn_closed`.
pub(crate) const CLOSED_LEN: usize = 88;

// TCP states, as the kernel numbers them (`BPF_TCP_*`).
const TCP_ESTABLISHED: u8 = 1;
const TCP_FIN_WAIT1: u8 = 4;
const TCP_FIN_WAIT2: u8 = 5;
const TCP_TIME_WAIT: u8 = 6;
const TCP_CLOSE_WAIT: u8 = 8;
const TCP_LAST_ACK: u8 = 9;
const TCP_CLOSING: u8 = 11;

/// The 16-byte form the kernel program stores an address in: IPv6 as is,
/// IPv4 mapped into IPv6.
fn address_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// The key of a connection in the kernel's table of open connections.
pub(crate) fn encode_key(local: SocketAddr, peer: SocketAddr) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key[0..16].copy_from_slice(&address_bytes(local.ip()));
    key[16..32].copy_from_slice(&address_bytes(peer.ip()));
    key[32..34].copy_from_slice(&local.port().to_le_bytes());
    key[34..36].copy_from_slice(&peer.port().to_le_bytes());
    key
}

fn decode_key(key: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let address = |bytes: &[u8]| -> Option<IpAddr> {
        let octets: [u8; 16] = bytes.try_into().ok()?;
        let v6 = Ipv6Addr::from(octets);
        Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4))
    };
    let port = |bytes: &[u8]| Some(u16::from_le_bytes(bytes.try_into().ok()?));
    Some((
        SocketAddr::new(address(key.get(0..16)?)?, port(key.get(32..34)?)?),
        SocketAddr::new(address(key.get(16..32)?)?, port(key.get(34..36)?)?),
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// When a still-open connection completed its handshake, in nanoseconds of
/// the monotonic clock, from its `struct conn_open`.
pub(crate) fn established_ns(open: &[u8; OPEN_LEN]) -> u64 {
    u64::from_le_bytes(open[0..8].try_into().expect("eight bytes"))
}

/// How a connection ended, from the state it was closed from.
fn ending(state_before_close: u8) -> Ending {
    match state_before_close {
        // The peer's FIN had arrived and this end had answered with its own.
        TCP_LAST_ACK => Ending::PeerClosed,
        // This end had sent its FIN first.
        TCP_FIN_WAIT1 | TCP_FIN_WAIT2 | TCP_CLOSING | TCP_TIME_WAIT => Ending::NodeClosed,
        // No orderly shutdown: a reset in either direction, or the kernel
        // giving up on a peer that stopped answering.
        TCP_ESTABLISHED | TCP_CLOSE_WAIT => Ending::Aborted,
        _ => Ending::Other,
    }
}

/// A closed connection, from its `struct conn_closed`. `None` if `bytes` is
/// not one.
pub(crate) fn decode_closed(bytes: &[u8]) -> Option<ClosedConnection> {
    if bytes.len() != CLOSED_LEN {
        return None;
    }
    let (local, peer) = decode_key(&bytes[0..KEY_LEN])?;
    let established = u64_at(bytes, 56)?;
    let closed = u64_at(bytes, 64)?;
    Some(ClosedConnection {
        local,
        peer,
        origin: if bytes[36] == 1 {
            Origin::Accepted
        } else {
            Origin::Connected
        },
        ending: ending(bytes[37]),
        rtt: Duration::from_micros(u32_at(bytes, 40)?.into()),
        min_rtt: Duration::from_micros(u32_at(bytes, 44)?.into()),
        retransmits: u32_at(bytes, 48)?,
        segments_sent: u32_at(bytes, 52)?,
        lifetime: Duration::from_nanos(closed.saturating_sub(established)),
        bytes_acked: u64_at(bytes, 72)?,
        bytes_received: u64_at(bytes, 80)?,
    })
}

#[cfg(test)]
#[path = "wire_test.rs"]
mod tests;
