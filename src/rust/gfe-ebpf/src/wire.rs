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
        // The peer's FIN had arrived and the node had answered with its own.
        TCP_LAST_ACK => Ending::PeerClosed,
        // The node had sent its FIN first.
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
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A `struct conn_closed` as the kernel program would write it.
    fn closed_bytes(local: &str, peer: &str, accepted: u8, state: u8) -> Vec<u8> {
        let mut bytes = encode_key(addr(local), addr(peer)).to_vec();
        bytes.extend([accepted, state, 0, 0]);
        bytes.extend(1_500u32.to_le_bytes()); // srtt_us
        bytes.extend(900u32.to_le_bytes()); // min_rtt_us
        bytes.extend(3u32.to_le_bytes()); // retransmits
        bytes.extend(120u32.to_le_bytes()); // segments_out
        bytes.extend(10_000_000_000u64.to_le_bytes()); // established_ns
        bytes.extend(12_500_000_000u64.to_le_bytes()); // closed_ns
        bytes.extend(4_096u64.to_le_bytes()); // bytes_acked
        bytes.extend(512u64.to_le_bytes()); // bytes_received
        bytes
    }

    #[test]
    fn key_holds_ipv4_addresses_in_mapped_form() {
        let key = encode_key(addr("10.0.0.1:443"), addr("192.0.2.7:50000"));

        let mut expected = [0u8; KEY_LEN];
        expected[10..16].copy_from_slice(&[0xff, 0xff, 10, 0, 0, 1]);
        expected[26..32].copy_from_slice(&[0xff, 0xff, 192, 0, 2, 7]);
        expected[32..34].copy_from_slice(&443u16.to_le_bytes());
        expected[34..36].copy_from_slice(&50000u16.to_le_bytes());
        assert_eq!(key, expected);
    }

    #[test]
    fn key_of_an_ipv4_peer_on_an_ipv6_socket_matches_the_ipv4_key() {
        let plain = encode_key(addr("10.0.0.1:443"), addr("192.0.2.7:50000"));
        let mapped = encode_key(
            addr("[::ffff:10.0.0.1]:443"),
            addr("[::ffff:192.0.2.7]:50000"),
        );

        assert_eq!(plain, mapped);
    }

    #[test]
    fn decodes_a_closed_connection() {
        let bytes = closed_bytes("10.0.0.1:443", "192.0.2.7:50000", 1, TCP_LAST_ACK);

        let closed = decode_closed(&bytes).unwrap();

        assert_eq!(closed.local, addr("10.0.0.1:443"));
        assert_eq!(closed.peer, addr("192.0.2.7:50000"));
        assert_eq!(closed.origin, Origin::Accepted);
        assert_eq!(closed.ending, Ending::PeerClosed);
        assert_eq!(closed.rtt, Duration::from_micros(1_500));
        assert_eq!(closed.min_rtt, Duration::from_micros(900));
        assert_eq!(closed.retransmits, 3);
        assert_eq!(closed.segments_sent, 120);
        assert_eq!(closed.lifetime, Duration::from_millis(2_500));
        assert_eq!(closed.bytes_acked, 4_096);
        assert_eq!(closed.bytes_received, 512);
    }

    #[test]
    fn decodes_ipv6_addresses_as_ipv6() {
        let bytes = closed_bytes("[2001:db8::1]:443", "[2001:db8::2]:50000", 0, TCP_FIN_WAIT2);

        let closed = decode_closed(&bytes).unwrap();

        assert_eq!(closed.local, addr("[2001:db8::1]:443"));
        assert_eq!(closed.origin, Origin::Connected);
        assert_eq!(closed.ending, Ending::NodeClosed);
    }

    #[test]
    fn a_connection_closed_without_a_shutdown_was_aborted() {
        for state in [TCP_ESTABLISHED, TCP_CLOSE_WAIT] {
            assert_eq!(ending(state), Ending::Aborted);
        }
    }

    #[test]
    fn rejects_bytes_of_the_wrong_length() {
        let mut bytes = closed_bytes("10.0.0.1:443", "192.0.2.7:50000", 1, TCP_LAST_ACK);
        bytes.pop();

        assert_eq!(decode_closed(&bytes), None);
    }

    #[test]
    fn reads_when_an_open_connection_was_established() {
        let mut open = [0u8; OPEN_LEN];
        open[0..8].copy_from_slice(&42_000_000_000u64.to_le_bytes());
        open[8] = 1;

        assert_eq!(established_ns(&open), 42_000_000_000);
    }
}
