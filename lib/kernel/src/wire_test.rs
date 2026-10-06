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
