use super::*;
use gfe_config::{ListenProtocol, ListenerId};

fn listener(id: &str) -> Arc<ArcSwap<Listener>> {
    Arc::new(ArcSwap::from_pointee(Listener {
        id: ListenerId(id.to_string()),
        address: "127.0.0.1".parse().unwrap(),
        port: 443,
        protocol: ListenProtocol::Https,
    }))
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn tls(sni: Option<&str>) -> TlsInfo {
    TlsInfo {
        sni: sni.map(str::to_string),
        version: "TLSv1.3",
        cipher: "TLS13_AES_256_GCM_SHA384".to_string(),
        alpn: Some("h2".to_string()),
        resumed: false,
    }
}

#[test]
fn a_connection_tells_both_of_its_addresses() {
    let conn = ConnInfo::new(addr(40000), addr(443), listener("https"), None);

    assert_eq!(conn.client(), addr(40000));
    assert_eq!(conn.local(), addr(443));
}

#[test]
fn an_ipv4_client_of_a_dual_stack_socket_is_told_as_ipv4() {
    let mapped: SocketAddr = "[::ffff:192.0.2.1]:40000".parse().unwrap();
    let local: SocketAddr = "[::ffff:192.0.2.9]:443".parse().unwrap();

    let conn = ConnInfo::new(mapped, local, listener("https"), None);

    assert_eq!(conn.client(), "192.0.2.1:40000".parse().unwrap());
    assert_eq!(conn.local(), "192.0.2.9:443".parse().unwrap());
}

#[test]
fn an_ipv6_client_keeps_its_address() {
    let client: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();

    let conn = ConnInfo::new(client, addr(443), listener("https"), None);

    assert_eq!(conn.client(), client);
}

#[test]
fn a_renamed_listener_is_seen_by_the_connections_accepted_on_it() {
    let configured = listener("old");
    let conn = ConnInfo::new(addr(40000), addr(443), Arc::clone(&configured), None);
    let mut renamed = (*configured.load_full()).clone();
    renamed.id = ListenerId("new".to_string());

    configured.store(Arc::new(renamed));

    assert_eq!(conn.listener().id, ListenerId("new".to_string()));
}

#[test]
fn a_plaintext_connection_has_no_tls_parameters() {
    let conn = ConnInfo::new(addr(40000), addr(80), listener("http"), None);

    assert!(!conn.is_tls());
    assert!(conn.tls().is_none());
    assert_eq!(conn.sni(), None);
}

#[test]
fn a_tls_connection_tells_the_server_name_the_client_asked_for() {
    let negotiated = tls(Some("app.example.org"));

    let conn = ConnInfo::new(addr(40000), addr(443), listener("https"), Some(negotiated));

    assert!(conn.is_tls());
    assert_eq!(conn.sni(), Some("app.example.org"));
    assert_eq!(conn.tls().unwrap().version, "TLSv1.3");
}

#[test]
fn a_tls_connection_without_sni_has_no_server_name() {
    let conn = ConnInfo::new(addr(40000), addr(443), listener("https"), Some(tls(None)));

    assert!(conn.is_tls());
    assert_eq!(conn.sni(), None);
}
