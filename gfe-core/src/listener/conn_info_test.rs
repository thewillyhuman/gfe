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

fn plaintext(client_port: u16) -> Arc<ConnInfo> {
    ConnInfo::new(addr(client_port), addr(443), listener("https"), None)
}

#[test]
fn a_registered_connection_is_found_by_its_addresses() {
    let connections = Connections::new();
    let registration = connections.register(plaintext(40000));

    let found = connections.lookup(addr(40000), addr(443)).unwrap();

    assert!(Arc::ptr_eq(&found, registration.conn()));
}

#[test]
fn a_connection_between_other_addresses_is_not_found() {
    let connections = Connections::new();
    let _registration = connections.register(plaintext(40000));

    assert!(connections.lookup(addr(40001), addr(443)).is_none());
    assert!(connections.lookup(addr(40000), addr(80)).is_none());
}

#[test]
fn a_connection_is_forgotten_when_its_registration_is_dropped() {
    let connections = Connections::new();
    let registration = connections.register(plaintext(40000));
    assert_eq!(connections.len(), 1);

    drop(registration);

    assert!(connections.lookup(addr(40000), addr(443)).is_none());
    assert!(connections.is_empty());
}

#[test]
fn a_late_drop_does_not_forget_the_connection_that_reused_the_addresses() {
    let connections = Connections::new();
    let closed = connections.register(plaintext(40000));
    let reusing = connections.register(plaintext(40000));

    drop(closed);

    let found = connections.lookup(addr(40000), addr(443)).unwrap();
    assert!(Arc::ptr_eq(&found, reusing.conn()));
}

#[test]
fn a_request_is_in_flight_until_its_guard_is_dropped() {
    let conn = plaintext(40000);
    assert!(!conn.has_request_in_flight());

    let request = conn.begin_request();
    assert!(conn.has_request_in_flight());

    drop(request);
    assert!(!conn.has_request_in_flight());
}

#[test]
fn a_connection_is_busy_while_any_of_its_requests_is_in_flight() {
    let conn = plaintext(40000);
    let first = conn.begin_request();
    let second = conn.begin_request();

    drop(first);

    assert!(conn.has_request_in_flight());
    drop(second);
    assert!(!conn.has_request_in_flight());
}

#[test]
fn requests_are_counted_as_they_arrive_and_stay_counted() {
    let conn = plaintext(40000);
    assert_eq!(conn.requests(), 0);

    drop(conn.begin_request());
    let _in_flight = conn.begin_request();

    assert_eq!(conn.requests(), 2);
}

#[test]
fn a_renamed_listener_is_seen_by_the_connections_accepted_on_it() {
    let listener = listener("https");
    let conn = ConnInfo::new(addr(40000), addr(443), Arc::clone(&listener), None);
    assert_eq!(conn.listener().id, ListenerId("https".to_string()));

    let mut renamed = Listener::clone(&listener.load());
    renamed.id = ListenerId("edge".to_string());
    listener.store(Arc::new(renamed));

    assert_eq!(conn.listener().id, ListenerId("edge".to_string()));
}

#[test]
fn a_plaintext_connection_has_no_tls_parameters() {
    let conn = plaintext(40000);

    assert!(!conn.is_tls());
    assert!(conn.tls().is_none());
    assert!(conn.sni().is_none());
}

#[test]
fn a_tls_connection_tells_the_server_name_the_client_asked_for() {
    let negotiated = tls(Some("api.example.org"));
    let conn = ConnInfo::new(addr(40000), addr(443), listener("https"), Some(negotiated));

    assert!(conn.is_tls());
    assert_eq!(conn.sni(), Some("api.example.org"));
    assert_eq!(conn.tls().unwrap().version, "TLSv1.3");
}

#[test]
fn a_tls_connection_without_sni_has_no_server_name() {
    let conn = ConnInfo::new(addr(40000), addr(443), listener("https"), Some(tls(None)));

    assert!(conn.is_tls());
    assert!(conn.sni().is_none());
}

#[test]
fn a_connection_tells_both_of_its_addresses() {
    let conn = plaintext(40000);

    assert_eq!(conn.client(), addr(40000));
    assert_eq!(conn.local(), addr(443));
}
