use super::*;
use rustls::HandshakeKind;

/// A server for `localhost` with a self-signed certificate, resuming
/// sessions as rustls does by default.
fn server_config() -> Arc<rustls::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap(),
        )
        .unwrap();
    Arc::new(config)
}

/// Hand what `from` has to write to `to`, and let `to` process it.
fn exchange<A, B>(from: &mut rustls::ConnectionCommon<A>, to: &mut rustls::ConnectionCommon<B>) {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    let mut unread = &buf[..];
    while !unread.is_empty() {
        to.read_tls(&mut unread).unwrap();
    }
    to.process_new_packets().unwrap();
}

/// One in-memory handshake of a fresh connection of `client` against
/// `server`, the session tickets sent after it read too; how it was done.
fn handshake(
    client: &Arc<rustls::ClientConfig>,
    server: &Arc<rustls::ServerConfig>,
) -> HandshakeKind {
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut client = rustls::ClientConnection::new(Arc::clone(client), name).unwrap();
    let mut server = rustls::ServerConnection::new(Arc::clone(server)).unwrap();
    while client.is_handshaking() || server.is_handshaking() {
        exchange(&mut client, &mut server);
        exchange(&mut server, &mut client);
    }
    // TLS 1.3 sends the tickets a later connection resumes with after the
    // handshake; the client has to read them to have a session to resume.
    exchange(&mut server, &mut client);
    client.handshake_kind().unwrap()
}

#[test]
fn resumes_tls_sessions_across_connections_by_default() {
    let server = server_config();
    let client = client_config(true);

    assert_eq!(handshake(&client, &server), HandshakeKind::Full);
    assert_eq!(handshake(&client, &server), HandshakeKind::Resumed);
}

#[test]
fn told_not_to_resume_makes_a_full_handshake_on_every_connection() {
    let server = server_config();
    let client = client_config(false);

    assert_eq!(handshake(&client, &server), HandshakeKind::Full);
    assert_eq!(handshake(&client, &server), HandshakeKind::Full);
}
