//! End-to-end: a real `gfe-cp` server in-process, a real `gfe-agent` pulling
//! over HTTP. Exercises the full publish → get-target → apply → report path.

use gfe_agent::{Agent, Paths, Tick};
use gfe_cp::crypto::AeadSealer;
use gfe_cp::{ApiState, Auth, Store};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Seed a minimal, valid fleet with one node and publish it.
fn seed(store: &Store) {
    use gfe_cp_types::{Backend, Fleet, ListenerSpec, Node, PoolSpec, RouteActionSpec, RouteSpec};
    use gfe_types::{ListenProtocol, Scheme};

    store
        .create_fleet(Fleet::new("atlas-prod", "10.0.0.1".parse().unwrap()))
        .unwrap();
    store
        .put_node(Node::new(
            "atlas-prod",
            "gfe-node-01",
            "10.0.0.5".parse().unwrap(),
        ))
        .unwrap();
    store
        .put_listener(
            "atlas-prod",
            ListenerSpec {
                name: "http".into(),
                address: "10.0.0.1".parse().unwrap(),
                port: 80,
                protocol: ListenProtocol::Http,
            },
        )
        .unwrap();
    store
        .put_pool(
            "atlas-prod",
            PoolSpec {
                name: "web".into(),
                scheme: Scheme::Http,
                lb_policy: Default::default(),
                health_check: None,
                backends: vec![Backend {
                    host: "10.0.0.2".into(),
                    port: 8080,
                    weight: 1,
                    enabled: true,
                }],
            },
        )
        .unwrap();
    store
        .put_route(
            "atlas-prod",
            RouteSpec {
                name: "r".into(),
                listener: "http".into(),
                host: "atlas.example.org".into(),
                path_prefix: "/".into(),
                action: RouteActionSpec::Forward("web".into()),
            },
        )
        .unwrap();
    gfe_cp::publish(store, "atlas-prod", "test").unwrap();
}

#[tokio::test]
async fn agent_pulls_and_applies_published_revision() {
    let store = Store::in_memory(Arc::new(AeadSealer::new(&[4u8; 32]).unwrap()));
    seed(&store);
    let state = Arc::new(ApiState {
        debouncer: Arc::new(gfe_cp::Debouncer::new(
            store.clone(),
            std::time::Duration::from_millis(50),
        )),
        store: store.clone(),
        auth: Auth::default(),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(gfe_cp::serve_on(listener, state));

    let dir = std::env::temp_dir().join(format!("gfe-agent-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_file = dir.join("gfe-dynamic.json");
    let agent = Agent::new(
        format!("http://127.0.0.1:{port}"),
        None,
        "atlas-prod",
        "gfe-node-01",
        Paths {
            config_file: config_file.clone(),
            static_toml: Some(dir.join("gfe.toml")),
            prefix: Some(dir.clone()),
        },
    );

    // First tick: should apply revision 1.
    assert_eq!(agent.tick(None).await.unwrap(), Tick::Applied(1));
    let written = std::fs::read_to_string(&config_file).unwrap();
    assert!(written.contains("\"web\""), "dynamic json: {written}");
    assert!(dir.join("gfe.toml").exists());

    // The node's observed state is recorded.
    let node = store.get_node("atlas-prod", "gfe-node-01").unwrap();
    assert_eq!(node.applied_seq, Some(1));

    // Second tick at seq 1: up to date.
    assert_eq!(agent.tick(Some(1)).await.unwrap(), Tick::UpToDate);

    let _ = std::fs::remove_dir_all(&dir);
}
