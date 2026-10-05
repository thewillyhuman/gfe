//! The example configs of `docs/examples/` are what an operator copies:
//! they must load with the current schema.

use gfe_config::{load_dynamic_config, load_node_config, validate};
use std::path::{Path, PathBuf};

/// A file of the repository's `docs/examples/` directory.
fn shipped_example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/examples")
        .join(name)
}

#[test]
fn example_node_config_loads() {
    let node = load_node_config(&shipped_example("gfe.example.toml"));

    assert!(node.is_ok(), "{}", node.unwrap_err());
}

/// The paths the package and its systemd unit provide: the cache must
/// survive a stop, which `/tmp` does not under `PrivateTmp=yes`.
#[test]
fn example_node_config_uses_the_packaged_paths() {
    let node = load_node_config(&shipped_example("gfe.example.toml")).unwrap();

    assert_eq!(
        node.control_plane.config_file,
        Path::new("/etc/gfe/gfe-dynamic.json")
    );
    assert_eq!(
        node.control_plane.local_cache.as_deref(),
        Some(Path::new("/var/lib/gfe/config-cache.json"))
    );
}

/// Certificates are not loaded: the files it names exist only on a node.
#[test]
fn example_dynamic_config_loads_and_validates() {
    let cfg = load_dynamic_config(&shipped_example("gfe-dynamic.example.json")).unwrap();

    let validated = validate(&cfg);

    assert!(validated.is_ok(), "{}", validated.unwrap_err());
}
