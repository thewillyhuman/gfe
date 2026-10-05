//! `gfe-node --check-config` as a pre-flight gate for config management
//! tooling: the binary is run exactly as a deploy hook would run it.

#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VALID_DYNAMIC: &str = r#"{
    "listeners": [{"id":"http","address":"127.0.0.1","port":8080,"protocol":"http"}],
    "routes": [{"id":"r","listener":"http","host":"a.example.org","action":{"forward":"p"}}],
    "pools": [{"id":"p","upstreams":[{"host":"10.0.0.1","port":8080}]}]
}"#;

/// A route forwarding to a pool that does not exist.
const INVALID_DYNAMIC: &str = r#"{
    "listeners": [{"id":"http","address":"127.0.0.1","port":8080,"protocol":"http"}],
    "routes": [{"id":"r","listener":"http","host":"a.example.org","action":{"forward":"missing"}}]
}"#;

/// An HTTPS listener whose certificate files do not exist.
const MISSING_CERT_DYNAMIC: &str = r#"{
    "certificates": [{"default":true,"cert_file":"/nonexistent/gfe.crt","key_file":"/nonexistent/gfe.key"}],
    "listeners": [{"id":"https","address":"127.0.0.1","port":8443,"protocol":"https"}]
}"#;

/// A scratch directory unique to one test.
fn scratch(test: &str) -> PathBuf {
    common::scratch("check", test)
}

/// Write a bootstrap TOML whose `config_file` points at `dynamic`.
fn write_bootstrap(dir: &Path, dynamic: &Path) -> PathBuf {
    let toml = format!(
        "[node]\nid = \"t\"\n\n\
         [control_plane]\nconfig_file = \"{}\"\n\n\
         [health_check_defaults]\n",
        dynamic.display()
    );
    let path = dir.join("gfe.toml");
    std::fs::write(&path, toml).unwrap();
    path
}

fn check_config(bootstrap: Option<&Path>, candidate: Option<&Path>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gfe-node"));
    cmd.arg("--check-config");
    if let Some(bootstrap) = bootstrap {
        cmd.arg("--config").arg(bootstrap);
    }
    if let Some(candidate) = candidate {
        cmd.arg("--dynamic-config").arg(candidate);
    }
    cmd.output().unwrap()
}

#[test]
fn accepts_valid_candidate_instead_of_deployed_file() {
    let dir = scratch("valid");
    // The deployed dynamic config does not exist yet: only the candidate does.
    let bootstrap = write_bootstrap(&dir, &dir.join("not-deployed.json"));
    let candidate = dir.join("candidate.json");
    std::fs::write(&candidate, VALID_DYNAMIC).unwrap();

    let out = check_config(Some(&bootstrap), Some(&candidate));

    assert!(out.status.success(), "{out:?}");
}

#[test]
fn rejects_invalid_candidate_even_when_deployed_file_is_valid() {
    let dir = scratch("invalid");
    let deployed = dir.join("deployed.json");
    std::fs::write(&deployed, VALID_DYNAMIC).unwrap();
    let bootstrap = write_bootstrap(&dir, &deployed);
    let candidate = dir.join("candidate.json");
    std::fs::write(&candidate, INVALID_DYNAMIC).unwrap();

    let out = check_config(Some(&bootstrap), Some(&candidate));

    assert!(!out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown pool missing"), "{stderr}");
}

#[test]
fn checks_deployed_file_when_no_candidate_is_given() {
    let dir = scratch("deployed");
    let deployed = dir.join("deployed.json");
    std::fs::write(&deployed, INVALID_DYNAMIC).unwrap();
    let bootstrap = write_bootstrap(&dir, &deployed);

    let out = check_config(Some(&bootstrap), None);

    assert!(!out.status.success(), "{out:?}");
}

#[test]
fn rejects_certificates_that_cannot_be_loaded() {
    let dir = scratch("missing-cert");
    let deployed = dir.join("deployed.json");
    std::fs::write(&deployed, MISSING_CERT_DYNAMIC).unwrap();
    let bootstrap = write_bootstrap(&dir, &deployed);

    let out = check_config(Some(&bootstrap), None);

    assert!(!out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("/nonexistent/gfe.crt"), "{stderr}");
}

/// On a node being bootstrapped the dynamic config is written before the
/// bootstrap config exists, so a candidate must be checkable on its own.
#[test]
fn accepts_valid_candidate_without_a_bootstrap_config() {
    let dir = scratch("standalone-valid");
    let candidate = dir.join("candidate.json");
    std::fs::write(&candidate, VALID_DYNAMIC).unwrap();

    let out = check_config(None, Some(&candidate));

    assert!(out.status.success(), "{out:?}");
}

#[test]
fn rejects_invalid_candidate_without_a_bootstrap_config() {
    let dir = scratch("standalone-invalid");
    let candidate = dir.join("candidate.json");
    std::fs::write(&candidate, INVALID_DYNAMIC).unwrap();

    let out = check_config(None, Some(&candidate));

    assert!(!out.status.success(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown pool missing"), "{stderr}");
}

/// Deploy hooks show this line to whoever deploys.
#[test]
fn says_what_it_checked() {
    let dir = scratch("summary");
    let candidate = dir.join("candidate.json");
    std::fs::write(&candidate, VALID_DYNAMIC).unwrap();

    let out = check_config(None, Some(&candidate));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim_end(),
        "config OK: 1 listeners, 1 routes, 1 pools, 0 certificates"
    );
}
