use super::*;
use crate::reload::test_support::{http_listener, scratch_dir};
use gfe_config::load_dynamic_config;

#[test]
fn a_written_cache_reads_back_as_the_same_config() {
    let dir = scratch_dir("cache-round-trip");
    let path = dir.join("config-cache.json");
    let config = DynamicConfig {
        listeners: vec![http_listener("http", 80)],
        ..Default::default()
    };

    write(&path, &config).unwrap();

    let back = load_dynamic_config(&path).unwrap();
    assert_eq!(back.listeners, config.listeners);
}

#[test]
fn writing_replaces_the_previous_cache_and_leaves_no_staging_file() {
    let dir = scratch_dir("cache-replace");
    let path = dir.join("config-cache.json");
    write(&path, &DynamicConfig::default()).unwrap();
    let config = DynamicConfig {
        listeners: vec![http_listener("http", 80)],
        ..Default::default()
    };

    write(&path, &config).unwrap();

    assert_eq!(load_dynamic_config(&path).unwrap().listeners.len(), 1);
    assert!(!dir.join("config-cache.tmp").exists());
}

#[test]
fn writing_into_a_missing_directory_fails() {
    let path = std::env::temp_dir().join("gfe-core-no-such-dir/config-cache.json");

    assert!(write(&path, &DynamicConfig::default()).is_err());
}
