//! Compiles the kernel-side program (`bpf/tcp_events.bpf.c`) with clang.
//!
//! Only when building for Linux. If clang is not installed the crate still
//! builds, without the program: attaching then reports that this build has no
//! eBPF support. If clang is there and the program does not compile, the
//! build fails.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCE: &str = "bpf/tcp_events.bpf.c";

fn main() {
    println!("cargo::rerun-if-changed={SOURCE}");
    println!("cargo::rerun-if-env-changed=CLANG");
    println!("cargo::rustc-check-cfg=cfg(gfe_bpf_built)");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let object = out_dir.join("tcp_events.bpf.o");
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());

    let mut compile = Command::new(&clang);
    // -g: the maps are described by BTF, which clang emits with debug info.
    compile.args([
        "-O2", "-g", "-target", "bpf", "-Wall", "-Werror", "-c", SOURCE, "-o",
    ]);
    compile.arg(&object);
    // Debian-style multiarch keeps <asm/types.h> in a per-architecture
    // directory that a BPF-targeted clang does not search by itself.
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let multiarch = format!("/usr/include/{arch}-linux-gnu");
    if Path::new(&multiarch).is_dir() {
        compile.args(["-idirafter", &multiarch]);
    }

    match compile.status() {
        Ok(status) if status.success() => println!("cargo::rustc-cfg=gfe_bpf_built"),
        Ok(status) => panic!("{clang} failed to compile {SOURCE}: {status}"),
        Err(_) => println!(
            "cargo::warning={clang} not found: building gfe-ebpf without its kernel program; \
             kernel TCP statistics will be unavailable in this build"
        ),
    }
}
