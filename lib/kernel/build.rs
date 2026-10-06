//! Compiles the kernel-side program (`bpf/tcp_events.bpf.c`) with clang.
//!
//! Only when building for Linux, and there it is required: a Linux build
//! without its kernel program would be a node that can never see its TCP
//! connections, so a missing clang fails the build rather than going
//! unnoticed. Other targets build a stand-in and need no compiler.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

/// The program, relative to this crate.
const SOURCE: &str = "bpf/tcp_events.bpf.c";

fn main() {
    println!("cargo::rerun-if-changed={SOURCE}");
    println!("cargo::rerun-if-env-changed=CLANG");

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
        Ok(status) if status.success() => {}
        Ok(status) => fail(&format!("`{clang}` failed to compile {SOURCE}: {status}")),
        Err(e) => fail(&format!(
            "cannot run `{clang}`: {e}\n\
             Building netkit-kernel for Linux needs clang (with the BPF target) and the \
             kernel's uapi headers to compile its kernel program, {SOURCE}.\n\
             Install clang (Debian/Ubuntu: `apt install clang`; RHEL/Alma: \
             `dnf install clang`), or point CLANG at one, e.g. CLANG=/usr/bin/clang-18."
        )),
    }
}

/// Stops the build with `message`, without a panic's backtrace noise.
fn fail(message: &str) -> ! {
    eprintln!("error: netkit-kernel: {message}");
    process::exit(1);
}
