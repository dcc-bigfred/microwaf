//! Prepare the XDP object for embedding when the `ebpf` feature is enabled.
//!
//! Looks for an existing `libmw_ebpf.so`, or builds it with nightly + bpf-linker.
//! The bytes are then `include_bytes!`'d into the daemon binary.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../mw-ebpf/src/lib.rs");
    println!("cargo:rerun-if-changed=../mw-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=../mw-ebpf/.cargo/config.toml");
    println!("cargo:rerun-if-env-changed=MICROWAF_BPF_OBJECT");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EBPF");

    if env::var_os("CARGO_FEATURE_EBPF").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("microwaf crate lives under crates/")
        .to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("libmw_ebpf.so");

    let src = resolve_bpf_object(&workspace_root).unwrap_or_else(|e| {
        panic!(
            "ebpf feature enabled but BPF object unavailable: {e}\n\
             Fix: `make ebpf-setup && make ebpf`\n\
             Or set MICROWAF_BPF_OBJECT=/path/to/libmw_ebpf.so"
        );
    });

    fs::copy(&src, &dest).unwrap_or_else(|e| {
        panic!("copy {} → {}: {e}", src.display(), dest.display());
    });
    println!(
        "cargo:rustc-env=MICROWAF_BPF_SOURCE={}",
        src.display()
    );
}

fn resolve_bpf_object(workspace_root: &Path) -> Result<PathBuf, String> {
    if let Ok(p) = env::var("MICROWAF_BPF_OBJECT") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "MICROWAF_BPF_OBJECT={} is not a file",
            path.display()
        ));
    }

    let candidates = [
        workspace_root.join("target/bpfel-unknown-none/release/libmw_ebpf.so"),
        workspace_root.join("target/bpfel-unknown-none/debug/libmw_ebpf.so"),
        workspace_root.join("dist/libmw_ebpf.so"),
    ];
    if let Some(p) = candidates.into_iter().find(|p| p.is_file()) {
        return Ok(p);
    }

    build_bpf_object(workspace_root)
}

fn build_bpf_object(workspace_root: &Path) -> Result<PathBuf, String> {
    let ebpf_dir = workspace_root.join("crates/mw-ebpf");
    let target_dir = workspace_root.join("target");
    let out = target_dir.join("bpfel-unknown-none/release/libmw_ebpf.so");

    // Ensure ~/.cargo/bin (bpf-linker) is visible.
    let mut path_env = env::var("PATH").unwrap_or_default();
    if let Some(home) = env::var_os("HOME") {
        let cargo_bin = PathBuf::from(home).join(".cargo/bin");
        path_env = format!("{}:{path_env}", cargo_bin.display());
    }

    let status = Command::new("cargo")
        .args(["+nightly", "build", "--release"])
        .current_dir(&ebpf_dir)
        .env("PATH", &path_env)
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .map_err(|e| {
            format!("failed to spawn cargo +nightly (is nightly installed?): {e}")
        })?;

    if !status.success() {
        return Err(
            "cargo +nightly build of mw-ebpf failed (need: make ebpf-setup)".into(),
        );
    }
    if !out.is_file() {
        return Err(format!(
            "mw-ebpf build finished but {} missing",
            out.display()
        ));
    }
    Ok(out)
}
