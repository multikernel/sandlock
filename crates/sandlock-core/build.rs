use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../..").canonicalize().unwrap();
    let src = repo_root.join("tests/rootfs-helper.c");
    let bin = repo_root.join("tests/rootfs-helper");

    // Only rebuild if the source changed.
    println!("cargo:rerun-if-changed={}", src.display());

    if !src.exists() {
        return; // Source not present — skip (e.g. packaged crate).
    }

    // Already up-to-date?
    if bin.exists() {
        if let (Ok(src_meta), Ok(bin_meta)) = (src.metadata(), bin.metadata()) {
            if let (Ok(src_time), Ok(bin_time)) =
                (src_meta.modified(), bin_meta.modified())
            {
                if bin_time >= src_time {
                    return;
                }
            }
        }
    }

    // Try musl-gcc (fully static), then cc -static.
    for cc in &["musl-gcc", "cc"] {
        let ok = Command::new(cc)
            .args(&["-static", "-O2", "-o"])
            .arg(&bin)
            .arg(&src)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return;
        }
    }

    println!(
        "cargo:warning=cannot compile tests/rootfs-helper — \
         chroot tests will fail. Install musl-tools or static libc."
    );
}
