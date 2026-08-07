use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../..").canonicalize().unwrap();

    // rootfs-helper: an ordinary static-libc test fixture (chroot tests). It
    // lives in tests/ and its binary sits beside it (a git-ignored artifact).
    build_static(
        &repo_root.join("tests/rootfs-helper.c"),
        &repo_root.join("tests/rootfs-helper"),
        &["musl-gcc", "cc"],
        &["-static", "-O2"],
        "cannot compile tests/rootfs-helper: chroot tests will fail. \
         Install musl-tools or static libc.",
    );

    // restore-stub: a core component of the restore engine (the supervisor execs
    // it to reconstruct a checkpoint), freestanding, no libc, no PIE. It lives
    // next to the checkpoint code that owns it; its binary is built into OUT_DIR
    // and its path is handed to the crate via the RESTORE_STUB_PATH env var.
    //
    // The fixed load address must match `checkpoint::restore_blob::STUB_BASE`:
    // the stub reconstructs the checkpoint's layout around itself, so its own
    // text and stack have to sit outside the address range programs occupy. The
    // default -no-pie base (0x400000) is exactly where a static ET_EXEC workload
    // loads, so the checkpoint's own text would be mapped over the running stub.
    //
    // Cross-compilation: when TARGET is riscv64gc-unknown-linux-gnu (or any
    // riscv64* variant), look for a riscv64 cross-compiler. On the host it
    // uses plain `cc` as before.
    let stub_src = manifest_dir.join("src/checkpoint/restore-stub.c");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let stub_bin = out_dir.join("restore-stub");
    let target = std::env::var("TARGET").unwrap_or_default();
    let (ccs, warn) = if target.starts_with("riscv64")
        || target.starts_with("riscv64gc")
    {
        (
            &["riscv64-linux-gnu-gcc", "riscv64-unknown-linux-gnu-gcc"][..],
            "cannot compile restore-stub for riscv64: its restore tests will be \
             skipped. Install a riscv64 cross-compiler (e.g. riscv64-linux-gnu-gcc).",
        )
    } else {
        (
            &["cc"][..],
            "cannot compile restore-stub: its restore tests will be skipped.",
        )
    };
    build_static(
        &stub_src,
        &stub_bin,
        ccs,
        &[
            "-static",
            "-nostdlib",
            "-no-pie",
            "-O2",
            // Without these, loop-idiom recognition rewrites the stub's own
            // hand-written memset/memcpy bodies into calls to memset/memcpy,
            // i.e. into infinite self-recursion. There is no libc to fall back
            // on, so the stub must keep its byte loops as byte loops.
            "-ffreestanding",
            "-fno-tree-loop-distribute-patterns",
            "-Wl,-Ttext-segment=0x30000000000",
        ],
        warn,
    );
    // Emit the path every run (rustc-env is not cached across build-script runs),
    // whether or not the binary was just (re)built.
    println!("cargo:rustc-env=RESTORE_STUB_PATH={}", stub_bin.display());
}

/// Compile `src` to `bin` with the first working compiler in `ccs`, skipping the
/// work when `bin` is newer than `src`. Emits `warn` (as a cargo warning) if no
/// compiler succeeds. A missing source is silently skipped (packaged crate).
fn build_static(src: &Path, bin: &Path, ccs: &[&str], args: &[&str], warn: &str) {
    println!("cargo:rerun-if-changed={}", src.display());
    if !src.exists() {
        return;
    }
    if bin.exists() {
        if let (Ok(s), Ok(b)) = (src.metadata(), bin.metadata()) {
            if let (Ok(st), Ok(bt)) = (s.modified(), b.modified()) {
                if bt >= st {
                    return;
                }
            }
        }
    }
    for cc in ccs {
        let ok = Command::new(cc)
            .args(args)
            .arg("-o")
            .arg(bin)
            .arg(src)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return;
        }
    }
    println!("cargo:warning={warn}");
}
