use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../..").canonicalize().unwrap();

    // rootfs-helper: an ordinary static-libc test fixture (chroot tests). It
    // lives in tests/ and its binary sits beside it (a git-ignored artifact).
    if !build_static(
        &repo_root.join("tests/rootfs-helper.c"),
        &repo_root.join("tests/rootfs-helper"),
        &["musl-gcc", "cc"],
        &["-static", "-O2"],
    ) {
        println!(
            "cargo:warning=cannot compile tests/rootfs-helper: chroot tests will \
             fail. Install musl-tools or static libc."
        );
    }

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
    let host = std::env::var("HOST").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();
    let is_riscv64 = target.starts_with("riscv64");
    // Checkpoint restore is claimed only on x86_64 and riscv64 (see
    // `restore_interactive`); on those arches a stub build failure is fatal, not
    // a silent skip — a green build with no stub is how regressions slip past CI.
    let is_restore_arch = target.starts_with("x86_64") || is_riscv64;
    let (ccs, fail_msg) = if is_riscv64 {
        if host.starts_with("riscv64") {
            (
                &["cc", "riscv64-linux-gnu-gcc", "riscv64-unknown-linux-gnu-gcc"][..],
                "failed to compile restore-stub for riscv64: no working C compiler \
                 (install gcc); checkpoint restore is unavailable",
            )
        } else {
            (
                &["riscv64-linux-gnu-gcc", "riscv64-unknown-linux-gnu-gcc"][..],
                "failed to compile restore-stub for riscv64: no working cross-compiler \
                 (install riscv64-linux-gnu-gcc); checkpoint restore is unavailable",
            )
        }
    } else {
        (
            &["cc"][..],
            "failed to compile restore-stub: no working C compiler \
             (install cc/gcc); checkpoint restore is unavailable",
        )
    };
    // The link address must match restore_blob::STUB_BASE and must sit below
    // the Sv39 user ceiling (256 GiB) on riscv64.  x86_64 uses 0x300_0000_0000.
    let text_segment = if is_riscv64 {
        "-Wl,-Ttext-segment=0x3000000000"
    } else {
        "-Wl,-Ttext-segment=0x30000000000"
    };
    if !build_static(
        &stub_src,
        &stub_bin,
        ccs,
        &[
            "-static",
            "-nostdlib",
            "-no-pie",
            "-O2",
            "-ffreestanding",
            "-fno-tree-loop-distribute-patterns",
            // A compiler with default SSP (vanilla GCC; Ubuntu's exempts
            // -ffreestanding) reads the canary at %fs:0x28, and the stub's
            // thread pointer is zero until it restores the checkpoint's.
            "-fno-stack-protector",
            text_segment,
        ],
    ) {
        if is_restore_arch {
            panic!("{fail_msg}");
        }
        println!("cargo:warning={fail_msg}");
    }
    // Emit the path every run (rustc-env is not cached across build-script runs),
    // whether or not the binary was just (re)built.
    println!("cargo:rustc-env=RESTORE_STUB_PATH={}", stub_bin.display());
}

/// Compile `src` to `bin` with the first working compiler in `ccs`, skipping the
/// work when `bin` is newer than both `src` and this build script (the flags
/// live here, so a flag change must recompile). Returns `false` only when the
/// source is present, stale, and no compiler in `ccs` succeeded; a missing
/// source (a packaged crate) or an up-to-date `bin` reports success. The caller
/// decides whether that failure is a hard error or a warning.
fn build_static(src: &Path, bin: &Path, ccs: &[&str], args: &[&str]) -> bool {
    println!("cargo:rerun-if-changed={}", src.display());
    if !src.exists() {
        return true;
    }
    let mtime = |p: &Path| p.metadata().and_then(|m| m.modified()).ok();
    let build_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs");
    if let (Some(bt), Some(st), Some(rt)) = (mtime(bin), mtime(src), mtime(&build_rs)) {
        if bt >= st && bt >= rt {
            return true;
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
            return true;
        }
    }
    false
}
