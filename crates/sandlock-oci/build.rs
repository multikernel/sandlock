use std::process::Command;

fn main() {
    // Build sandlock-init statically (crt-static) for the HOST target so it runs
    // inside an empty chroot without a dynamic loader. No musl target needed:
    // sandlock-init is pure Rust + libc (no NSS/DNS), so static glibc is fine.
    // A separate --target-dir avoids contending the outer build's target lock.
    let out = std::env::var("OUT_DIR").unwrap();
    let host = std::env::var("HOST").unwrap();
    let init_target_dir = format!("{}/init-build", out);
    // Build for the HOST triple explicitly. Naming the target keeps crt-static
    // off the host-built proc-macros (serde_derive cannot be a static cdylib)
    // and applies it only to the sandlock-init binary and its target deps.
    // Cargo also exports CARGO_ENCODED_RUSTFLAGS into the build-script
    // environment, and it takes precedence over RUSTFLAGS for the nested cargo;
    // remove it so our crt-static flag is the one that applies.
    let status = Command::new(env!("CARGO"))
        .args([
            "build", "--release", "-p", "sandlock-init", "--bin", "sandlock-init",
            "--target", &host,
            "--target-dir", &init_target_dir,
        ])
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .status()
        .expect("build sandlock-init");
    assert!(status.success(), "failed to build sandlock-init");
    let bin = format!("{}/{}/release/sandlock-init", init_target_dir, host);
    println!("cargo:rustc-env=SANDLOCK_INIT_BIN={}", bin);
    println!("cargo:rerun-if-changed=../sandlock-init/src");
}
