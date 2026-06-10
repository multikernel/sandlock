//! Compile and run the pure-C smoke test against the cdylib.

#[test]
fn c_smoke_compiles_and_runs() {
    use std::path::PathBuf;
    use std::process::Command;

    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let bin = out_dir.join("handler_smoke");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("target")
        });
    let profile_dir = target_dir.join(profile);
    let cdylib_dir = [
        profile_dir.clone(),
        profile_dir.join("deps"),
        target_dir.join("release"),
        target_dir.join("release").join("deps"),
    ]
    .into_iter()
    .find(|dir| {
        dir.join("libsandlock_ffi.so").exists() || dir.join("libsandlock_ffi.dylib").exists()
    })
    .expect("libsandlock_ffi cdylib should exist in target output");

    let rpath_arg = format!("-Wl,-rpath,{}", cdylib_dir.to_str().unwrap());

    let status = Command::new("cc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            concat!(env!("CARGO_MANIFEST_DIR"), "/include"),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/c/handler_smoke.c"),
            "-L",
            cdylib_dir.to_str().unwrap(),
            &rpath_arg,
            "-lsandlock_ffi",
            "-o",
            bin.to_str().unwrap(),
        ])
        .status()
        .expect("cc invocation");
    assert!(status.success(), "C compile failed");

    let out = Command::new(&bin).output().expect("run handler_smoke");
    assert!(
        out.status.success(),
        "handler_smoke exited non-zero: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
