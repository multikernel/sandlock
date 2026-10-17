//! Compile and run the pure-C smoke test against the cdylib.

#[test]
fn c_smoke_compiles_and_runs() {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::process::Command;

    let out_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let bin = out_dir.join("handler_smoke");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    // Cargo links integration tests against the crate's *rlib*, and does not
    // treat the *cdylib* as a build prerequisite — so `cargo test` never
    // (re)builds `libsandlock_ffi.so`. Build it ourselves so we always link the
    // current artifact instead of a stale one left in `target/` (which fails
    // with "undefined reference" when the symbol set has changed). `--lib`
    // builds the cdylib/staticlib/rlib; the recursive `cargo` is safe because
    // the outer build lock is released before tests run.
    let mut build = Command::new(env!("CARGO"));
    build.args(["build", "-p", "sandlock-ffi", "--lib"]);
    build.arg("--no-default-features");
    for (name, enabled) in [
        ("http", cfg!(feature = "http")),
        ("checkpoint", cfg!(feature = "checkpoint")),
        ("image", cfg!(feature = "image")),
        ("profiles", cfg!(feature = "profiles")),
        ("cow", cfg!(feature = "cow")),
    ] {
        if enabled {
            build.args(["--features", name]);
        }
    }
    if profile == "release" {
        build.arg("--release");
    }
    let build_status = build.status().expect("invoke cargo build for cdylib");
    assert!(
        build_status.success(),
        "failed to build sandlock-ffi cdylib"
    );

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

    struct Library(*mut libc::c_void);
    impl Drop for Library {
        fn drop(&mut self) {
            unsafe { libc::dlclose(self.0) };
        }
    }

    let library_path = CString::new(cdylib_dir.join("libsandlock_ffi.so").as_os_str().as_bytes())
        .expect("library path has no NUL bytes");
    let handle = unsafe { libc::dlopen(library_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let error = unsafe { libc::dlerror() };
        let message = if error.is_null() {
            "unknown loader error".into()
        } else {
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned()
        };
        panic!("failed to load FFI library: {message}");
    }
    let library = Library(handle);
    for (symbol, enabled) in [
        ("sandlock_sandbox_builder_image", cfg!(feature = "image")),
        ("sandlock_image_pull", cfg!(feature = "image")),
        ("sandlock_handle_checkpoint", cfg!(feature = "checkpoint")),
        ("sandlock_checkpoint_save", cfg!(feature = "checkpoint")),
        ("sandlock_checkpoint_load", cfg!(feature = "checkpoint")),
        ("sandlock_checkpoint_set_name", cfg!(feature = "checkpoint")),
        ("sandlock_checkpoint_name", cfg!(feature = "checkpoint")),
        (
            "sandlock_checkpoint_set_app_state",
            cfg!(feature = "checkpoint"),
        ),
        (
            "sandlock_checkpoint_app_state",
            cfg!(feature = "checkpoint"),
        ),
        ("sandlock_checkpoint_free", cfg!(feature = "checkpoint")),
        ("sandlock_restore_interactive", cfg!(feature = "checkpoint")),
        (
            "sandlock_handle_restore_skipped_len",
            cfg!(feature = "checkpoint"),
        ),
        (
            "sandlock_handle_restore_skipped_fd",
            cfg!(feature = "checkpoint"),
        ),
        (
            "sandlock_handle_restore_skipped_path",
            cfg!(feature = "checkpoint"),
        ),
    ] {
        let name = CString::new(symbol).unwrap();
        let exported = !unsafe { libc::dlsym(library.0, name.as_ptr()) }.is_null();
        assert_eq!(exported, enabled, "unexpected export state for {symbol}");
    }

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
