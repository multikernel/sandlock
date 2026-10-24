#![cfg(feature = "image")]

//! Container images through the C ABI: `sandlock_image_pull` hands back
//! JSON that `sandlock_sandbox_builder_image` turns into a chrooted run.

use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::{c_char, c_int, c_uint};
use std::path::{Path, PathBuf};
use std::ptr;

use sandlock_ffi::{
    sandlock_image_pull, sandlock_result_free, sandlock_result_stderr, sandlock_result_stdout,
    sandlock_result_success, sandlock_run, sandlock_sandbox_build,
    sandlock_sandbox_builder_env_var, sandlock_sandbox_builder_image, sandlock_sandbox_builder_new,
    sandlock_sandbox_free, sandlock_sandbox_t, sandlock_string_free,
};

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn take_string(p: *mut c_char) -> String {
    assert!(!p.is_null());
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    unsafe { sandlock_string_free(p) };
    s
}

fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The static rootfs-helper that sandlock-core's build.rs compiles into its
/// OUT_DIR; that env is private to sandlock-core, so find it in the target dir.
fn helper_binary() -> PathBuf {
    let profile_dir = std::env::current_exe().unwrap();
    let profile_dir = profile_dir.parent().and_then(Path::parent).unwrap();
    fs::read_dir(profile_dir.join("build"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("sandlock-core-")
        })
        .map(|e| e.path().join("out/rootfs-helper"))
        .filter(|p| p.is_file())
        .max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok())
        .expect("rootfs-helper not found; sandlock-core's build.rs should have compiled it")
}

/// An OCI layout holding one image: the static rootfs-helper plus a config
/// that sets Env and a WorkingDir the layer does not contain.
fn helper_image_layout(dir: &Path) {
    let helper = fs::read(helper_binary()).unwrap();

    let mut layer = tar::Builder::new(Vec::new());
    for d in ["usr/", "usr/bin/", "proc/", "dev/", "tmp/"] {
        let mut h = tar::Header::new_gnu();
        h.set_path(d).unwrap();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o755);
        h.set_size(0);
        h.set_cksum();
        layer.append(&h, std::io::empty()).unwrap();
    }
    let mut h = tar::Header::new_gnu();
    h.set_path("usr/bin/rootfs-helper").unwrap();
    h.set_mode(0o755);
    h.set_size(helper.len() as u64);
    h.set_cksum();
    layer.append(&h, helper.as_slice()).unwrap();
    let layer = layer.into_inner().unwrap();

    let blobs = dir.join("blobs/sha256");
    fs::create_dir_all(&blobs).unwrap();
    let blob = |media_type: &str, data: &[u8]| {
        let hex = sha256_hex(data);
        fs::write(blobs.join(&hex), data).unwrap();
        serde_json::json!({"mediaType": media_type, "digest": format!("sha256:{hex}"), "size": data.len()})
    };
    let config = serde_json::json!({"config": {
        "Env": ["PATH=/usr/bin", "GREETING=from-image"],
        "WorkingDir": "/work/here",
        "Cmd": ["rootfs-helper", "pwd"],
    }});
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "config": blob("application/vnd.oci.image.config.v1+json", config.to_string().as_bytes()),
        "layers": [blob("application/vnd.oci.image.layer.v1.tar", &layer)],
    });
    let manifest = blob(
        "application/vnd.oci.image.manifest.v1+json",
        manifest.to_string().as_bytes(),
    );
    fs::write(
        dir.join("index.json"),
        serde_json::json!({"schemaVersion": 2, "manifests": [manifest]}).to_string(),
    )
    .unwrap();
}

fn pull(reference: &str, cache: &Path) -> Result<String, String> {
    let (r, c) = (cstr(reference), cstr(cache.to_str().unwrap()));
    let mut err: *mut c_char = ptr::null_mut();
    let json = unsafe { sandlock_image_pull(r.as_ptr(), c.as_ptr(), &mut err) };
    if json.is_null() {
        Err(take_string(err))
    } else {
        assert!(err.is_null());
        Ok(take_string(json))
    }
}

fn build(image_json: &str, env: &[(&str, &str)]) -> Result<*mut sandlock_sandbox_t, c_int> {
    let json = cstr(image_json);
    let mut b =
        unsafe { sandlock_sandbox_builder_image(sandlock_sandbox_builder_new(), json.as_ptr()) };
    for (k, v) in env {
        let (k, v) = (cstr(k), cstr(v));
        b = unsafe { sandlock_sandbox_builder_env_var(b, k.as_ptr(), v.as_ptr()) };
    }
    let mut err: c_int = 0;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, &mut err_msg) };
    if !err_msg.is_null() {
        unsafe { sandlock_string_free(err_msg) };
    }
    if policy.is_null() {
        Err(err)
    } else {
        Ok(policy)
    }
}

fn run(policy: *mut sandlock_sandbox_t, argv: &[&str]) -> (bool, String, String) {
    let owned: Vec<CString> = argv.iter().map(|s| cstr(s)).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    let r = unsafe { sandlock_run(policy, ptr::null(), ptrs.as_ptr(), ptrs.len() as c_uint) };
    assert!(!r.is_null(), "sandlock_run returned null");
    let out = (
        unsafe { sandlock_result_success(r) },
        take_string(unsafe { sandlock_result_stdout(r) }),
        take_string(unsafe { sandlock_result_stderr(r) }),
    );
    unsafe { sandlock_result_free(r) };
    out
}

#[test]
fn pulled_image_runs_with_its_env_and_working_dir() {
    let layout = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    helper_image_layout(layout.path());

    let json = pull(&format!("oci:{}", layout.path().display()), cache.path()).unwrap();
    let image: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(Path::new(image["rootfs"].as_str().unwrap())
        .join("usr/bin/rootfs-helper")
        .is_file());
    assert_eq!(
        image["config"]["cmd"],
        serde_json::json!(["rootfs-helper", "pwd"])
    );
    assert_eq!(image["config"]["working_dir"], "/work/here");

    let policy = build(&json, &[]).unwrap();
    let (ok, stdout, stderr) = run(policy, &["rootfs-helper", "pwd"]);
    assert!(ok, "pwd failed: {stderr}");
    assert_eq!(stdout.trim(), "/work/here");
    unsafe { sandlock_sandbox_free(policy) };

    // /proc/self/environ is not readable under chroot, so check the env the
    // C ABI recorded on the built sandbox instead.
    let env = |extra: &[(&str, &str)]| {
        let json = cstr(&json);
        let mut b = unsafe {
            sandlock_sandbox_builder_image(sandlock_sandbox_builder_new(), json.as_ptr())
        };
        for (k, v) in extra {
            let (k, v) = (cstr(k), cstr(v));
            b = unsafe { sandlock_sandbox_builder_env_var(b, k.as_ptr(), v.as_ptr()) };
        }
        unsafe { *Box::from_raw(b) }.build().unwrap().env.clone()
    };
    assert_eq!(env(&[])["GREETING"], "from-image");
    assert_eq!(env(&[("GREETING", "explicit")])["GREETING"], "explicit");
}

#[test]
fn pull_failure_reports_why() {
    let cache = tempfile::tempdir().unwrap();
    let err = pull("oci:/nonexistent/layout", cache.path()).unwrap_err();
    assert!(err.contains("not an OCI image layout"), "{err}");
}

#[test]
fn malformed_image_json_fails_the_build() {
    // Dropping the image silently would run the command on the host tree.
    assert!(build("{not json", &[]).is_err());
    assert!(build(r#"{"config": {}}"#, &[]).is_err());
    let b = unsafe { sandlock_sandbox_builder_image(sandlock_sandbox_builder_new(), ptr::null()) };
    assert!(b.is_null());
}
