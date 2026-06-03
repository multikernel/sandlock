// Verifies http_inject_ca splices the generated CA into a declared trust
// bundle as seen by the workload. When the sandbox has HTTP ACL rules plus an
// inject-ca path, the seccomp openat handler returns a memfd containing the
// original file contents followed by the CA public cert. Running `cat` on the
// declared bundle therefore prints the sentinel original content plus a
// BEGIN CERTIFICATE block. Requires a Landlock-capable kernel.

use sandlock_core::Sandbox;

#[tokio::test]
async fn inject_ca_appends_to_declared_bundle() {
    let dir = std::env::temp_dir().join(format!(
        "sandlock-test-inject-ca-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let bundle = dir.join("bundle.pem");
    std::fs::write(&bundle, b"ORIGINAL-BUNDLE\n").unwrap();
    let bundle_str = bundle.to_str().unwrap().to_string();

    let policy = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(dir.to_str().unwrap())
        .http_allow("GET */*")
        .http_inject_ca(bundle_str.clone())
        .build()
        .unwrap();

    let result = policy
        .clone()
        .with_name("test")
        .run(&["cat", &bundle_str])
        .await
        .unwrap();
    assert!(result.success(), "cat should succeed, exit={:?}", result.code());

    let out = String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default());
    assert!(
        out.contains("ORIGINAL-BUNDLE"),
        "original bundle content preserved, got: {out}"
    );
    assert!(
        out.contains("BEGIN CERTIFICATE"),
        "CA cert appended to bundle, got: {out}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
