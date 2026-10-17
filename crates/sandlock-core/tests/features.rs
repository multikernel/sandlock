use sandlock_core::Sandbox;

#[test]
fn json_policy_inspection_is_available() {
    let sandbox = Sandbox::builder()
        .fs_read("/usr")
        .build_unchecked()
        .unwrap();
    let json = sandlock_core::profile::sandbox_to_json(&sandbox, &[]).unwrap();
    assert!(json.contains("/usr"));
}

#[cfg(not(feature = "profiles"))]
#[test]
fn toml_profiles_require_the_feature() {
    let error = sandlock_core::profile::parse_profile("[filesystem]\nread = ['/usr']").unwrap_err();
    assert!(matches!(
        error,
        sandlock_core::SandlockError::Sandbox(
            sandlock_core::error::SandboxError::FeatureDisabled {
                feature: "profiles",
                ..
            }
        )
    ));
}

#[cfg(not(feature = "cow"))]
#[test]
fn cow_configuration_requires_the_feature() {
    use sandlock_core::sandbox::{BranchAction, ByteSize};
    for builder in [
        Sandbox::builder().workdir("/tmp"),
        Sandbox::builder().fs_storage("/tmp"),
        Sandbox::builder().max_disk(ByteSize(1024)),
        Sandbox::builder().on_exit(BranchAction::Abort),
        Sandbox::builder().on_error(BranchAction::Keep),
    ] {
        assert!(matches!(
            builder.build_unchecked(),
            Err(sandlock_core::error::SandboxError::FeatureDisabled { feature: "cow", .. })
        ));
    }
}

#[cfg(not(feature = "cow"))]
#[tokio::test]
async fn deserialized_cow_policy_is_rejected_before_spawn() {
    let sandbox = Sandbox::builder().build_unchecked().unwrap();
    let mut json = serde_json::to_value(&sandbox).unwrap();
    json["workdir"] = serde_json::json!("/tmp");
    let mut sandbox: Sandbox = serde_json::from_value(json).unwrap();
    let error = sandbox
        .create_interactive(&["/bin/true"])
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error,
        sandlock_core::SandlockError::Sandbox(
            sandlock_core::error::SandboxError::FeatureDisabled { feature: "cow", .. }
        )
    ));
}
