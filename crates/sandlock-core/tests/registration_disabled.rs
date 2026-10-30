use sandlock_core::Sandbox;

fn sandbox(name: &str) -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/bin")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .build()
        .unwrap()
        .with_name(name)
}

async fn check_registration(no_supervisor: bool) {
    let name = format!("test-registration-{}-{no_supervisor}", std::process::id());
    let mut private = sandbox(&name);
    private.registration = false;
    private.no_supervisor = no_supervisor;
    private.create(&["sleep", "30"]).await.unwrap();
    assert!(!sandlock_core::control::list_sandboxes()
        .unwrap()
        .contains(&name));

    let mut registered = sandbox(&name);
    registered.no_supervisor = no_supervisor;
    registered.create(&["sleep", "30"]).await.unwrap();
    assert!(sandlock_core::control::list_sandboxes()
        .unwrap()
        .contains(&name));

    let result = private.clone().run(&["true"]).await.unwrap();
    assert!(result.success());
    let error = sandbox(&name).create(&["true"]).await.unwrap_err();
    assert!(error.to_string().contains("already running"));

    private.kill().unwrap();
    registered.kill().unwrap();
}

#[tokio::test]
async fn registration_is_per_sandbox() {
    check_registration(false).await;
}

#[tokio::test]
async fn registration_is_per_sandbox_without_supervisor() {
    check_registration(true).await;
}

#[test]
fn registration_is_not_serialized_policy() {
    let builder = Sandbox::builder().registration(false);
    let sandbox = builder.clone().build().unwrap();
    assert!(!sandbox.registration);
    let mut policy = serde_json::to_value(&sandbox).unwrap();
    assert!(policy.get("registration").is_none());
    policy["registration"] = false.into();
    let restored: Sandbox = serde_json::from_value(policy).unwrap();
    assert!(restored.registration);
}

#[cfg(feature = "cli")]
#[test]
fn cli_builder_registers_by_default() {
    use clap::{Args, FromArgMatches};
    use sandlock_core::sandbox::SandboxBuilder;

    let matches =
        SandboxBuilder::augment_args(clap::Command::new("test")).get_matches_from(["test"]);
    let sandbox = SandboxBuilder::from_arg_matches(&matches)
        .unwrap()
        .build()
        .unwrap();
    assert!(sandbox.registration);
}
