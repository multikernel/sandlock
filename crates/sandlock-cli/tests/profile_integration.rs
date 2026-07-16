use std::process::Command;

fn sandlock_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sandlock"))
}

/// The `[filesystem]` `read` list for a test profile, including `/lib64` only
/// when the host has it. RISC-V glibc and musl have no `/lib64` (the loader
/// lives under `/lib`), and a profile `read` entry is a mandatory grant, so
/// requiring `/lib64` on such a host aborts confinement. Mirrors
/// `fs_read_if_exists` for the profile layer.
fn read_list() -> &'static str {
    if std::path::Path::new("/lib64").exists() {
        r#"read = ["/usr", "/lib", "/lib64", "/bin", "/etc"]"#
    } else {
        r#"read = ["/usr", "/lib", "/bin", "/etc"]"#
    }
}

#[test]
fn profile_program_section_supplies_command() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_path = tmp.path().join("p.toml");
    std::fs::write(&profile_path, format!(r#"
        [program]
        exec = "/bin/true"

        [filesystem]
        {read}
    "#, read = read_list())).unwrap();

    let out = sandlock_bin()
        .args(["run", "--profile-file", profile_path.to_str().unwrap()])
        .output()
        .expect("spawn sandlock");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn trailing_command_overrides_profile_program_section() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_path = tmp.path().join("p.toml");
    // Profile says exec = "/bin/false" — should be overridden by CLI command.
    std::fs::write(&profile_path, format!(r#"
        [program]
        exec = "/bin/false"

        [filesystem]
        {read}
    "#, read = read_list())).unwrap();

    let out = sandlock_bin()
        .args(["run", "--profile-file", profile_path.to_str().unwrap(), "--", "/bin/true"])
        .output()
        .expect("spawn sandlock");

    assert!(out.status.success(), "trailing command /bin/true should win over profile's /bin/false; stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn profile_with_args_are_passed_to_command() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_path = tmp.path().join("p.toml");
    std::fs::write(&profile_path, format!(r#"
        [program]
        exec = "/bin/sh"
        args = ["-c", "exit 0"]

        [filesystem]
        {read}
    "#, read = read_list())).unwrap();

    let out = sandlock_bin()
        .args(["run", "--profile-file", profile_path.to_str().unwrap()])
        .output()
        .expect("spawn sandlock");

    assert!(out.status.success(), "profile-supplied args should work; stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn missing_exec_and_no_trailing_command_is_error() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_path = tmp.path().join("p.toml");
    // Profile has no [program] section at all.
    std::fs::write(&profile_path, r#"
        [filesystem]
        read = ["/usr"]
    "#).unwrap();

    let out = sandlock_bin()
        .args(["run", "--profile-file", profile_path.to_str().unwrap()])
        .output()
        .expect("spawn sandlock");

    assert!(!out.status.success(), "should fail when no command source is available");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no command") || stderr.contains("exec"),
        "error message should mention missing command; stderr: {}", stderr
    );
}

#[test]
fn profile_by_name_loads_program_section() {
    let tmp = tempfile::tempdir().unwrap();
    // Sandlock's profile_dir() honors XDG_CONFIG_HOME if set.
    let profiles_dir = tmp.path().join("sandlock").join("profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    let profile_path = profiles_dir.join("by-name-test.toml");
    std::fs::write(&profile_path, format!(r#"
        [program]
        exec = "/bin/true"

        [filesystem]
        {read}
    "#, read = read_list())).unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sandlock"))
        .env("XDG_CONFIG_HOME", tmp.path())
        .args(["run", "--profile", "by-name-test"])
        .output()
        .expect("spawn sandlock");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn no_supervisor_rejects_supervisor_only_profile_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_path = tmp.path().join("p.toml");
    std::fs::write(&profile_path, format!(r#"
        [program]
        exec = "/bin/true"

        [filesystem]
        {read}

        [network]
        allow = ["example.com:443"]
    "#, read = read_list())).unwrap();

    let out = sandlock_bin()
        .args(["run", "--no-supervisor", "--profile-file", profile_path.to_str().unwrap()])
        .output()
        .expect("spawn sandlock");

    assert!(!out.status.success(), "--no-supervisor should reject network rules from profiles");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--no-supervisor") && stderr.contains("[network].allow"),
        "stderr should explain incompatible profile field; stderr: {}",
        stderr,
    );
}
