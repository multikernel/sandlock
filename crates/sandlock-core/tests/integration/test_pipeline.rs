use sandlock_core::policy::Policy;
use sandlock_core::pipeline::{Stage, Pipeline, Gather};
use std::time::Duration;

fn base_policy() -> Policy {
    Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_write("/tmp")
        .build()
        .unwrap()
}

// ============================================================
// Stage tests
// ============================================================

#[tokio::test]
async fn test_stage_run() {
    let policy = base_policy();
    let result = Stage::new(&policy, &["echo", "hello"]).run(None).await.unwrap();
    assert!(result.success());
}

#[tokio::test]
async fn test_stage_or_stage_returns_pipeline() {
    let policy = base_policy();
    let pipeline = Stage::new(&policy, &["echo", "hello"])
        | Stage::new(&policy, &["cat"]);
    assert_eq!(pipeline.stages.len(), 2);
}

#[tokio::test]
async fn test_stage_chaining() {
    let policy = base_policy();
    let pipeline = Stage::new(&policy, &["echo", "a"])
        | Stage::new(&policy, &["cat"])
        | Stage::new(&policy, &["cat"]);
    assert_eq!(pipeline.stages.len(), 3);
}

// ============================================================
// Pipeline tests
// ============================================================

#[tokio::test]
async fn test_two_stage_pipe() {
    let policy = base_policy();
    let result = (
        Stage::new(&policy, &["echo", "hello pipeline"])
        | Stage::new(&policy, &["cat"])
    ).run(None).await.unwrap();

    assert!(result.success());
    let stdout = result.stdout_str().unwrap_or("");
    assert!(stdout.contains("hello pipeline"), "got: {}", stdout);
}

#[tokio::test]
async fn test_three_stage_pipe() {
    let policy = base_policy();
    let result = (
        Stage::new(&policy, &["echo", "hello"])
        | Stage::new(&policy, &["tr", "a-z", "A-Z"])
        | Stage::new(&policy, &["cat"])
    ).run(None).await.unwrap();

    assert!(result.success());
    let stdout = result.stdout_str().unwrap_or("");
    assert!(stdout.contains("HELLO"), "got: {}", stdout);
}

#[tokio::test]
async fn test_disjoint_policies() {
    let tmp = std::env::temp_dir().join(format!("sandlock-test-pipeline-disjoint-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let secret = tmp.join("secret.txt");
    std::fs::write(&secret, "sensitive data").unwrap();

    // Stage 1: can read the temp dir
    let reader_policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_read(&tmp)
        .build()
        .unwrap();

    // Stage 2: cannot read the temp dir (only standard paths)
    let processor_policy = base_policy();

    let result = (
        Stage::new(&reader_policy, &["cat", secret.to_str().unwrap()])
        | Stage::new(&processor_policy, &["tr", "a-z", "A-Z"])
    ).run(None).await.unwrap();

    assert!(result.success());
    let stdout = result.stdout_str().unwrap_or("");
    assert!(stdout.contains("SENSITIVE DATA"), "got: {}", stdout);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn test_pipeline_captures_last_stderr() {
    let policy = base_policy();
    let result = (
        Stage::new(&policy, &["echo", "hello"])
        | Stage::new(&policy, &["sh", "-c", "cat >&2; echo stdout_line"])
    ).run(None).await.unwrap();

    assert!(result.success());
    let stderr = result.stderr_str().unwrap_or("");
    assert!(stderr.contains("hello"), "stderr should contain piped input, got: {}", stderr);
}

#[tokio::test]
async fn test_first_stage_failure() {
    let policy = base_policy();
    let result = (
        Stage::new(&policy, &["/nonexistent_binary_xyz"])
        | Stage::new(&policy, &["cat"])
    ).run(None).await.unwrap();

    // Last stage (cat) reads EOF → exits 0
    // The pipeline returns last stage's exit code
    let stdout = result.stdout_str().unwrap_or("");
    assert_eq!(stdout, "", "stdout should be empty when first stage fails");
}

#[tokio::test]
async fn test_last_stage_failure() {
    let policy = base_policy();
    let result = (
        Stage::new(&policy, &["echo", "hello"])
        | Stage::new(&policy, &["sh", "-c", "exit 42"])
    ).run(None).await.unwrap();

    assert!(!result.success());
    assert_eq!(result.code(), Some(42));
}

#[tokio::test]
async fn test_pipeline_requires_two_stages() {
    let policy = base_policy();
    let result = Pipeline::new(vec![Stage::new(&policy, &["echo"])]);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_pipeline_timeout() {
    let policy = base_policy();
    let result = (
        Stage::new(&policy, &["sleep", "60"])
        | Stage::new(&policy, &["cat"])
    ).run(Some(Duration::from_secs(1))).await.unwrap();

    assert!(!result.success());
}

// ============================================================
// XOA pattern tests
// ============================================================

#[tokio::test]
async fn test_xoa_data_flow() {
    let tmp = std::env::temp_dir().join(format!("sandlock-test-xoa-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let data_file = tmp.join("data.txt");
    std::fs::write(&data_file, "From: alice\nSubject: hello\n").unwrap();

    // Planner: no access to workspace, generates a script
    let planner_policy = base_policy();

    // Executor: can read workspace
    let executor_policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_read(&tmp)
        .build()
        .unwrap();

    // Planner emits a shell command that reads the data file
    let planner_cmd = format!("echo 'cat {}'", data_file.display());

    let result = (
        Stage::new(&planner_policy, &["sh", "-c", &planner_cmd])
        | Stage::new(&executor_policy, &["sh"])
    ).run(None).await.unwrap();

    assert!(result.success(), "exit={:?}", result.code());
    let stdout = result.stdout_str().unwrap_or("");
    assert!(stdout.contains("From: alice"), "got: {}", stdout);
    assert!(stdout.contains("Subject: hello"), "got: {}", stdout);

    let _ = std::fs::remove_dir_all(&tmp);
}

// ============================================================
// Gather tests
// ============================================================

#[tokio::test]
async fn test_gather_two_sources() {
    let policy = base_policy();
    // greeting → fd 3, name → stdin (last source)
    // Consumer: cat fd 3 first, then cat stdin
    let result = Gather::new()
        .source("greeting", Stage::new(&policy, &["echo", "hello"]))
        .source("name", Stage::new(&policy, &["echo", "world"]))
        .consumer(Stage::new(&policy, &["sh", "-c",
            "cat <&3; cat"
        ]))
        .run(None).await.unwrap();

    assert!(result.success(), "exit={:?} stderr={}", result.code(),
            result.stderr_str().unwrap_or(""));
    let stdout = result.stdout_str().unwrap_or("");
    assert!(stdout.contains("hello"), "missing greeting, got: {}", stdout);
    assert!(stdout.contains("world"), "missing name, got: {}", stdout);
}

#[tokio::test]
async fn test_gather_env_var() {
    let policy = base_policy();
    let result = Gather::new()
        .source("alpha", Stage::new(&policy, &["echo", "aaa"]))
        .source("beta", Stage::new(&policy, &["echo", "bbb"]))
        .consumer(Stage::new(&policy, &["sh", "-c",
            "echo $_SANDLOCK_GATHER"
        ]))
        .run(None).await.unwrap();

    assert!(result.success());
    let stdout = result.stdout_str().unwrap_or("");
    assert!(stdout.contains("alpha:"), "got: {}", stdout);
    assert!(stdout.contains("beta:"), "got: {}", stdout);
}

#[tokio::test]
async fn test_gather_disjoint_policies() {
    let tmp = std::env::temp_dir().join(format!("sandlock-test-gather-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let secret = tmp.join("secret.txt");
    std::fs::write(&secret, "secret data").unwrap();

    // Data source: can read the file
    let data_policy = Policy::builder()
        .fs_read("/usr").fs_read("/lib").fs_read_if_exists("/lib64").fs_read("/bin")
        .fs_read("/etc").fs_read("/proc").fs_read("/dev")
        .fs_read(&tmp)
        .build()
        .unwrap();

    // Code source: no access to tmp (like a planner)
    let code_policy = base_policy();

    // Consumer: no access to tmp either (gets data via pipe)
    let consumer_policy = base_policy();

    let result = Gather::new()
        .source("data", Stage::new(&data_policy, &[
            "cat", secret.to_str().unwrap()
        ]))
        .source("code", Stage::new(&code_policy, &[
            "echo", "tr a-z A-Z <&3"
        ]))
        .consumer(Stage::new(&consumer_policy, &[
            // code is on stdin, data is on fd 3
            "sh", "-c", "code=$(cat); eval \"$code\""
        ]))
        .run(None).await.unwrap();

    assert!(result.success(), "exit={:?} stderr={}", result.code(),
            result.stderr_str().unwrap_or(""));
    let stdout = result.stdout_str().unwrap_or("");
    assert!(stdout.contains("SECRET DATA"), "got: {}", stdout);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn test_gather_requires_consumer() {
    let policy = base_policy();
    let result = Gather::new()
        .source("a", Stage::new(&policy, &["echo", "hello"]))
        .run(None).await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_gather_requires_sources() {
    let policy = base_policy();
    let result = Gather::new()
        .consumer(Stage::new(&policy, &["cat"]))
        .run(None).await;

    assert!(result.is_err());
}
