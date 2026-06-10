use super::*;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[test]
fn run_as_parses_uid_and_gid() {
    let r = RunAs::from_str("1000:2000").unwrap();
    assert_eq!(r.uid, 1000);
    assert_eq!(r.gid, 2000);
}

#[test]
fn run_as_requires_both_ids() {
    // A bare UID (no `:GID`) is rejected — gid is not defaulted.
    assert!(RunAs::from_str("1000").is_err());
}

#[test]
fn run_as_rejects_garbage() {
    assert!(RunAs::from_str("root").is_err());
    assert!(RunAs::from_str("1000:abc").is_err());
    assert!(RunAs::from_str("").is_err());
}

#[test]
fn resolve_sandbox_path_plain() {
    let r = resolve_sandbox_path_to_host(Path::new("/etc/ssl/x.pem"), None, &[]);
    assert_eq!(r, PathBuf::from("/etc/ssl/x.pem"));
}

#[test]
fn resolve_sandbox_path_under_chroot() {
    let r = resolve_sandbox_path_to_host(
        Path::new("/etc/ssl/x.pem"),
        Some(Path::new("/srv/root")),
        &[],
    );
    assert_eq!(r, PathBuf::from("/srv/root/etc/ssl/x.pem"));
}

#[test]
fn resolve_sandbox_path_mount_takes_precedence() {
    let mounts = vec![(PathBuf::from("/etc/ssl"), PathBuf::from("/host/ssl"))];
    let r = resolve_sandbox_path_to_host(
        Path::new("/etc/ssl/x.pem"),
        Some(Path::new("/srv/root")),
        &mounts,
    );
    assert_eq!(r, PathBuf::from("/host/ssl/x.pem"));
}

#[tokio::test]
async fn inject_ca_nonexistent_path_errors_at_run() {
    // Wildcard host rule avoids DNS; the missing inject path must error
    // before any fork or network work.
    let mut policy = Sandbox::builder()
        .http_allow("GET */*")
        .http_inject_ca("/definitely/not/here/sandlock-bundle.pem")
        .build()
        .unwrap();
    let res = policy.run(&["true"]).await;
    assert!(res.is_err(), "expected error for missing --http-inject-ca path");
}

// --- SandboxBuilder integration ---

#[test]
fn builder_http_rules() {
    let policy = Sandbox::builder()
        .http_allow("GET api.example.com/v1/*")
        .http_deny("* */admin/*")
        .build()
        .unwrap();
    assert_eq!(policy.http_allow.len(), 1);
    assert_eq!(policy.http_deny.len(), 1);
    assert_eq!(policy.http_allow[0].method, "GET");
    assert_eq!(policy.http_deny[0].host, "*");
}

#[test]
fn builder_invalid_http_allow_returns_error() {
    let result = Sandbox::builder()
        .http_allow("GETexample.com")
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_invalid_http_deny_returns_error() {
    let result = Sandbox::builder()
        .http_deny("BADRULE")
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_http_ca_without_key_returns_error() {
    let result = Sandbox::builder()
        .http_ca("/tmp/ca.pem")
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_http_key_without_ca_returns_error() {
    let result = Sandbox::builder()
        .http_key("/tmp/key.pem")
        .build();
    assert!(result.is_err());
}

#[test]
fn builder_http_ca_and_key_together_ok() {
    let policy = Sandbox::builder()
        .http_ca("/tmp/ca.pem")
        .http_key("/tmp/key.pem")
        .build()
        .unwrap();
    assert!(policy.http_ca.is_some());
    assert!(policy.http_key.is_some());
}

#[test]
fn inject_ca_adds_443_and_requires_http_rule() {
    // No http rule -> error.
    let err = Sandbox::builder()
        .http_inject_ca("/etc/ssl/certs/ca-certificates.crt")
        .build();
    assert!(err.is_err());

    // With an http rule -> ok, and 443 is intercepted.
    let policy = Sandbox::builder()
        .http_allow("GET example.com/*")
        .http_inject_ca("/etc/ssl/certs/ca-certificates.crt")
        .build()
        .unwrap();
    assert!(policy.http_ports.contains(&443));
    assert_eq!(policy.http_inject_ca.len(), 1);
}

#[test]
fn http_ca_out_requires_trigger() {
    let err = Sandbox::builder()
        .http_allow("GET example.com/*")
        .http_ca_out("/tmp/out.pem")
        .build();
    assert!(err.is_err());

    let ok = Sandbox::builder()
        .http_allow("GET example.com/*")
        .http_inject_ca("/etc/ssl/certs/ca-certificates.crt")
        .http_ca_out("/tmp/out.pem")
        .build();
    assert!(ok.is_ok());
}

#[test]
fn allows_sysv_ipc_reads_extra_allow_syscalls() {
    let p = Sandbox::builder()
        .extra_allow_syscalls(vec!["sysv_ipc".into()])
        .build()
        .unwrap();
    assert!(p.allows_sysv_ipc());

    let p2 = Sandbox::builder().build().unwrap();
    assert!(!p2.allows_sysv_ipc());

    let p3 = Sandbox::builder()
        .extra_allow_syscalls(vec!["other_group".into()])
        .build()
        .unwrap();
    assert!(!p3.allows_sysv_ipc());
}

#[test]
fn builder_parses_net_deny() {
    let policy = Sandbox::builder()
        .net_deny("10.0.0.0/8")
        .build()
        .unwrap();
    assert_eq!(policy.net_deny.len(), 1);
}

#[test]
fn builder_net_allow_bind_comma_and_ranges() {
    // Comma-separated ports and `lo-hi` ranges expand, sort, and dedup.
    let policy = Sandbox::builder()
        .net_allow_bind("8080,9000-9002")
        .net_allow_bind_port(443)
        .net_allow_bind("9001,443") // overlaps dedup away
        .build()
        .unwrap();
    assert_eq!(policy.net_allow_bind, vec![443, 8080, 9000, 9001, 9002]);
}

#[test]
fn builder_net_allow_bind_rejects_bad_specs() {
    assert!(Sandbox::builder().net_allow_bind("9000-8000").build().is_err()); // reversed
    assert!(Sandbox::builder().net_allow_bind("80,abc").build().is_err());    // bad port
    assert!(Sandbox::builder().net_allow_bind("70000").build().is_err());     // > u16
    assert!(Sandbox::builder().net_allow_bind("8080,").build().is_err());     // empty part
}

#[test]
fn builder_rejects_net_allow_and_net_deny_together() {
    let err = Sandbox::builder()
        .net_allow("github.com:443")
        .net_deny("10.0.0.0/8")
        .build();
    assert!(err.is_err());
}

#[test]
fn builder_net_deny_bind_comma_and_ranges() {
    // Same port grammar as --net-allow-bind (comma lists + lo-hi ranges).
    let policy = Sandbox::builder()
        .net_deny_bind("8080,9000-9002")
        .net_deny_bind_port(443)
        .build()
        .unwrap();
    assert_eq!(policy.net_deny_bind, vec![443, 8080, 9000, 9001, 9002]);
    assert!(policy.net_allow_bind.is_empty());
}

#[test]
fn builder_rejects_allow_bind_and_deny_bind_together() {
    let err = Sandbox::builder()
        .net_allow_bind("8080")
        .net_deny_bind("9090")
        .build();
    assert!(err.is_err());
    assert!(format!("{}", err.unwrap_err()).contains("mutually exclusive"));
}

#[test]
fn builder_net_deny_rejects_hostname() {
    let err = Sandbox::builder().net_deny("evil.com:443").build();
    assert!(err.is_err());
}

#[test]
fn net_deny_resolves_to_denylist_policies() {
    let policy = Sandbox::builder().net_deny("10.0.0.0/8").build().unwrap();
    let set = crate::network::resolve_net_deny(&policy.net_deny);
    assert!(!set.tcp.allows("10.0.0.5".parse().unwrap(), 443));
    assert!(set.tcp.allows("8.8.8.8".parse().unwrap(), 443));
}
