//! Integration tests for the `sandlock_profile_parse` C ABI export.
//!
//! These drive the FFI symbol directly and assert on the JSON body, not just
//! on "not null": the whole point of the export is that the caller receives
//! resolved values (structured mounts, integer bytes, epoch seconds) rather
//! than the profile's string micro-grammars.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

use sandlock_ffi::{sandlock_profile_parse, sandlock_string_free};

/// Call the export and take ownership of whatever it produced.
///
/// Returns `(json, err, err_msg)` with both strings copied out and the
/// originals released, so a leak in the test itself cannot mask one in the
/// implementation.
fn call(toml: &str) -> (Option<String>, c_int, Option<String>) {
    let c = CString::new(toml).unwrap();
    let mut err: c_int = 7; // poison: the export must write this
    let mut err_msg: *mut c_char = ptr::null_mut();
    let raw = unsafe { sandlock_profile_parse(c.as_ptr(), &mut err, &mut err_msg) };

    let json = if raw.is_null() {
        None
    } else {
        let s = unsafe { CStr::from_ptr(raw) }.to_str().unwrap().to_owned();
        unsafe { sandlock_string_free(raw) };
        Some(s)
    };
    let msg = if err_msg.is_null() {
        None
    } else {
        let s = unsafe { CStr::from_ptr(err_msg) }
            .to_str()
            .unwrap()
            .to_owned();
        unsafe { sandlock_string_free(err_msg) };
        Some(s)
    };
    (json, err, msg)
}

fn parse_ok(toml: &str) -> serde_json::Value {
    let (json, err, msg) = call(toml);
    assert_eq!(err, 0, "expected success, err_msg: {msg:?}");
    assert!(msg.is_none(), "success must not set err_msg: {msg:?}");
    serde_json::from_str(&json.expect("success must return a string")).unwrap()
}

fn parse_err(toml: &str) -> String {
    let (json, err, msg) = call(toml);
    assert_eq!(err, -1, "expected failure, got json: {json:?}");
    assert!(json.is_none(), "failure must return null");
    msg.expect("failure must set err_msg")
}

#[test]
fn valid_profile_returns_resolved_json() {
    let v = parse_ok(
        r#"
        [program]
        exec = "/usr/bin/redis-cli"
        args = ["-h", "cache.internal"]

        [determinism]
        time_start = "2026-01-01T00:00:00Z"

        [filesystem]
        mount = ["/data:/srv/data:ro"]

        [network]
        allow_bind = [8080, "9000-9001"]
        allow = ["tcp://cache.internal:6379"]

        [limits]
        memory = "512M"
    "#,
    );

    // Mounts come back structured, not as `V:H:ro` spec strings.
    assert_eq!(
        v["filesystem"]["mount"],
        serde_json::json!([{"virt": "/data", "host": "/srv/data", "ro": true}])
    );
    // Sizes come back as integer bytes.
    assert_eq!(v["limits"]["memory"], serde_json::json!(536870912u64));
    // time_start comes back as epoch time.
    assert_eq!(
        v["determinism"]["time_start"],
        serde_json::json!({"seconds": 1767225600i64, "nanoseconds": 0})
    );
    // Bind port ranges come back expanded.
    assert_eq!(
        v["network"]["allow_bind"],
        serde_json::json!({"any": false, "ports": [8080, 9000, 9001]})
    );
    // Net rules come back structured, with a spec string for the builder ABI.
    assert_eq!(
        v["network"]["allow"][0],
        serde_json::json!({
            "protocol": "tcp",
            "target": {"kind": "host", "host": "cache.internal"},
            "ports": [6379],
            "all_ports": false,
            "spec": "tcp://cache.internal:6379",
        })
    );
    // Program identity survives.
    assert_eq!(
        v["program"]["exec"],
        serde_json::json!("/usr/bin/redis-cli")
    );
    assert_eq!(
        v["program"]["args"],
        serde_json::json!(["-h", "cache.internal"])
    );
}

#[test]
fn empty_profile_is_a_success_not_a_failure() {
    let v = parse_ok("");
    assert_eq!(v["filesystem"]["mount"], serde_json::json!([]));
    assert!(v["limits"]["memory"].is_null());
}

#[test]
fn unknown_key_is_reported_with_a_message() {
    let msg = parse_err("[program]\nexec = \"/bin/true\"\nbogus = 1");
    assert!(msg.contains("unknown field"), "got: {msg}");
    assert!(msg.contains("bogus"), "got: {msg}");
}

#[test]
fn grammar_errors_carry_the_core_message() {
    assert!(parse_err("[limits]\nmemory = \"1.5G\"").contains("invalid byte size: 1.5G"));
    assert!(parse_err("[filesystem]\nmount = [\"nocolon\"]").contains("VIRTUAL:HOST"));
    assert!(parse_err("[determinism]\ntime_start = \"nope\"").contains("time_start"));
    assert!(parse_err("[network]\nallow = [\"example.com:0\"]").contains("port 0 is not valid"));
}

#[test]
fn invalid_toml_is_reported() {
    assert!(parse_err("[program").contains("TOML parse error"));
}

#[test]
fn null_toml_sets_err_but_no_message() {
    let mut err: c_int = 7;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let raw = unsafe { sandlock_profile_parse(ptr::null(), &mut err, &mut err_msg) };
    assert!(raw.is_null());
    assert_eq!(err, -1);
    // A null profile is a binding-layer bug, not a profile problem: there is
    // no user-actionable message, and inventing one in this layer would be
    // wrong.
    assert!(err_msg.is_null(), "err_msg must stay null");
}

#[test]
fn invalid_utf8_is_rejected_rather_than_read_as_empty() {
    // A lossy decode would report a truncated (or empty) profile as valid.
    let bytes = b"[program]\nexec = \"/bin/\xff\"\0";
    let mut err: c_int = 7;
    let mut err_msg: *mut c_char = ptr::null_mut();
    let raw =
        unsafe { sandlock_profile_parse(bytes.as_ptr() as *const c_char, &mut err, &mut err_msg) };
    assert!(raw.is_null());
    assert_eq!(err, -1);
    assert!(!err_msg.is_null(), "decode failure must set err_msg");
    let msg = unsafe { CStr::from_ptr(err_msg) }
        .to_string_lossy()
        .into_owned();
    unsafe { sandlock_string_free(err_msg) };
    assert!(msg.contains("utf-8"), "got: {msg}");
}

#[test]
fn err_msg_is_cleared_before_each_call() {
    // A caller that reuses the variable must not be handed back a stale
    // pointer from the previous call, or it will double-free.
    let mut err: c_int = 0;
    let mut err_msg: *mut c_char = ptr::null_mut();

    let bad = CString::new("[program]\nbogus = 1").unwrap();
    let raw = unsafe { sandlock_profile_parse(bad.as_ptr(), &mut err, &mut err_msg) };
    assert!(raw.is_null());
    assert!(!err_msg.is_null());
    unsafe { sandlock_string_free(err_msg) };
    // Deliberately left dangling, as a careless caller would.

    let good = CString::new("[program]\nexec = \"/bin/true\"").unwrap();
    let raw = unsafe { sandlock_profile_parse(good.as_ptr(), &mut err, &mut err_msg) };
    assert!(!raw.is_null());
    assert_eq!(err, 0);
    assert!(
        err_msg.is_null(),
        "success must reset err_msg, not leave the previous pointer"
    );
    unsafe { sandlock_string_free(raw) };
}

#[test]
fn null_out_params_are_allowed() {
    let good = CString::new("[program]\nexec = \"/bin/true\"").unwrap();
    let raw = unsafe { sandlock_profile_parse(good.as_ptr(), ptr::null_mut(), ptr::null_mut()) };
    assert!(!raw.is_null(), "a null return always means failure");
    unsafe { sandlock_string_free(raw) };

    let bad = CString::new("[program]\nbogus = 1").unwrap();
    let raw = unsafe { sandlock_profile_parse(bad.as_ptr(), ptr::null_mut(), ptr::null_mut()) };
    assert!(raw.is_null());
}

#[test]
fn string_free_is_a_no_op_on_null() {
    unsafe { sandlock_string_free(ptr::null_mut()) };
}

/// A profile can smuggle a NUL into the *diagnostic*, because TOML decodes
/// `\u0000` and the message quotes the decoded value back. A C string cannot
/// carry one, and the caller must still be told what went wrong: reporting
/// `err = -1` with a null `err_msg` gives a Python or Go user a bare exception
/// with no text at all, and every one of these reaches the message through a
/// different formatter (`{}` on a byte-size error, a syscall name list, and
/// toml's own parse error).
#[test]
fn a_nul_in_the_diagnostic_is_escaped_not_dropped() {
    for (toml, needle) in [
        (
            r#"[limits]"#.to_string() + "\nmemory = \"1\\u0000G\"",
            "1\\0G",
        ),
        (
            r#"[syscalls]"#.to_string() + "\nextra_deny = [\"re\\u0000ad\"]",
            "re\\0ad",
        ),
        (
            r#"[limits]"#.to_string() + "\n\"bo\\u0000gus\" = 1",
            "bo\\0gus",
        ),
    ] {
        let msg = parse_err(&toml);
        assert!(
            msg.contains(needle),
            "diagnosis lost for {toml:?}; expected {needle:?} in {msg:?}"
        );
    }
}

/// The NUL only bothers the *message* path. When the profile is valid, the
/// value keeps its NUL and rides out in the JSON, where `\u0000` is an
/// ordinary escape: the C string stays intact and the consumer sees the whole
/// value rather than a prefix. `%00` in an HTTP rule gets there without any
/// TOML escape at all, since the path is percent-decoded.
#[test]
fn a_nul_inside_a_value_does_not_truncate_the_json() {
    let v = parse_ok("[http]\nallow = [\"GET example.com/a%00b\"]");
    assert_eq!(v["http"]["allow"][0]["path"], "/a\u{0}b");
    assert_eq!(v["http"]["allow"][0]["spec"], "GET example.com/a\u{0}b");
    // Truncation at the NUL would have dropped every later section.
    assert!(v["limits"].is_object(), "document was cut short: {v}");
}

/// Twelve combinations of (profile: null / valid / invalid) x (err: null /
/// non-null) x (err_msg: null / non-null). A binding written against the
/// header is allowed to discard either out-parameter, and none of those calls
/// may fault or leave a poisoned `err_msg` behind.
#[test]
fn every_out_param_combination_is_safe() {
    const POISON: *mut c_char = usize::MAX as *mut c_char;
    let valid = CString::new("[limits]\nmemory = \"1G\"").unwrap();
    let invalid = CString::new("[limits]\nbogus = 1").unwrap();

    for (label, toml, want_json) in [
        ("null", ptr::null(), false),
        ("valid", valid.as_ptr(), true),
        ("invalid", invalid.as_ptr(), false),
    ] {
        for pass_err in [true, false] {
            for pass_err_msg in [true, false] {
                let mut err: c_int = 7;
                let mut err_msg: *mut c_char = POISON;
                let err_p = if pass_err { &mut err } else { ptr::null_mut() };
                let err_msg_p = if pass_err_msg {
                    &mut err_msg
                } else {
                    ptr::null_mut()
                };
                let raw = unsafe { sandlock_profile_parse(toml, err_p, err_msg_p) };

                assert_eq!(
                    !raw.is_null(),
                    want_json,
                    "{label} (err={pass_err}, err_msg={pass_err_msg})"
                );
                if pass_err {
                    assert_eq!(err, if want_json { 0 } else { -1 }, "{label}");
                }
                if pass_err_msg {
                    assert_ne!(err_msg, POISON, "{label}: err_msg was never written");
                    // Only a real profile problem carries a diagnosis: a null
                    // profile is a binding bug and success has nothing to say.
                    assert_eq!(
                        !err_msg.is_null(),
                        label == "invalid",
                        "{label}: unexpected err_msg"
                    );
                }

                if !raw.is_null() {
                    unsafe { sandlock_string_free(raw) };
                }
                if pass_err_msg && !err_msg.is_null() {
                    unsafe { sandlock_string_free(err_msg) };
                }
            }
        }
    }
}

/// Both allocations are the caller's to free, and both must actually be
/// freeable. Running the success and the failure path many times over exercises
/// the release path enough that a double free or a use-after-free trips the
/// allocator here rather than in a user's process.
#[test]
fn repeated_calls_hand_back_releasable_allocations() {
    let good = CString::new(
        "[filesystem]\nmount = [\"/v:/h:ro\"]\n[limits]\nmemory = \"512M\"\n\
         [network]\nallow_bind = [\"8000-8100\"]",
    )
    .unwrap();
    let bad = CString::new("[limits]\nmemory = \"1.5G\"").unwrap();

    for _ in 0..2_000 {
        for profile in [&good, &bad] {
            let mut err: c_int = 7;
            let mut err_msg: *mut c_char = ptr::null_mut();
            let raw = unsafe { sandlock_profile_parse(profile.as_ptr(), &mut err, &mut err_msg) };
            if !raw.is_null() {
                assert!(!unsafe { CStr::from_ptr(raw) }.to_bytes().is_empty());
                unsafe { sandlock_string_free(raw) };
            }
            if !err_msg.is_null() {
                assert!(!unsafe { CStr::from_ptr(err_msg) }.to_bytes().is_empty());
                unsafe { sandlock_string_free(err_msg) };
            }
        }
    }
}

/// Length is not a grammar: a path far longer than any buffer a caller is
/// likely to have sized must survive the round trip intact rather than being
/// clipped somewhere along it.
#[test]
fn a_very_long_value_survives_intact() {
    let path = format!("/{}", "a".repeat(200_000));
    let v = parse_ok(&format!("[filesystem]\nread = [\"{path}\"]"));
    assert_eq!(v["filesystem"]["read"][0], path);
}
