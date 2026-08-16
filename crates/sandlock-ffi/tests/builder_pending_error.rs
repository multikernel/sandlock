//! Integration tests for the builder's pending-error latch and for the setters
//! that need it.
//!
//! `sandlock_sandbox_builder_on_exit` / `_on_error` take a raw `u8`
//! discriminant and have no error channel of their own. A value outside the
//! documented set is a static bug in the calling binding, so the setter latches
//! it in the builder and `sandlock_sandbox_build` reports it: -1 plus a message
//! naming the setter and the offending value. It used to be coerced to
//! `Commit`, which silently ran a branch policy nobody asked for (and, for
//! `on_error`, discarded the guest work on the error path by committing it).
//!
//! The latch is also what lets the size and time setters take the strings a
//! user writes instead of pre-parsed numbers. They used to take `uint64_t`,
//! which forced every binding to carry its own grammar, and the two SDKs that
//! did agreed with each other while both diverging from the core (fractions and
//! a `T` suffix the core has never accepted). Now the core parses, and a
//! rejected value comes back with the core's own text.
//!
//! These drive the FFI symbols directly (no C compilation step), the same way
//! `tests/protection.rs` does.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::time::{Duration, UNIX_EPOCH};

use sandlock_core::profile::parse_time_start;
use sandlock_core::sandbox::{BranchAction, ByteSize, Sandbox, SandboxBuilder};
use sandlock_ffi::{
    sandlock_profile_parse, sandlock_sandbox_build, sandlock_sandbox_builder_chroot,
    sandlock_sandbox_builder_cwd, sandlock_sandbox_builder_env_var,
    sandlock_sandbox_builder_extra_allow_syscalls, sandlock_sandbox_builder_extra_deny_syscalls,
    sandlock_sandbox_builder_fs_deny, sandlock_sandbox_builder_fs_mount,
    sandlock_sandbox_builder_fs_mount_ro, sandlock_sandbox_builder_fs_read,
    sandlock_sandbox_builder_fs_storage, sandlock_sandbox_builder_fs_write,
    sandlock_sandbox_builder_http_allow, sandlock_sandbox_builder_http_ca,
    sandlock_sandbox_builder_http_ca_out, sandlock_sandbox_builder_http_deny,
    sandlock_sandbox_builder_http_inject_ca, sandlock_sandbox_builder_http_key,
    sandlock_sandbox_builder_max_disk, sandlock_sandbox_builder_max_memory,
    sandlock_sandbox_builder_net_allow, sandlock_sandbox_builder_net_allow_bind,
    sandlock_sandbox_builder_net_deny, sandlock_sandbox_builder_net_deny_bind,
    sandlock_sandbox_builder_new, sandlock_sandbox_builder_on_error,
    sandlock_sandbox_builder_on_exit, sandlock_sandbox_builder_time_start,
    sandlock_sandbox_builder_time_start_epoch, sandlock_sandbox_builder_workdir,
    sandlock_sandbox_free, sandlock_string_free,
};

/// Values no binding should ever pass: `BranchAction` documents 0, 1 and 2.
/// 3 is the classic off-by-one past the last variant, 7 is the value the issue
/// used as its example, and `u8::MAX` is the top of the range.
const INVALID_DISCRIMINANTS: &[u8] = &[3, 7, 42, u8::MAX];

/// Run `configure` over a fresh builder and build it through the C ABI.
///
/// Returns `(built, err, err_msg)` with the message copied out and the original
/// released, so a leak in the test cannot mask one in the implementation. The
/// sandbox itself is freed here: these tests only assert on success/failure.
fn build_via_ffi<F>(configure: F) -> (bool, c_int, Option<String>)
where
    F: FnOnce(*mut SandboxBuilder) -> *mut SandboxBuilder,
{
    let b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");
    let b = configure(b);
    assert!(!b.is_null(), "configure returned a null builder");

    let mut err: c_int = 7; // poison: build must overwrite this
    let mut err_msg: *mut c_char = ptr::null_mut();
    // SAFETY: `b` came from builder_new and was possibly relocated by setters.
    let sandbox = unsafe { sandlock_sandbox_build(b, &mut err, &mut err_msg) };

    let built = !sandbox.is_null();
    if built {
        unsafe { sandlock_sandbox_free(sandbox) };
    }
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
    (built, err, msg)
}

/// Build and assert the latch fired, returning the message for content checks.
fn expect_rejected<F>(configure: F) -> String
where
    F: FnOnce(*mut SandboxBuilder) -> *mut SandboxBuilder,
{
    let (built, err, msg) = build_via_ffi(configure);
    assert!(
        !built,
        "build must return null after a rejected setter value"
    );
    assert_eq!(
        err, -1,
        "build must report -1 after a rejected setter value"
    );
    msg.expect("a rejected setter value must produce an err_msg")
}

#[test]
fn on_exit_unrecognized_discriminant_fails_the_build() {
    for &raw in INVALID_DISCRIMINANTS {
        let msg = expect_rejected(|b| unsafe { sandlock_sandbox_builder_on_exit(b, raw) });
        assert!(
            msg.contains("on_exit"),
            "message must name the setter, got: {msg:?}",
        );
        assert!(
            msg.contains(&raw.to_string()),
            "message must quote the offending value {raw}, got: {msg:?}",
        );
    }
}

#[test]
fn on_error_unrecognized_discriminant_fails_the_build() {
    for &raw in INVALID_DISCRIMINANTS {
        let msg = expect_rejected(|b| unsafe { sandlock_sandbox_builder_on_error(b, raw) });
        assert!(
            msg.contains("on_error"),
            "message must name the setter, got: {msg:?}",
        );
        assert!(
            msg.contains(&raw.to_string()),
            "message must quote the offending value {raw}, got: {msg:?}",
        );
    }
}

#[test]
fn documented_discriminants_still_build_and_reach_the_sandbox() {
    // Without this, an implementation that rejected every value would pass the
    // tests above. Read the action back off the built Sandbox so the assertion
    // covers the translation, not just the absence of an error.
    for (raw, expected) in [
        (0u8, BranchAction::Commit),
        (1, BranchAction::Abort),
        (2, BranchAction::Keep),
    ] {
        let b = sandlock_sandbox_builder_new();
        let b = unsafe { sandlock_sandbox_builder_on_exit(b, raw) };
        let b = unsafe { sandlock_sandbox_builder_on_error(b, raw) };
        // SAFETY: `b` came from builder_new and was relocated by the setters.
        let sandbox = unsafe { *Box::from_raw(b) }
            .build()
            .expect("documented discriminants must build");
        assert_eq!(sandbox.on_exit, expected, "on_exit({raw}) mistranslated");
        assert_eq!(sandbox.on_error, expected, "on_error({raw}) mistranslated");
    }
}

#[test]
fn a_latched_error_survives_later_valid_calls() {
    // The latch is not a transient flag: a valid call after the bad one must
    // not clear it, or a binding could hide its own bug by setting the field
    // twice.
    let msg = expect_rejected(|b| unsafe {
        let b = sandlock_sandbox_builder_on_exit(b, 9);
        sandlock_sandbox_builder_on_exit(b, 1)
    });
    assert!(
        msg.contains("on_exit") && msg.contains('9'),
        "the latched error must survive the later valid call, got: {msg:?}",
    );
}

#[test]
fn the_first_rejection_wins() {
    // Two bad values, one per setter: the message must name the first one. The
    // earliest bad input is the one that explains the rest.
    let msg = expect_rejected(|b| unsafe {
        let b = sandlock_sandbox_builder_on_exit(b, 3);
        sandlock_sandbox_builder_on_error(b, 4)
    });
    assert!(
        msg.contains("on_exit") && msg.contains('3'),
        "the first rejection must win, got: {msg:?}",
    );
    assert!(
        !msg.contains("on_error"),
        "the later rejection must not overwrite the first, got: {msg:?}",
    );
}

#[test]
fn cloning_a_rejected_builder_keeps_it_rejected() {
    // `SandboxBuilder: Clone` is hand-written, so a forgotten field here would
    // make `.clone().build()` a laundering channel for rejected input. The
    // pipeline API clones builders, so this is reachable, not theoretical.
    let b = sandlock_sandbox_builder_new();
    let b = unsafe { sandlock_sandbox_builder_on_exit(b, 7) };
    // SAFETY: `b` came from builder_new and was relocated by the setter.
    let builder = unsafe { *Box::from_raw(b) };
    let err = builder
        .clone()
        .build()
        .expect_err("a clone of a rejected builder must stay rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("on_exit") && msg.contains('7'),
        "the clone must carry the original reason, got: {msg:?}",
    );
}

#[test]
fn build_unchecked_also_refuses_a_rejected_builder() {
    // `build_unchecked` is public and is what sandlock-oci calls. Checking only
    // in `build()` would let rejected input straight through that path.
    let err = SandboxBuilder::default()
        .reject("on_exit: unrecognized branch action 7")
        .build_unchecked()
        .expect_err("build_unchecked must refuse a rejected builder");
    assert!(
        err.to_string().contains("on_exit"),
        "build_unchecked must report the latched reason, got: {err}",
    );
}

// ----------------------------------------------------------------
// String setters: the core owns the grammar
// ----------------------------------------------------------------

/// Build through the C ABI setters and hand back the `Sandbox`, so a test can
/// read what the core parsed instead of only observing that nothing failed.
fn build_ok<F>(configure: F) -> Sandbox
where
    F: FnOnce(*mut SandboxBuilder) -> *mut SandboxBuilder,
{
    let b = sandlock_sandbox_builder_new();
    assert!(!b.is_null(), "builder_new returned null");
    let b = configure(b);
    assert!(!b.is_null(), "configure returned a null builder");
    // SAFETY: `b` came from builder_new and was relocated by the setters.
    unsafe { *Box::from_raw(b) }
        .build()
        .expect("a value the core accepts must build")
}

fn set_max_memory(b: *mut SandboxBuilder, value: &str) -> *mut SandboxBuilder {
    let c = CString::new(value).expect("test value must not contain NUL");
    unsafe { sandlock_sandbox_builder_max_memory(b, c.as_ptr()) }
}

fn set_max_disk(b: *mut SandboxBuilder, value: &str) -> *mut SandboxBuilder {
    let c = CString::new(value).expect("test value must not contain NUL");
    unsafe { sandlock_sandbox_builder_max_disk(b, c.as_ptr()) }
}

fn set_time_start(b: *mut SandboxBuilder, value: &str) -> *mut SandboxBuilder {
    let c = CString::new(value).expect("test value must not contain NUL");
    unsafe { sandlock_sandbox_builder_time_start(b, c.as_ptr()) }
}

/// Every shape of the core's byte-size grammar, driven through the C ABI:
/// a bare count of bytes, each documented suffix, the lowercase spellings and
/// surrounding whitespace. Read back off the built `Sandbox`, so a setter that
/// accepted the string and dropped it would fail here.
#[test]
fn max_memory_accepts_the_whole_core_byte_size_grammar() {
    for (text, expected) in [
        ("1024", 1024u64),
        ("100K", 100 * 1024),
        ("512M", 512 * 1024 * 1024),
        ("1G", 1024 * 1024 * 1024),
        ("100k", 100 * 1024),
        ("512m", 512 * 1024 * 1024),
        ("1g", 1024 * 1024 * 1024),
        ("  512M  ", 512 * 1024 * 1024),
        // The core trims around the number as well as around the whole string,
        // so this is accepted; pinned here because it is the kind of detail a
        // hand-written binding parser gets wrong in one direction or the other.
        ("512 M", 512 * 1024 * 1024),
    ] {
        let sandbox = build_ok(|b| set_max_memory(b, text));
        assert_eq!(
            sandbox.max_memory,
            Some(ByteSize(expected)),
            "max_memory({text:?}) reached the sandbox as the wrong size",
        );
    }
}

#[test]
fn max_disk_accepts_the_whole_core_byte_size_grammar() {
    for (text, expected) in [
        ("1024", 1024u64),
        ("100K", 100 * 1024),
        ("10G", 10 * 1024 * 1024 * 1024),
        ("10g", 10 * 1024 * 1024 * 1024),
    ] {
        let sandbox = build_ok(|b| set_max_disk(b, text));
        assert_eq!(
            sandbox.max_disk,
            Some(ByteSize(expected)),
            "max_disk({text:?}) reached the sandbox as the wrong size",
        );
    }
}

/// Values the core rejects, with the exact text a CLI user gets for the same
/// value. `sandlock --max-memory 1.5G` runs `ByteSize::parse` and prints its
/// error (crates/sandlock-cli/src/main.rs), and `build()` puts the latched
/// reason back into `SandboxError::Invalid`, so the two strings must be equal
/// rather than merely similar. A setter that reworded the diagnosis, or parsed
/// the string itself, fails this.
#[test]
fn max_memory_rejects_with_the_text_the_cli_prints() {
    for value in BAD_BYTE_SIZES {
        let msg = expect_rejected(|b| set_max_memory(b, value));
        let cli = format!("{}", ByteSize::parse(value).unwrap_err());
        assert_eq!(msg, cli, "max_memory({value:?}) must speak with the core");
    }
}

#[test]
fn max_disk_rejects_with_the_text_the_cli_prints() {
    for value in BAD_BYTE_SIZES {
        let msg = expect_rejected(|b| set_max_disk(b, value));
        let cli = format!("{}", ByteSize::parse(value).unwrap_err());
        assert_eq!(msg, cli, "max_disk({value:?}) must speak with the core");
    }
}

/// `1.5G` and `512T` are not arbitrary: both SDKs accepted them while the core
/// never has, because each shipped a parser of its own and the two agreed with
/// each other instead of with the grammar they were feeding. Routing the string
/// to the core is what makes them errors here.
const BAD_BYTE_SIZES: &[&str] = &[
    "",
    " ",
    "1.5G",
    "512T",
    "not_a_size",
    "M",
    "-1",
    "17179869184G",
];

/// The `time_start` grammar, including the three things the old `uint64_t`
/// epoch-seconds parameter could not carry: sub-second precision, a non-UTC
/// offset, and an instant before 1970.
#[test]
fn time_start_accepts_the_core_timestamp_grammar() {
    // 2026-01-01T00:00:00Z, and 1969-07-20T20:17:00Z (Apollo 11 touchdown),
    // both as plain epoch counts so the expectation does not go through the
    // parser under test.
    let y2026 = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
    for (text, expected) in [
        ("2026-01-01T00:00:00Z", y2026),
        ("2026-01-01T00:00:00+00:00", y2026),
        // Same instant written in another zone: the offset has to be applied,
        // not ignored.
        ("2026-01-01T01:00:00+01:00", y2026),
        (
            "2026-01-01T00:00:00.500Z",
            y2026 + Duration::from_millis(500),
        ),
        (
            "1969-07-20T20:17:00Z",
            UNIX_EPOCH - Duration::from_secs(14_182_980),
        ),
    ] {
        let sandbox = build_ok(|b| set_time_start(b, text));
        assert_eq!(
            sandbox.time_start,
            Some(expected),
            "time_start({text:?}) reached the sandbox as the wrong instant",
        );
    }
}

/// Values the core rejects. The message must be the core's, so the only thing
/// that differs from what a CLI user sees for `--time-start` is the knob name
/// the surface passes in: same parser, same diagnosis, same value quoted.
#[test]
fn time_start_rejects_with_the_core_diagnosis() {
    for value in [
        "",
        "nope",
        // No offset: a local wall-clock reading is not an instant.
        "2026-01-01T00:00:00",
        // A bare epoch count, which is exactly what this setter used to take.
        // It is not RFC3339, so it has to fail rather than be re-interpreted.
        "1700000000",
        "2026-13-01T00:00:00Z",
    ] {
        let msg = expect_rejected(|b| set_time_start(b, value));
        let core = format!("{}", parse_time_start(value, "time_start").unwrap_err());
        assert_eq!(msg, core, "time_start({value:?}) must speak with the core");

        let cli = format!("{}", parse_time_start(value, "--time-start").unwrap_err());
        assert_eq!(
            msg.replacen("time_start", "--time-start", 1),
            cli,
            "only the knob name may differ from the CLI text, got: {msg:?}",
        );
    }
}

/// A null pointer and a non-UTF-8 byte string are the two conditions the core
/// cannot see, and the only ones the C ABI diagnoses itself. The old setters
/// took a number and could not meet them; the sibling string setters in this
/// file still answer both with `unwrap_or("")` or a silent return, which hands
/// the core a value the caller never passed.
#[test]
fn a_null_or_non_utf8_argument_is_latched_rather_than_swallowed() {
    let msg = expect_rejected(|b| unsafe { sandlock_sandbox_builder_max_memory(b, ptr::null()) });
    assert!(
        msg.contains("max_memory") && msg.contains("NULL"),
        "a null size must name the setter and the condition, got: {msg:?}",
    );

    let msg = expect_rejected(|b| unsafe { sandlock_sandbox_builder_time_start(b, ptr::null()) });
    assert!(
        msg.contains("time_start") && msg.contains("NULL"),
        "a null timestamp must name the setter and the condition, got: {msg:?}",
    );

    // 0xFF is not a valid UTF-8 lead byte anywhere in a sequence.
    let garbage = CString::new(vec![0x35u8, 0x31, 0x32, 0xff]).unwrap();
    let msg =
        expect_rejected(|b| unsafe { sandlock_sandbox_builder_max_disk(b, garbage.as_ptr()) });
    assert!(
        msg.contains("max_disk") && msg.contains("UTF-8"),
        "a non-UTF-8 size must name the setter and the condition, got: {msg:?}",
    );
}

/// One latch, shared by both kinds of setter: a rejected string still wins over
/// a later rejected discriminant, so the message points at the first mistake
/// whichever setter made it.
#[test]
fn the_first_rejection_wins_across_setter_kinds() {
    let msg = expect_rejected(|b| {
        let b = set_max_memory(b, "1.5G");
        unsafe { sandlock_sandbox_builder_on_exit(b, 7) }
    });
    assert!(
        msg.contains("1.5G") && !msg.contains("on_exit"),
        "the earlier rejected string must win, got: {msg:?}",
    );
}

// ================================================================
// The numeric door to `time_start`
// ================================================================

/// `sandlock_sandbox_builder_time_start_epoch` is the other half of the string
/// setter, and it exists because a binding that consumes `sandlock_profile_parse`
/// holds a resolved instant rather than the text it came from. Its input is the
/// `{seconds, nanoseconds}` pair that export reports, so the two have to land on
/// the same instant as the grammar the profile was written in; otherwise a
/// profile means one thing when a CLI loads it and another when a binding
/// re-applies what it was told the profile resolved to.
#[test]
fn the_epoch_door_lands_where_the_grammar_door_lands() {
    for text in [
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.500Z",
        "1969-07-20T20:17:00Z",
        // Half a second before the epoch, where the canonical split borrows:
        // the pair is (-1, 500000000), not (0, -500000000).
        "1969-12-31T23:59:59.500Z",
        "1970-01-01T00:00:00Z",
    ] {
        let through_text = build_ok(|b| set_time_start(b, text)).time_start.unwrap();

        let (seconds, nanoseconds) = epoch_split(text);
        let through_epoch = build_ok(|b| unsafe {
            sandlock_sandbox_builder_time_start_epoch(b, seconds, nanoseconds)
        })
        .time_start
        .unwrap();

        assert_eq!(
            through_epoch, through_text,
            "{text} resolved differently through the two doors",
        );
    }
}

/// Split a stamp the way `sandlock_profile_parse` reports it, through the core
/// itself: a split computed here would be this test agreeing with itself rather
/// than with the export whose output the setter claims to take.
fn epoch_split(text: &str) -> (i64, u32) {
    let json = profile_parse_json(&format!(
        "[determinism]\ntime_start = {}\n",
        serde_json::to_string(text).unwrap()
    ));
    let ts = &json["determinism"]["time_start"];
    (
        ts["seconds"].as_i64().unwrap(),
        ts["nanoseconds"].as_u64().unwrap() as u32,
    )
}

/// Resolve a profile through `sandlock_profile_parse` and return its canonical
/// JSON.
fn profile_parse_json(toml: &str) -> serde_json::Value {
    let text = CString::new(toml).unwrap();
    let mut err: c_int = 7;
    let mut err_msg: *mut c_char = ptr::null_mut();
    // SAFETY: `text` is a valid NUL-terminated string and both out-params are
    // live for the call.
    let raw = unsafe { sandlock_profile_parse(text.as_ptr(), &mut err, &mut err_msg) };
    assert!(!raw.is_null() && err == 0, "profile_parse refused {toml:?}");
    // SAFETY: a non-null return is an owned NUL-terminated JSON document.
    let json = unsafe { CStr::from_ptr(raw) }.to_str().unwrap().to_owned();
    unsafe { sandlock_string_free(raw) };
    serde_json::from_str(&json).unwrap()
}

/// The pair is normalized on both sides: the canonical form never emits a
/// remainder of a whole second or more, so a caller that does is working from a
/// different contract, and agreeing with it silently would hide that.
#[test]
fn the_epoch_door_refuses_an_unnormalized_remainder() {
    let msg = expect_rejected(|b| unsafe {
        sandlock_sandbox_builder_time_start_epoch(b, 0, 1_000_000_000)
    });
    assert!(
        msg.contains("nanoseconds must be below 1000000000"),
        "an unnormalized remainder must say so, got: {msg:?}",
    );
}

/// Out of range for the timestamp type, and therefore latched rather than
/// wrapped into some other instant.
#[test]
fn the_epoch_door_refuses_an_instant_it_cannot_represent() {
    let msg =
        expect_rejected(|b| unsafe { sandlock_sandbox_builder_time_start_epoch(b, i64::MAX, 0) });
    assert!(
        msg.contains("time_start"),
        "an out-of-range instant must name the knob, got: {msg:?}",
    );
}

// ----------------------------------------------------------------
// Every `*const c_char` builder setter reports what it cannot represent
// ----------------------------------------------------------------

/// One `*const c_char` builder setter, by the name it reports itself under.
type StrSetter = (
    &'static str,
    fn(*mut SandboxBuilder, *const c_char) -> *mut SandboxBuilder,
);

fn string_setters() -> Vec<StrSetter> {
    vec![
        ("fs_read", |b, s| unsafe { sandlock_sandbox_builder_fs_read(b, s) }),
        ("fs_write", |b, s| unsafe { sandlock_sandbox_builder_fs_write(b, s) }),
        ("fs_deny", |b, s| unsafe { sandlock_sandbox_builder_fs_deny(b, s) }),
        ("fs_storage", |b, s| unsafe { sandlock_sandbox_builder_fs_storage(b, s) }),
        ("workdir", |b, s| unsafe { sandlock_sandbox_builder_workdir(b, s) }),
        ("cwd", |b, s| unsafe { sandlock_sandbox_builder_cwd(b, s) }),
        ("chroot", |b, s| unsafe { sandlock_sandbox_builder_chroot(b, s) }),
        ("net_allow", |b, s| unsafe { sandlock_sandbox_builder_net_allow(b, s) }),
        ("net_deny", |b, s| unsafe { sandlock_sandbox_builder_net_deny(b, s) }),
        ("net_allow_bind", |b, s| unsafe { sandlock_sandbox_builder_net_allow_bind(b, s) }),
        ("net_deny_bind", |b, s| unsafe { sandlock_sandbox_builder_net_deny_bind(b, s) }),
        ("http_allow", |b, s| unsafe { sandlock_sandbox_builder_http_allow(b, s) }),
        ("http_deny", |b, s| unsafe { sandlock_sandbox_builder_http_deny(b, s) }),
        ("http_ca", |b, s| unsafe { sandlock_sandbox_builder_http_ca(b, s) }),
        ("http_key", |b, s| unsafe { sandlock_sandbox_builder_http_key(b, s) }),
        ("http_inject_ca", |b, s| unsafe { sandlock_sandbox_builder_http_inject_ca(b, s) }),
        ("http_ca_out", |b, s| unsafe { sandlock_sandbox_builder_http_ca_out(b, s) }),
        ("extra_deny_syscalls", |b, s| unsafe {
            sandlock_sandbox_builder_extra_deny_syscalls(b, s)
        }),
        ("extra_allow_syscalls", |b, s| unsafe {
            sandlock_sandbox_builder_extra_allow_syscalls(b, s)
        }),
        ("max_memory", |b, s| unsafe { sandlock_sandbox_builder_max_memory(b, s) }),
        ("max_disk", |b, s| unsafe { sandlock_sandbox_builder_max_disk(b, s) }),
        ("time_start", |b, s| unsafe { sandlock_sandbox_builder_time_start(b, s) }),
    ]
}

#[test]
fn a_non_utf8_setter_argument_is_reported_by_every_string_setter() {
    // A path is an arbitrary byte string on Linux: `readdir()` hands one back
    // and a C caller forwards it. `to_str().unwrap_or("")` turned that into
    // the empty string, so the core either diagnosed a value nobody passed or,
    // for the grant side, recorded an empty path. An empty path is a prefix of
    // every guest path, which is how it voids an allowlist rather than merely
    // losing one entry.
    let bytes = CString::new(&b"\xff\xfe/secret"[..]).unwrap();
    for (name, set) in string_setters() {
        let msg = expect_rejected(|b| set(b, bytes.as_ptr()));
        assert!(
            msg.contains(name) && msg.contains("UTF-8"),
            "{name} must report the non-UTF-8 argument, got: {msg:?}",
        );
    }
}

#[test]
fn a_null_setter_argument_is_reported_by_every_string_setter() {
    // The other half: a null argument used to return the builder untouched, so
    // the grant, deny or limit the caller asked for simply was not there.
    for (name, set) in string_setters() {
        let msg = expect_rejected(|b| set(b, ptr::null()));
        assert!(
            msg.contains(name) && msg.contains("NULL"),
            "{name} must report the null argument, got: {msg:?}",
        );
    }
}

#[test]
fn an_env_var_pair_reports_whichever_half_it_cannot_represent() {
    let good = CString::new("KEY").unwrap();
    let bad = CString::new(&b"\xff\xfe"[..]).unwrap();

    let msg = expect_rejected(|b| unsafe {
        sandlock_sandbox_builder_env_var(b, bad.as_ptr(), good.as_ptr())
    });
    assert!(msg.contains("env_var key"), "got: {msg:?}");

    let msg = expect_rejected(|b| unsafe {
        sandlock_sandbox_builder_env_var(b, good.as_ptr(), bad.as_ptr())
    });
    assert!(msg.contains("env_var value"), "got: {msg:?}");

    let msg = expect_rejected(|b| unsafe {
        sandlock_sandbox_builder_env_var(b, ptr::null(), good.as_ptr())
    });
    assert!(msg.contains("env_var key") && msg.contains("NULL"), "got: {msg:?}");
}

#[test]
fn a_mount_pair_reports_whichever_half_it_cannot_represent() {
    // Both mount setters used to route through a helper that answered "add no
    // mount" for a null, non-UTF-8 or empty path, which is the coercion this
    // commit is about: the caller asked for a mount, got none, and heard
    // nothing. For `fs_mount_ro` the two outcomes are a read-only view and a
    // writable one.
    let good = CString::new("/srv/data").unwrap();
    let bad = CString::new(&b"\xff\xfe"[..]).unwrap();
    let empty = CString::new("").unwrap();

    type MountSetter = (
        &'static str,
        fn(*mut SandboxBuilder, *const c_char, *const c_char) -> *mut SandboxBuilder,
    );
    let setters: Vec<MountSetter> = vec![
        ("fs_mount", |b, v, h| unsafe {
            sandlock_sandbox_builder_fs_mount(b, v, h)
        }),
        ("fs_mount_ro", |b, v, h| unsafe {
            sandlock_sandbox_builder_fs_mount_ro(b, v, h)
        }),
    ];

    for (name, set) in setters {
        for (arg, what) in [(bad.as_ptr(), "UTF-8"), (ptr::null(), "NULL")] {
            let msg = expect_rejected(|b| set(b, arg, good.as_ptr()));
            assert!(
                msg.contains(&format!("{name} virtual path")) && msg.contains(what),
                "{name} must name the virtual path, got: {msg:?}",
            );
            let msg = expect_rejected(|b| set(b, good.as_ptr(), arg));
            assert!(
                msg.contains(&format!("{name} host path")) && msg.contains(what),
                "{name} must name the host path, got: {msg:?}",
            );
        }

        // Emptiness is the core's verdict, forwarded rather than pre-empted, so
        // it names the setter but not the C ABI's own half labels.
        let msg = expect_rejected(|b| set(b, empty.as_ptr(), good.as_ptr()));
        assert!(
            msg.contains(name) && msg.contains("virtual path") && msg.contains("empty"),
            "{name} must forward the core's empty-path verdict, got: {msg:?}",
        );
        let msg = expect_rejected(|b| set(b, good.as_ptr(), empty.as_ptr()));
        assert!(
            msg.contains(name) && msg.contains("host path") && msg.contains("empty"),
            "{name} must forward the core's empty-path verdict, got: {msg:?}",
        );
    }

    // The guard rail: a well-formed pair still lands, and `fs_mount_ro` still
    // marks the virtual path read-only.
    let sandbox = build_ok(|b| unsafe {
        let virt = CString::new("/data").unwrap();
        let virt_ro = CString::new("/ref").unwrap();
        let b = sandlock_sandbox_builder_fs_mount(b, virt.as_ptr(), good.as_ptr());
        sandlock_sandbox_builder_fs_mount_ro(b, virt_ro.as_ptr(), good.as_ptr())
    });
    assert_eq!(sandbox.fs_mount.len(), 2);
    assert_eq!(sandbox.fs_mount_ro, vec![std::path::PathBuf::from("/ref")]);
}

#[test]
fn a_valid_string_setter_argument_is_untouched_by_the_check() {
    // The guard rail: the checks above must not have made the ordinary path
    // reject anything. One representative from each family.
    let sandbox = build_ok(|b| unsafe {
        let read = CString::new("/usr").unwrap();
        let deny = CString::new("/etc/shadow").unwrap();
        let rule = CString::new("tcp://example.com:443").unwrap();
        let key = CString::new("LANG").unwrap();
        let value = CString::new("C").unwrap();
        let calls = CString::new("ptrace, mount").unwrap();
        let b = sandlock_sandbox_builder_fs_read(b, read.as_ptr());
        let b = sandlock_sandbox_builder_fs_deny(b, deny.as_ptr());
        let b = sandlock_sandbox_builder_net_allow(b, rule.as_ptr());
        let b = sandlock_sandbox_builder_env_var(b, key.as_ptr(), value.as_ptr());
        sandlock_sandbox_builder_extra_deny_syscalls(b, calls.as_ptr())
    });
    assert_eq!(sandbox.fs_readable, vec![std::path::PathBuf::from("/usr")]);
    assert_eq!(sandbox.fs_denied, vec![std::path::PathBuf::from("/etc/shadow")]);
    assert_eq!(sandbox.net_allow.len(), 1);
    assert_eq!(sandbox.env.get("LANG").map(String::as_str), Some("C"));
    assert_eq!(
        sandbox.extra_deny_syscalls,
        vec!["ptrace".to_string(), "mount".to_string()],
    );
}
