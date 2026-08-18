//! Malformed and hostile input for the canonical profile parser.
//!
//! The unit tests next to the parser cover what a well-formed profile resolves
//! to. These cover what happens when it is not well formed, because that is the
//! half a binding depends on: the canonical form exists so that a profile means
//! the same thing through the CLI and through an SDK, and a profile that is
//! *rejected* by one and *accepted* by the other is the same divergence as one
//! that resolves differently. So the centrepiece here is a battery that runs
//! every hostile profile through both entry points and demands byte-identical
//! diagnoses.

use sandlock_core::profile::{canonical, parse_profile};

fn ok(toml: &str) -> serde_json::Value {
    let json = canonical::parse_to_json(toml).unwrap_or_else(|e| panic!("{toml:?} failed: {e}"));
    serde_json::from_str(&json).expect("emitted JSON must parse")
}

fn err(toml: &str) -> String {
    match canonical::parse_to_json(toml) {
        Ok(json) => panic!("{toml:?} was accepted, giving: {json}"),
        Err(e) => e.to_string(),
    }
}

/// Every hostile profile in this file, so the parity check below cannot drift
/// away from the cases the other tests actually exercise.
fn hostile_profiles() -> Vec<String> {
    let mut cases: Vec<String> = Vec::new();
    cases.extend(EMPTY_VALUES.iter().map(|(toml, _)| toml.to_string()));
    cases.extend(OUT_OF_RANGE.iter().map(|(toml, _)| toml.to_string()));
    cases.extend(WRONG_TYPES.iter().map(|(toml, _)| toml.to_string()));
    cases.extend(
        [
            // nothing to parse
            "",
            "   \n\t\n",
            "# just a comment\n",
            // structure
            "[bogus]\nx = 1\n",
            "[limits]\nbogus = 1\n",
            "memory = \"1G\"\n",
            "[limits]\nmemory = \"1G\"\nmemory = \"2G\"\n",
            "[limits]\nmemory = \"1G\"\n[limits]\ncpu = 1\n",
            "[program.env]\nA = \"1\"\nA = \"2\"\n",
            "[program",
            // NUL smuggled in through the TOML escape
            "[limits]\nmemory = \"1\\u0000G\"\n",
            "[syscalls]\nextra_deny = [\"re\\u0000ad\"]\n",
            "[filesystem]\nmount = [\"\\u0000\"]\n",
            "[program]\nexec = \"a\\u0000b\"\n",
            "[filesystem]\nchroot = \"/a\\u0000b\"\n",
            // grammar shapes
            "[filesystem]\nmount = [\"nocolon\"]\n",
            "[filesystem]\nmount = [\"/v:/h:bogus\"]\n",
            "[filesystem]\non_exit = \"Commit\"\n",
            "[filesystem]\non_exit = \"bogus\"\n",
            "[determinism]\ntime_start = \"nope\"\n",
            "[determinism]\ntime_start = \"2026-01-01T00:00:00\"\n",
            "[determinism]\ntime_start = \"1700000000\"\n",
            "[determinism]\ntime_start = \"999999-01-01T00:00:00Z\"\n",
            "[determinism]\ntime_start = \"2026-01-01T00:00:00+99:00\"\n",
            "[limits]\nmemory = \"1.5G\"\n",
            "[limits]\nmemory = \"1T\"\n",
            "[network]\nallow = [\"ftp://example.com\"]\n",
            "[network]\nallow = [\"icmp://example.com:80\"]\n",
            "[network]\nallow = [\"tcp://10.0.0.0/33\"]\n",
            "[network]\nallow = [\"tcp://[::1]/129\"]\n",
            "[network]\nallow_bind = [\"9-1\"]\n",
            "[network]\nallow_bind = [\"-\"]\n",
            "[network]\nallow_bind = [\"*\", \"80\"]\n",
            "[network]\ndeny_bind = [\"*\"]\n",
            "[http]\nallow = [\"GET\"]\n",
            // cross-section checks, which only fire inside the builder
            "[network]\nallow = [\"tcp://a\"]\ndeny = [\"tcp://b\"]\n",
            "[syscalls]\nextra_allow = [\"sysv_ipc\"]\nextra_deny = [\"sysv_ipc\"]\n",
            "[syscalls]\nextra_allow = [\"read\"]\n",
            "[syscalls]\nextra_deny = [\"no_such_syscall\"]\n",
            "[program]\nuid = 1000\n",
            "[program]\ngid = 1000\n",
            "[limits]\ncpu = 0\n",
            "[limits]\nopen_files = 0\n",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    cases
}

/// The reason this form exists. `canonical::parse` runs the CLI's own pipeline
/// instead of a second validator, so a profile that is rejected must be
/// rejected identically, down to the wording: an SDK user filing a bug quotes a
/// message a CLI user can reproduce.
///
/// Comparing the full string, not a prefix, is deliberate. Any re-implemented
/// check would almost certainly still say "invalid byte size" while differing
/// in the value it quotes or the layer it names.
#[test]
fn every_rejection_is_word_for_word_what_the_cli_prints() {
    for toml in hostile_profiles() {
        let canonical = canonical::parse(&toml).err().map(|e| e.to_string());
        let cli = parse_profile(&toml).err().map(|e| e.to_string());
        assert_eq!(canonical, cli, "profile: {toml:?}");
    }
}

// ---------------------------------------------------------------
// Nothing to parse
// ---------------------------------------------------------------

/// An empty profile is a profile that constrains nothing, not a syntax error.
/// It is also the shape a caller gets from an empty file or an empty string, so
/// it has to produce the full section skeleton rather than a partial document
/// that a consumer's field mapping would trip over.
#[test]
fn a_profile_with_nothing_in_it_still_yields_every_section() {
    for toml in ["", "   \n\t\n", "# just a comment\n", "\u{feff}[limits]\n"] {
        let v = ok(toml);
        for section in [
            "config",
            "determinism",
            "program",
            "filesystem",
            "network",
            "http",
            "syscalls",
            "limits",
        ] {
            assert!(v[section].is_object(), "{toml:?} lost [{section}]");
        }
        assert_eq!(v["limits"]["memory"], serde_json::Value::Null);
        assert_eq!(v["filesystem"]["on_exit"], "commit");
    }
}

/// A file with no recognized section is far more likely to be the wrong file,
/// or a schema that moved, than an empty policy. Accepting it as "no
/// constraints" would hand a caller a wide-open sandbox from a typo.
#[test]
fn a_file_with_no_known_section_is_rejected_not_read_as_empty() {
    let msg = err("[bogus]\nx = 1\n");
    assert!(msg.contains("unknown field `bogus`"), "{msg}");
    // The message has to list the alternatives, or the caller cannot tell a
    // typo from a version skew.
    assert!(msg.contains("`limits`"), "{msg}");

    // The old flat schema, where keys sat at the top level, fails the same way.
    assert!(err("memory = \"1G\"\n").contains("unknown field `memory`"));
}

/// Both sides of the wire reject unknown keys, which is what makes a schema
/// change a load-time failure instead of a setting that quietly stops applying.
#[test]
fn an_unknown_key_inside_a_known_section_is_rejected() {
    let msg = err("[limits]\nbogus = 1\n");
    assert!(msg.contains("unknown field `bogus`"), "{msg}");
    assert!(msg.contains("`memory`"), "{msg}");
}

/// TOML forbids these outright; the point of pinning it is that a profile
/// written twice never silently resolves to "the last one wins", which would
/// make a merge conflict resolve itself into a policy nobody chose.
#[test]
fn a_key_written_twice_is_rejected() {
    assert!(err("[limits]\nmemory = \"1G\"\nmemory = \"2G\"\n").contains("duplicate key `memory`"));
    assert!(err("[limits]\nmemory = \"1G\"\n[limits]\ncpu = 1\n").contains("duplicate key"));
    assert!(err("[program.env]\nA = \"1\"\nA = \"2\"\n").contains("duplicate key `A`"));
}

// ---------------------------------------------------------------
// Right name, wrong type
// ---------------------------------------------------------------

/// A field of the right name and the wrong type, in both directions: a string
/// where a number belongs and a number where a string belongs. A parser that
/// coerced would turn `cpu = "1"` into a working profile in one binding and a
/// failure in another, which is the drift this form removes.
const WRONG_TYPES: &[(&str, &str)] = &[
    ("[limits]\ncpu = \"1\"\n", "expected u8"),
    ("[limits]\nmemory = 1024\n", "expected a string"),
    ("[limits]\nmemory = [\"1G\"]\n", "expected a string"),
    (
        "[determinism]\ntime_start = 1700000000\n",
        "expected a string",
    ),
    ("[determinism]\nrandom_seed = \"5\"\n", "expected u64"),
    ("[program]\nexec = 5\n", "invalid type: integer"),
    ("[program]\nclean_env = \"true\"\n", "expected a boolean"),
    ("[program]\nargs = [1, 2]\n", "invalid type: integer"),
    ("[program]\nenv = \"a=b\"\n", "invalid type: string"),
    ("[filesystem]\nmount = \"/a:/b\"\n", "invalid type: string"),
    ("[filesystem]\nread = \"/a\"\n", "invalid type: string"),
    ("[network]\nport_remap = 1\n", "invalid type: integer"),
];

#[test]
fn a_field_of_the_wrong_type_is_rejected_rather_than_coerced() {
    for (toml, needle) in WRONG_TYPES {
        let msg = err(toml);
        assert!(
            msg.contains(needle),
            "{toml:?}: expected {needle:?}, got {msg}"
        );
    }
}

// ---------------------------------------------------------------
// Empty values, one per micro-grammar
// ---------------------------------------------------------------

/// The empty string is the value a caller gets from an unset template variable
/// or an unfilled placeholder, so every grammar meets it eventually. Each one
/// has to name itself in the diagnosis; "invalid value" alone leaves the user
/// hunting through a profile for which of eight sections went wrong.
const EMPTY_VALUES: &[(&str, &str)] = &[
    ("[filesystem]\nmount = [\"\"]\n", "invalid mount spec \"\""),
    ("[limits]\nmemory = \"\"\n", "empty byte size string"),
    ("[limits]\ndisk = \"\"\n", "empty byte size string"),
    (
        "[determinism]\ntime_start = \"\"\n",
        "[determinism].time_start \"\"",
    ),
    (
        "[filesystem]\non_exit = \"\"\n",
        "invalid branch action \"\"",
    ),
    (
        "[filesystem]\non_error = \"\"\n",
        "invalid branch action \"\"",
    ),
    ("[network]\nallow = [\"\"]\n", "--net-allow: empty rule"),
    ("[network]\ndeny = [\"\"]\n", "--net-deny: empty rule"),
    (
        "[network]\nallow_bind = [\"\"]\n",
        "--net-allow-bind: empty port",
    ),
    (
        "[network]\ndeny_bind = [\"\"]\n",
        "--net-deny-bind: empty port",
    ),
    ("[http]\nallow = [\"\"]\n", "invalid http rule"),
    ("[http]\ndeny = [\"\"]\n", "invalid http rule"),
    (
        "[syscalls]\nextra_allow = [\"\"]\n",
        "unknown syscall group name",
    ),
];

#[test]
fn an_empty_value_is_rejected_by_the_grammar_that_owns_it() {
    for (toml, needle) in EMPTY_VALUES {
        let msg = err(toml);
        assert!(
            msg.contains(needle),
            "{toml:?}: expected {needle:?}, got {msg}"
        );
    }
}

/// Not every empty string is a grammar violation: a path is just a path, and
/// core accepts an empty one today. Pinning it keeps the previous test honest
/// about which list a field belongs to, and makes a future decision to reject
/// these show up as a deliberate change rather than an accident.
#[test]
fn an_empty_path_is_carried_through_rather_than_rejected() {
    assert_eq!(
        ok("[filesystem]\nchroot = \"\"\n")["filesystem"]["chroot"],
        ""
    );
    assert_eq!(
        ok("[filesystem]\nread = [\"\"]\n")["filesystem"]["read"][0],
        ""
    );
    assert_eq!(ok("[program]\nexec = \"\"\n")["program"]["exec"], "");
}

// ---------------------------------------------------------------
// Numbers at and past the edges
// ---------------------------------------------------------------

/// Sizes and ports both have a signed spelling a user can write and an
/// unsigned type they land in, which is where a silent wrap lives. Each of
/// these has to be a diagnosis, never a number.
const OUT_OF_RANGE: &[(&str, &str)] = &[
    // sizes: negative, non-numeric-large, and overflow through the suffix
    ("[limits]\nmemory = \"-1\"\n", "invalid byte size: -1"),
    ("[limits]\nmemory = \"-1G\"\n", "invalid byte size: -1G"),
    (
        "[limits]\nmemory = \"18446744073709551616\"\n",
        "invalid byte size",
    ),
    (
        "[limits]\nmemory = \"17179869184G\"\n",
        "byte size out of range",
    ),
    ("[limits]\ndisk = \"-1M\"\n", "invalid byte size: -1M"),
    // integers the schema types reject before any grammar runs
    ("[limits]\nprocesses = -1\n", "invalid value"),
    ("[limits]\nprocesses = 4294967296\n", "invalid value"),
    ("[limits]\ncpu = 256\n", "invalid value"),
    ("[program]\nuid = -1\n", "invalid value"),
    ("[program]\nuid = 4294967296\n", "invalid value"),
    ("[determinism]\nrandom_seed = -1\n", "invalid value"),
    ("[limits]\ngpu_devices = [-1]\n", "invalid value"),
    // ports written as integers, checked by the u16 schema type
    ("[network]\nallow_bind = [65536]\n", "did not match"),
    ("[network]\nallow_bind = [-1]\n", "did not match"),
    ("[http]\nports = [65536]\n", "invalid value"),
    ("[http]\nports = [-1]\n", "invalid value"),
    // the same ports written as strings, checked by the port grammar
    (
        "[network]\nallow_bind = [\"65536\"]\n",
        "--net-allow-bind: invalid port `65536`",
    ),
    (
        "[network]\nallow_bind = [\"-1\"]\n",
        "--net-allow-bind: invalid port range `-1`",
    ),
    (
        "[network]\nallow_bind = [\"1-65536\"]\n",
        "--net-allow-bind: invalid port range",
    ),
    (
        "[network]\nallow = [\"tcp://example.com:65536\"]\n",
        "invalid port `65536`",
    ),
    (
        "[network]\nallow = [\"tcp://example.com:-1\"]\n",
        "invalid port `-1`",
    ),
];

#[test]
fn a_number_outside_its_range_is_a_diagnosis_not_a_wrapped_value() {
    for (toml, needle) in OUT_OF_RANGE {
        let msg = err(toml);
        assert!(
            msg.contains(needle),
            "{toml:?}: expected {needle:?}, got {msg}"
        );
    }
}

/// The largest values that are still legal, so the range checks above are
/// pinned from below as well: a check that rejected everything would satisfy
/// them just as well as a correct one.
#[test]
fn the_largest_legal_values_are_still_accepted() {
    assert_eq!(
        ok("[limits]\nmemory = \"18446744073709551615\"\n")["limits"]["memory"],
        u64::MAX
    );
    assert_eq!(ok("[limits]\nmemory = \"0\"\n")["limits"]["memory"], 0);
    assert_eq!(ok("[limits]\ncpu = 100\n")["limits"]["cpu"], 100);
    let ports = ok("[network]\nallow_bind = [\"0-65535\"]\n");
    assert_eq!(ports["network"]["allow_bind"]["ports"][0], 0);
    assert_eq!(ports["network"]["allow_bind"]["ports"][65535], 65535);
    assert_eq!(ports["network"]["allow_bind"]["any"], false);
}

// ---------------------------------------------------------------
// NUL and length
// ---------------------------------------------------------------

/// A NUL is the one byte the transport cannot carry, and TOML hands it over
/// on request. The canonical document is JSON, where it is an ordinary escape,
/// so the value must arrive whole: a parser that stopped at the NUL would ship
/// a *shorter* path or host than the profile asked for, which for a net rule
/// means allowing a different destination than the file names.
#[test]
fn a_nul_inside_a_value_is_carried_whole_not_truncated() {
    let v = ok("[network]\nallow = [\"tcp://ex\\u0000ample.com\"]\n");
    assert_eq!(
        v["network"]["allow"][0]["target"]["host"],
        "ex\u{0}ample.com"
    );
    assert_eq!(v["network"]["allow"][0]["spec"], "tcp://ex\u{0}ample.com");

    let v = ok("[program.env]\nA = \"x\\u0000y\"\n");
    assert_eq!(v["program"]["env"]["A"], "x\u{0}y");

    // Percent-decoding gets there with no TOML escape involved at all.
    let v = ok("[http]\nallow = [\"GET example.com/a%00b\"]\n");
    assert_eq!(v["http"]["allow"][0]["path"], "/a\u{0}b");
}

/// A value long enough to outgrow any fixed buffer a consumer might have, and
/// enough of them to outgrow a single allocation, have to come back byte for
/// byte. Length is not part of any grammar here, so a limit appearing would be
/// an artifact of the plumbing rather than a decision.
#[test]
fn very_long_values_survive_the_round_trip() {
    let long = "/".to_string() + &"a".repeat(500_000);
    let v = ok(&format!("[filesystem]\nread = [\"{long}\"]\n"));
    assert_eq!(v["filesystem"]["read"][0], long);

    let many: Vec<String> = (0..2_000)
        .map(|i| format!("\"/p{i}/{}\"", "b".repeat(500)))
        .collect();
    let v = ok(&format!("[filesystem]\nread = [{}]\n", many.join(", ")));
    assert_eq!(v["filesystem"]["read"].as_array().unwrap().len(), 2_000);
}

/// Nesting is the classic way to turn a recursive-descent parser into a stack
/// overflow, which across a C ABI aborts the caller's whole process rather
/// than returning an error it can handle. The depth limit belongs to the TOML
/// parser; this pins that we are behind one.
#[test]
fn deeply_nested_input_is_an_error_not_a_stack_overflow() {
    let deep = format!(
        "[filesystem]\nread = {}{}\n",
        "[".repeat(100_000),
        "]".repeat(100_000)
    );
    assert!(err(&deep).contains("TOML parse error"));

    let tables = format!(
        "[program]\nenv = {}\"v\"{}\n",
        "{a=".repeat(5_000),
        "}".repeat(5_000)
    );
    assert!(err(&tables).contains("TOML parse error"));
}

/// The document is handed to a C caller as one NUL-terminated string, so it
/// has to be valid UTF-8 whatever the profile contained, and it has to
/// deserialize back into the canonical type: `deny_unknown_fields` on that type
/// means a round trip also proves no stray key crept into the emitted JSON.
#[test]
fn the_emitted_document_always_round_trips() {
    for toml in [
        "",
        "[filesystem]\nread = [\"/a\\u0000b\"]\n",
        "[program.env]\n\"\" = \"v\"\n",
        "[filesystem]\nread = [\"/\\u00e9/\\u0001/\\u007f\"]\n",
        "[network]\nallow = [\"tcp://\\u043f\\u0440\\u0438.\\u0440\\u0444:443\"]\n",
        "[filesystem]\nmount = [\"/v:/a:b:ro\"]\n",
    ] {
        let json = canonical::parse_to_json(toml).unwrap_or_else(|e| panic!("{toml:?}: {e}"));
        let back: canonical::CanonicalProfile = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("{toml:?} did not round trip: {e}"));
        assert_eq!(back, canonical::parse(toml).unwrap(), "profile: {toml:?}");
    }
}
