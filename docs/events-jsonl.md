# CLI runtime observations and standard devices

## Opt-in JSONL output

```sh
mkdir -p "$HOME/sandlock-audit"
sandlock run -r /usr -r /lib -r /etc -w "$PWD" --workdir "$PWD" \
  --events-jsonl "$HOME/sandlock-audit/run-001.jsonl" -- python3 task.py
```

`--events-jsonl PATH` creates a **new** 0600 regular file, independently of child
stdout/stderr. It refuses an existing file, symlink, missing parent, or a location
inside a sandbox writable grant, workdir, chroot or mount. The supervisor also
adds a deny rule for the file. Keep its parent outside untrusted write grants.
This protects against sandbox writes, not a hostile host user or administrator.
`--no-supervisor` is incompatible with this option.

Every line has:

- `schema_version`: 1;
- `sequence`: strictly increasing, starting at 1;
- `ts_unix_ms`: supervisor wall-clock timestamp, not a monotonic clock;
- `source`: `sandlock-cli`;
- `type`: `start`, `syscall`, `change`, or `finish`;
- `detail`: event-specific fields.

`start` records supervisor PID, timeout, dry-run flag and coverage. It intentionally
does not copy command argv, environment, credential values or child output.

`syscall` projects the existing `policy_fn` event: name/category, PID/parent PID,
destination IP/port/protocol/fd, size, observed paths and open flags. It omits
argv entirely. Paths and addresses may themselves be sensitive: treat this
file as private operational data. Non-UTF-8/unrepresentable values fail logging
rather than silently converting the evidence to a successful result.

**Coverage and verdict semantics are limited:**

- These are intercepted supervisor observations, not a complete kernel syscall
  return trace. Enabling `policy_fn` incurs existing interception, process
  tracking and argv-freeze overhead, even though argv is not exported.
- `supervisor_denied=true` is the existing event's `denied` field: the supervisor
  chose an errno response. It does not independently classify every errno as a
  security-policy rejection. The API does not supply the final errno here.
- `supervisor_denied=false` is **not** an allow/success verdict. Landlock or a
  subsequent kernel operation can still fail. `kernel_outcome=not_observed`
  makes that explicit. Paths are observation-only, not TOCTOU-safe authorization
  inputs. The callback never relaxes the existing policy.

`change` comes from `RunResult.changes`. It includes relative path, A/M/D kind,
before/after kind/mode/size, dry-run flag and `phase=cow_before_branch_action`.
It deliberately excludes file content, link targets and hashes. It is a COW
change set captured before the branch action, **not a commit receipt**. For
example, dry-run and aborted runs may report changes that never land in the
workdir. Non-COW writes are outside this result's coverage.

`finish` records succeeded/failed exit, runtime error, or timed_out. A timeout
has exit 124 and `changes_available=false`; it never invents an empty change
set. A normal child exit 124 is failed, not timed_out. Callbacks are drained
before the terminal event; writes are synced before returning from the CLI.
The existing status-fd format and timeout behavior are unchanged.

The file is capped at 64 MiB. Write/cap failures cause held callback operations
to be denied and prevent a successful CLI completion. Observation-only effects
already performed cannot be recalled. SIGKILL, storage failure, initialization
failure, or host power loss can leave an empty/partial file with **no finish**.
Consumers must mark that stream incomplete rather than replaying the command.
This is not a tamper-evident, exactly-once or lossless kernel audit service.

## Minimal device defaults

`sandlock run` adds these existing character devices by default:

| Device | Access | Linux major:minor |
|---|---|---|
| `/dev/null` | read/write | 1:3 |
| `/dev/zero` | read | 1:5 |
| `/dev/random` | read | 1:8 |
| `/dev/urandom` | read | 1:9 |

The CLI validates each node's type and device number, and rejects symlinks or
unexpected nodes. Missing nodes are skipped; it never creates devices. For a
chroot, validation checks the node inside the rootfs. `/dev` itself, terminals,
block devices, GPU devices, `/dev/full`, and write access to random sources are
not included. Explicit denies continue to take precedence under supervision.

Use `--no-default-devices` for the previous CLI behavior. Existing explicit
grants are not removed by this option. The Rust library builder remains opt-in:
`.standard_devices()?` provides the same validated grant set without changing
the library's default policy or its profile schema. A rendered effective
policy includes ordinary path grants, not an implicit hidden permission.

## Validation

```sh
cargo test --release -p sandlock-cli --test runtime_events
cargo test --release -p sandlock-core --test integration test_http_strict_tls
```

Tests require real Linux sandbox support. Strict TLS regression coverage lives
in `sandlock-core`: it uses a temporary injected CA bundle and inline Python
with `ssl.VERIFY_X509_STRICT`, then confirms the HTTP ACL returns its expected
403 response. It needs no upstream server, system CA bundle, or OpenSSL CLI.
Tool-free certificate structure tests check the minted leaf AKI against the CA
SKI and verify the CA `keyCertSign` usage. User-provided invalid CAs are not
silently repaired. HTTPS-only credential transport enforcement remains separate
work.
