# `sandlock learn`: profile generation

`sandlock learn` runs a workload under observation and emits a
sandlock profile (TOML) covering the filesystem paths, network connections,
and resource peaks the workload actually used. The resulting profile can be
passed directly to `sandlock run -p`.

## Synopsis

```
sandlock learn [options] -- <cmd> [args...]
```

| Flag | Default | Description |
|---|---|---|
| `-o <file>` | stdout | Write profile to file |
| `--timeout <secs>` | none | Kill workload after N seconds, emit partial profile |
| `--collapse [N]` | off | Collapse directories where ≥N files were observed (default N=4) |
| `--collapse-prefix <path>` | none | Force collapse of all paths under prefix (repeatable) |
| `--force-sensitive-collapse` | off | Allow `--collapse-prefix` to target sensitive paths (requires `--collapse-prefix`) |
| `--http-inject-ca <path>` | none | System CA bundle path; sandlock splices an ephemeral CA in at `open()` time so HTTPS is intercepted. |
| `--http-ca-out <path>` | none | Write the ephemeral MITM CA public cert to a file and record the path in the profile. Runtimes with a compiled-in CA store (e.g. Node.js) ignore the system bundle patched by `--http-inject-ca`; pair with `--env NODE_EXTRA_CA_CERTS=<path>` to point the runtime at the cert. |
| `--http-port <port>` | none | Additional TCP port to intercept (repeatable). |
| `--env KEY=VALUE` | none | Set an environment variable for the observed process (repeatable). |

## What is recorded

| Domain | Mechanism |
|---|---|
| Filesystem reads | seccomp-notify on `openat`/`open` |
| Filesystem writes | Same; classified by open flags (`O_WRONLY`, `O_RDWR`, `O_CREAT`) |
| Executed binaries and libraries | `/proc/<pid>/exe` + r-xp mappings from `/proc/<pid>/maps` |
| Network connections (TCP/UDP) | seccomp-notify on `connect`/`sendto`/`sendmsg` |
| HTTP method + host + path | Transparent proxy in logging-only mode (always on, see below) |
| Resource peaks | `/proc/<pid>/status` sampling: RSS, thread count, fd count |

## Path collapsing

By default every observed path is recorded individually. `--collapse N`
aggregates directories where ≥N files were touched, reducing profile
verbosity for large trees like `/usr/lib`.

After collapsing, **dedup** removes any individual path already covered by
an ancestor in the list, Landlock `PATH_BENEATH` grants are recursive, so
the ancestor entry is sufficient.

### Write collapse (automatic)

New files created during the run don't exist on the real filesystem (COW
intercepts them). Landlock requires an existing path, so the collapser
automatically walks up to the nearest existing ancestor. This is not
optional, so omitting the ancestor would cause `sandlock run` to abort.

### Path tiers

| Tier | Paths | Write collapse | `--collapse` / `--collapse-prefix` |
|---|---|---|---|
| **Protected** | `/`, `/root`, paths ending in `/.ssh` `/.aws` `/.kube` `/.gnupg` | skip + error | never (keep individual files; override with `--force-sensitive-collapse`) |
| **Guarded** | `$HOME`, `/etc`, `/proc`, `/sys`, `/dev`, `/boot`, `/run/secrets` | emit + warning + diff | never (keep individual files; override with `--force-sensitive-collapse`) |
| **Normal** | everything else | collapse freely | collapse freely |

The tiers apply to write collapse (when a non-existent path's nearest existing ancestor is used as the Landlock grant). Direct writes to an existing path are always recorded; a notice is printed to stderr when the path is Protected or Guarded. **The sole exception is `/`: a direct read or write of the filesystem root is always dropped with a warning, since granting `/` would subsume every other entry in the profile.**

When a write collapse lands on a guarded path, a warning is printed to
stderr along with an **observed-vs-granted diff**, the list of siblings
in that directory the workload never touched but will now have write access
to. The operator can use this to decide whether the grant is acceptable.

`--force-sensitive-collapse` allows `--collapse-prefix` to target protected
and guarded paths. A warning and diff are still printed.

## HTTP/HTTPS observation

The transparent proxy always runs in logging-only mode during `sandlock learn`. Method, host, and path of every request are recorded as `[http].allow` rules. By default port 80 is intercepted; port 443 requires `--http-inject-ca` (sandlock splices an ephemeral CA into the named bundle at `open()` time); passing `--http-port` overrides the default and intercepts only the specified ports. The inject-ca path is written to `[config].http_inject_ca` so `sandlock run` picks it up automatically. `[http].deny` rules are not learned.

## Tests

Tests require Linux 5.6+ (seccomp notif) and Linux 5.13+ (Landlock). They run the real `sandlock` binary, so build first:

```bash
cargo build -p sandlock-cli
```
Each test spawns a full sandlock process; running too many in
parallel exhausts kernel limits and causes hangs, use `--test-threads=4`.
```bash
# learn output tests - verify TOML profile content
cargo test -p sandlock-cli --test learn_test -- --test-threads=4

# learn round-trip tests - learn → profile → run end-to-end
cargo test -p sandlock-cli --test learn_integration -- --test-threads=4
```

## Example

```
# Observe a Python script and generate a profile
sandlock learn -o profile.toml -- python3 build.py

# Run under the generated profile
sandlock run -p profile.toml -- python3 build.py

# Collapse common library directories for a tighter profile
sandlock learn --collapse -o profile.toml -- python3 build.py
```
