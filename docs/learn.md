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

## What is recorded

| Domain | Mechanism |
|---|---|
| Filesystem reads | seccomp-notify on `openat`/`open` |
| Filesystem writes | Same; classified by open flags (`O_WRONLY`, `O_RDWR`, `O_CREAT`) |
| Executed binaries and libraries | `/proc/<pid>/exe` + r-xp mappings from `/proc/<pid>/maps` |
| Network connections (TCP/UDP) | seccomp-notify on `connect`/`sendto`/`sendmsg` |
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

| Tier | Paths | Write (auto) | `--collapse N` | `--collapse-prefix` |
|---|---|---|---|---|
| **Protected** | `/`, `/root`, `~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg` | skip + error | never (keep individual file) | refused unless `--force-sensitive-collapse` |
| **Guarded** | `/etc`, `/proc`, `/sys`, `/dev`, `/boot`, `/run/secrets` | emit + warning + diff | never (keep individual file) | refused unless `--force-sensitive-collapse` |
| **Normal** | everything else | collapse freely | collapse freely | collapse freely |

When a write collapse lands on a guarded path, a warning is printed to
stderr along with an **observed-vs-granted diff**, the list of siblings
in that directory the workload never touched but will now have write access
to. The operator can use this to decide whether the grant is acceptable.

`--force-sensitive-collapse` allows `--collapse-prefix` to target protected
and guarded paths. A warning and diff are still printed.

## Tests

```bash
# All learn tests
cargo test -p sandlock-cli -- test_learn

Tests require Linux 5.6+ (seccomp notif) and Linux 5.13+ (Landlock). They run the real `sandlock` binary, so build first:

```bash
cargo build -p sandlock-cli
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
