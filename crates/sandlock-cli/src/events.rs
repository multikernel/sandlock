//! Versioned supervisor observations, never a claim of complete syscall audit.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use sandlock_core::policy_fn::{SyscallCategory, SyscallEvent};
use sandlock_core::{Change, Entry};
use serde_json::{json, Value};

const MAX_BYTES: u64 = 64 * 1024 * 1024;

struct State {
    file: File,
    sequence: u64,
    bytes: u64,
    failed: bool,
}

#[derive(Clone)]
pub(crate) struct Events(Arc<Mutex<State>>);

impl Events {
    /// Create a new regular file only, outside every writable or mounted tree.
    pub(crate) fn create(path: &Path, grants: &[PathBuf]) -> io::Result<(Self, PathBuf)> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let path = parent.canonicalize()?.join(path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "events path requires a file name",
            )
        })?);
        for grant in grants {
            if path.starts_with(grant.canonicalize()?) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "events file must be outside sandbox write/mount/workdir grants",
                ));
            }
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        Ok((
            Self(Arc::new(Mutex::new(State {
                file,
                sequence: 0,
                bytes: 0,
                failed: false,
            }))),
            path,
        ))
    }

    pub(crate) fn emit(&self, kind: &str, detail: Value) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("events lock poisoned"))?;
        if state.failed {
            return Err(io::Error::other("events stream already failed"));
        }
        state.sequence += 1;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let mut line = serde_json::to_vec(&json!({
            "schema_version": 1, "sequence": state.sequence, "ts_unix_ms": ts,
            "source": "sandlock-cli", "type": kind, "detail": detail,
        }))?;
        line.push(b'\n');
        if state.bytes + line.len() as u64 > MAX_BYTES {
            state.failed = true;
            return Err(io::Error::other("events stream exceeded 64 MiB"));
        }
        if let Err(e) = state.file.write_all(&line) {
            state.failed = true;
            return Err(e);
        }
        state.bytes += line.len() as u64;
        Ok(())
    }

    pub(crate) fn syscall(&self, event: SyscallEvent) -> io::Result<()> {
        if event
            .path
            .iter()
            .chain(event.path2.iter())
            .any(|p| p.to_str().is_none())
        {
            if let Ok(mut state) = self.0.lock() {
                state.failed = true;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-UTF-8 event path",
            ));
        }
        let category = match event.category {
            SyscallCategory::File => "file",
            SyscallCategory::Network => "network",
            SyscallCategory::Process => "process",
            SyscallCategory::Memory => "memory",
        };
        self.emit(
            "syscall",
            json!({
                "syscall": event.syscall, "category": category, "pid": event.pid,
                "parent_pid": event.parent_pid, "host": event.host, "port": event.port,
                "protocol": event.protocol, "fd": event.fd, "size": event.size,
                "path": event.path, "path2": event.path2, "flags": event.flags,
                "supervisor_denied": event.denied,
                "kernel_outcome": "not_observed", "path_is_observation_only": true,
                "argv_omitted": true,
            }),
        )
    }

    pub(crate) fn changes(&self, changes: &[Change], dry_run: bool) -> io::Result<()> {
        for change in changes {
            let path = change.path.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 change path")
            })?;
            self.emit("change", json!({
                "path": path, "kind": change.kind().to_string(),
                "before": change.before.as_ref().map(entry), "after": change.after.as_ref().map(entry),
                "dry_run": dry_run, "phase": "cow_before_branch_action",
            }))?;
        }
        Ok(())
    }

    pub(crate) fn sync(&self) -> io::Result<()> {
        let state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("events lock poisoned"))?;
        if state.failed {
            return Err(io::Error::other(
                "events incomplete: write failed or size limit exceeded",
            ));
        }
        state.file.sync_all()
    }
}

fn entry(entry: &Entry) -> Value {
    // No bytes, symlink target or digest: avoid copying data into audit by default.
    json!({"kind": format!("{:?}", entry.kind).to_lowercase(), "mode": entry.mode, "size": entry.size})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_file_is_exclusive_and_rejects_writable_parent() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        assert!(Events::create(&path, &[root.path().to_owned()]).is_err());
        let (events, _) = Events::create(&path, &[]).unwrap();
        events.emit("start", json!({})).unwrap();
        events
            .emit("finish", json!({"status":"succeeded"}))
            .unwrap();
        events.sync().unwrap();
        assert!(Events::create(&path, &[]).is_err());
        let text = std::fs::read_to_string(&path).unwrap();
        let rows: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows[0]["sequence"], 1);
        assert_eq!(rows[1]["sequence"], 2);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn rejects_symlink_and_marks_write_limit_failure() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(root.path().join("target"), &link).unwrap();
        assert!(Events::create(&link, &[]).is_err());
        let (events, _) = Events::create(&root.path().join("log"), &[]).unwrap();
        events.0.lock().unwrap().bytes = MAX_BYTES;
        assert!(events.emit("syscall", json!({})).is_err());
        assert!(events.sync().is_err());
    }

    #[test]
    fn non_utf8_observation_fails_without_panicking_or_claiming_complete() {
        use std::os::unix::ffi::OsStringExt;
        let root = tempfile::tempdir().unwrap();
        let (events, _) = Events::create(&root.path().join("log"), &[]).unwrap();
        let event = SyscallEvent {
            syscall: "openat".into(),
            category: SyscallCategory::File,
            pid: 1,
            parent_pid: None,
            host: None,
            port: None,
            size: None,
            argv: None,
            denied: false,
            path: Some(std::ffi::OsString::from_vec(vec![255]).into()),
            path2: None,
            flags: None,
            protocol: None,
            fd: None,
        };
        assert!(events.syscall(event).is_err());
        assert!(events.sync().is_err());
    }
}
