use serde::{Serialize, Deserialize};
use std::path::{Path, PathBuf};
use super::{Checkpoint, ProcessState, MemorySegment, MemoryMap, FdInfo};
use crate::error::{SandlockError, SandboxRuntimeError};
use crate::sandbox::Sandbox;

// ---------------------------------------------------------------------------
// Save / Load -- directory-based format
// ---------------------------------------------------------------------------
//
// Layout:
//   <dir>/
//   ├── meta.json            # name, cow_snapshot
//   ├── policy.dat           # bincode-serialized Sandbox
//   ├── app_state.bin        # optional raw app state
//   └── process/
//       ├── info.json        # pid, cwd, exe
//       ├── fds.json         # file descriptor table
//       ├── memory_map.json  # FULL region metadata (every mapping)
//       ├── threads/
//       │   └── 0.bin        # raw register bytes (main thread)
//       └── memory/
//           └── <start_hex>.bin  # captured bytes for a region, keyed by its
//                                # start address (only regions with data)
//
// `memory_map.json` lists *every* mapping (not just captured ones) so that
// restore can `RemapFromFile` the file-backed regions (e.g. the executable
// text) that were never captured into `memory/`. Each `memory/<start_hex>.bin`
// is re-associated with its map entry by matching start address.

const IMAGE_VERSION: u32 = 2;

fn io_err(e: impl std::fmt::Display) -> SandlockError {
    SandlockError::Runtime(SandboxRuntimeError::Child(e.to_string()))
}

fn write_json<T: Serialize>(path: &Path, val: &T) -> Result<(), SandlockError> {
    let json = serde_json::to_string_pretty(val).map_err(io_err)?;
    std::fs::write(path, json).map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, SandlockError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
    serde_json::from_str(&data).map_err(io_err)
}

/// JSON schema for meta.json.
#[derive(Serialize, Deserialize)]
struct MetaJson {
    name: String,
    cow_snapshot: Option<String>,
    #[serde(default)]
    version: u32,
}

/// JSON schema for process/info.json.
#[derive(Serialize, Deserialize)]
struct InfoJson {
    pid: i32,
    cwd: String,
    exe: String,
}

/// JSON schema for each entry in process/fds.json.
#[derive(Serialize, Deserialize)]
struct FdJson {
    fd: i32,
    path: String,
    flags: i32,
    offset: u64,
}

/// JSON schema for each entry in process/memory_map.json.
#[derive(Serialize, Deserialize)]
struct MemoryMapJson {
    start: u64,
    end: u64,
    perms: String,
    offset: u64,
    path: Option<String>,
}

impl Checkpoint {
    /// Persist this checkpoint to a directory.
    ///
    /// Writes atomically: creates `<dir>.tmp`, populates it, then renames.
    pub fn save(&self, dir: &Path) -> Result<(), SandlockError> {
        let tmp = dir.with_extension("tmp");
        if tmp.exists() {
            std::fs::remove_dir_all(&tmp)
                .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
        }
        std::fs::create_dir_all(&tmp)
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;

        let res = self.save_inner(&tmp);
        if res.is_err() {
            let _ = std::fs::remove_dir_all(&tmp);
            return res;
        }

        // Atomic rename into place
        if dir.exists() {
            std::fs::remove_dir_all(dir)
                .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
        }
        std::fs::rename(&tmp, dir)
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;

        Ok(())
    }

    fn save_inner(&self, dir: &Path) -> Result<(), SandlockError> {
        // meta.json
        write_json(&dir.join("meta.json"), &MetaJson {
            name: self.name.clone(),
            cow_snapshot: self.cow_snapshot.as_ref().map(|p| p.display().to_string()),
            version: IMAGE_VERSION,
        })?;

        // policy.dat (bincode -- complex struct, not human-readable anyway)
        let policy_bytes = bincode::serialize(&self.policy).map_err(io_err)?;
        std::fs::write(dir.join("policy.dat"), &policy_bytes)
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;

        // app_state.bin
        if let Some(ref state) = self.app_state {
            std::fs::write(dir.join("app_state.bin"), state)
                .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
        }

        // process/
        let proc_dir = dir.join("process");
        std::fs::create_dir(&proc_dir)
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;

        // process/info.json
        write_json(&proc_dir.join("info.json"), &InfoJson {
            pid: self.process_state.pid,
            cwd: self.process_state.cwd.clone(),
            exe: self.process_state.exe.clone(),
        })?;

        // process/fds.json
        let fds: Vec<FdJson> = self.fd_table.iter().map(|f| FdJson {
            fd: f.fd,
            path: f.path.clone(),
            flags: f.flags,
            offset: f.offset,
        }).collect();
        write_json(&proc_dir.join("fds.json"), &fds)?;

        // process/memory_map.json -- FULL region metadata (every mapping), so
        // restore can RemapFromFile the file-backed regions (e.g. the
        // executable text) that were never captured into memory_data.
        let maps: Vec<MemoryMapJson> = self.process_state.memory_maps.iter().map(|m| MemoryMapJson {
            start: m.start,
            end: m.end,
            perms: m.perms.clone(),
            offset: m.offset,
            path: m.path.clone(),
        }).collect();
        write_json(&proc_dir.join("memory_map.json"), &maps)?;

        // process/threads/0.bin -- main thread register state
        let threads_dir = proc_dir.join("threads");
        std::fs::create_dir(&threads_dir)
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
        let reg_bytes: Vec<u8> = self.process_state.regs.iter()
            .flat_map(|r| r.to_le_bytes())
            .collect();
        std::fs::write(threads_dir.join("0.bin"), &reg_bytes)
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
        // process/threads/fpregs.bin -- FPU/extended register state
        std::fs::write(threads_dir.join("fpregs.bin"), &self.process_state.fpregs)
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;

        // process/memory/<start_hex>.bin -- captured segment bytes, keyed by
        // start address so load can re-associate each blob with its (full) map
        // entry regardless of how many uncaptured maps sit between them.
        let mem_dir = proc_dir.join("memory");
        std::fs::create_dir(&mem_dir)
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
        for seg in self.process_state.memory_data.iter() {
            std::fs::write(mem_dir.join(format!("{:x}.bin", seg.start)), &seg.data)
                .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
        }

        Ok(())
    }

    /// Load a checkpoint from a directory.
    pub fn load(dir: &Path) -> Result<Self, SandlockError> {
        if !dir.is_dir() {
            return Err(SandlockError::Runtime(SandboxRuntimeError::Child(
                format!("Checkpoint not found: {}", dir.display()),
            )));
        }

        // meta.json
        let meta: MetaJson = read_json(&dir.join("meta.json"))?;
        if meta.version != IMAGE_VERSION {
            return Err(SandlockError::Runtime(SandboxRuntimeError::Child(
                format!("unsupported checkpoint image version {} (expected {})",
                    meta.version, IMAGE_VERSION),
            )));
        }

        // policy.dat
        let policy_bytes = std::fs::read(dir.join("policy.dat"))
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
        let policy: Sandbox = bincode::deserialize(&policy_bytes).map_err(io_err)?;

        // app_state.bin
        let app_state_path = dir.join("app_state.bin");
        let app_state = if app_state_path.exists() {
            Some(std::fs::read(&app_state_path)
                .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?)
        } else {
            None
        };

        // process/
        let proc_dir = dir.join("process");

        // process/info.json
        let info: InfoJson = read_json(&proc_dir.join("info.json"))?;

        // process/fds.json
        let fds_json: Vec<FdJson> = read_json(&proc_dir.join("fds.json"))?;
        let fd_table: Vec<FdInfo> = fds_json.into_iter().map(|f| FdInfo {
            fd: f.fd,
            path: f.path,
            flags: f.flags,
            offset: f.offset,
        }).collect();

        // process/memory_map.json -- FULL region list (every mapping).
        let maps_json: Vec<MemoryMapJson> = read_json(&proc_dir.join("memory_map.json"))?;
        let memory_maps: Vec<MemoryMap> = maps_json.iter().map(|m| MemoryMap {
            start: m.start,
            end: m.end,
            perms: m.perms.clone(),
            offset: m.offset,
            path: m.path.clone(),
        }).collect();

        // process/threads/0.bin
        let threads_dir = proc_dir.join("threads");
        let reg_bytes = std::fs::read(threads_dir.join("0.bin"))
            .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
        let regs: Vec<u64> = reg_bytes.chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        // Read FP/extended registers; tolerate absence defensively.
        let fpregs = std::fs::read(threads_dir.join("fpregs.bin")).unwrap_or_default();

        // process/memory/<start_hex>.bin -- captured segments only, matched to
        // their map entry by start address. Maps without a blob (file-backed
        // regions like the executable text) carry no data and are restored via
        // RemapFromFile during resume.
        let mem_dir = proc_dir.join("memory");
        let mut memory_data = Vec::new();
        for map in &maps_json {
            let seg_path = mem_dir.join(format!("{:x}.bin", map.start));
            if seg_path.exists() {
                let data = std::fs::read(&seg_path)
                    .map_err(|e| SandlockError::Runtime(SandboxRuntimeError::Io(e)))?;
                memory_data.push(MemorySegment {
                    start: map.start,
                    data,
                });
            }
        }

        Ok(Checkpoint {
            name: meta.name,
            policy,
            process_state: ProcessState {
                pid: info.pid,
                cwd: info.cwd,
                exe: info.exe,
                regs,
                fpregs,
                memory_maps,
                memory_data,
            },
            fd_table,
            cow_snapshot: meta.cow_snapshot.map(PathBuf::from),
            app_state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Checkpoint;

    #[test]
    fn image_rejects_wrong_version() {
        let dir = std::env::temp_dir().join(format!("sandlock-ver-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("process/threads")).unwrap();
        std::fs::create_dir_all(dir.join("process/memory")).unwrap();
        std::fs::write(dir.join("meta.json"),
            br#"{"name":"x","cow_snapshot":null,"version":999}"#).unwrap();
        let res = Checkpoint::load(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("version"), "error should mention version, got: {msg}");
    }
}
