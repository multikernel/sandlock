use serde::{Serialize, Deserialize};
use crate::policy::Policy;
use crate::error::{SandlockError, SandboxError};
use std::io;
use std::path::{Path, PathBuf};

/// A frozen snapshot of sandbox state.
#[derive(Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub name: String,
    pub policy: Policy,
    pub process_state: ProcessState,
    pub fd_table: Vec<FdInfo>,
    pub cow_snapshot: Option<PathBuf>,
    pub app_state: Option<Vec<u8>>,
}

/// Captured process state via ptrace (registers) + process_vm_readv (memory) + /proc (metadata).
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessState {
    pub pid: i32,
    pub cwd: String,
    pub exe: String,
    pub regs: Vec<u64>,
    pub memory_maps: Vec<MemoryMap>,
    pub memory_data: Vec<MemorySegment>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemorySegment {
    pub start: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMap {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub path: Option<String>,
}

impl MemoryMap {
    pub fn writable(&self) -> bool {
        self.perms.starts_with("rw")
    }

    pub fn private(&self) -> bool {
        self.perms.contains('p')
    }

    pub fn is_special(&self) -> bool {
        self.path.as_ref().map_or(false, |p| {
            p.starts_with("[vdso]") || p.starts_with("[vvar]") || p.starts_with("[vsyscall]")
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FdInfo {
    pub fd: i32,
    pub path: String,
    pub flags: i32,
    pub offset: u64,
}

// ---------------------------------------------------------------------------
// ptrace helpers — PTRACE_SEIZE (doesn't auto-SIGSTOP like ATTACH)
// ---------------------------------------------------------------------------

fn ptrace_seize(pid: i32) -> io::Result<()> {
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_SEIZE as libc::c_uint, pid, 0, 0)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // PTRACE_INTERRUPT stops the tracee without SIGSTOP side effects
    let ret = unsafe {
        libc::ptrace(libc::PTRACE_INTERRUPT as libc::c_uint, pid, 0, 0)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // Wait for the ptrace-stop
    let mut status: i32 = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    Ok(())
}

fn ptrace_detach(pid: i32) -> io::Result<()> {
    let ret = unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ptrace_getregs(pid: i32) -> io::Result<Vec<u64>> {
    #[cfg(target_arch = "x86_64")]
    {
        // user_regs_struct is 27 u64 fields on x86_64 (216 bytes)
        let mut regs = vec![0u64; 27];
        let ret = unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, 0, regs.as_mut_ptr()) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(regs)
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Linux arm64 exposes general-purpose registers through
        // PTRACE_GETREGSET/NT_PRSTATUS. user_pt_regs is:
        // x0-x30, sp, pc, pstate (34 u64 values).
        const NT_PRSTATUS: libc::c_int = 1;
        let mut regs = vec![0u64; 34];
        let mut iov = libc::iovec {
            iov_base: regs.as_mut_ptr() as *mut libc::c_void,
            iov_len: regs.len() * std::mem::size_of::<u64>(),
        };
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid,
                NT_PRSTATUS as usize as *mut libc::c_void,
                &mut iov as *mut libc::iovec as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        regs.truncate(iov.iov_len / std::mem::size_of::<u64>());
        Ok(regs)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = pid;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "checkpoint register capture is not implemented on this architecture",
        ))
    }
}

// ---------------------------------------------------------------------------
// /proc parsing
// ---------------------------------------------------------------------------

fn parse_proc_maps(pid: i32) -> io::Result<Vec<MemoryMap>> {
    let content = std::fs::read_to_string(format!("/proc/{}/maps", pid))?;
    let mut maps = Vec::new();
    for line in content.lines() {
        // Format: start-end perms offset dev inode [pathname]
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 5 {
            continue;
        }
        let addrs: Vec<&str> = parts[0].split('-').collect();
        if addrs.len() != 2 {
            continue;
        }
        let start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(addrs[1], 16).unwrap_or(0);
        let perms = parts[1].to_string();
        let offset = u64::from_str_radix(parts[2], 16).unwrap_or(0);
        let path = if parts.len() >= 6 {
            let p = parts[5].trim();
            if p.is_empty() {
                None
            } else {
                Some(p.to_string())
            }
        } else {
            None
        };
        maps.push(MemoryMap {
            start,
            end,
            perms,
            offset,
            path,
        });
    }
    Ok(maps)
}

// ---------------------------------------------------------------------------
// Memory capture — process_vm_readv (scatter-gather, no file I/O)
// ---------------------------------------------------------------------------

fn capture_memory(pid: i32, maps: &[MemoryMap]) -> io::Result<Vec<MemorySegment>> {
    let mut segments = Vec::new();

    for map in maps {
        if !map.writable() || !map.private() || map.is_special() {
            continue;
        }
        let size = (map.end - map.start) as usize;
        if size > 256 * 1024 * 1024 {
            continue; // skip segments > 256MB
        }

        let mut data = vec![0u8; size];

        let local_iov = libc::iovec {
            iov_base: data.as_mut_ptr() as *mut libc::c_void,
            iov_len: size,
        };
        let remote_iov = libc::iovec {
            iov_base: map.start as *mut libc::c_void,
            iov_len: size,
        };

        let ret = unsafe {
            libc::process_vm_readv(
                pid as libc::pid_t,
                &local_iov as *const libc::iovec,
                1,
                &remote_iov as *const libc::iovec,
                1,
                0,
            )
        };

        if ret == size as isize {
            segments.push(MemorySegment {
                start: map.start,
                data,
            });
        }
        // Skip unreadable segments silently (same as old behavior)
    }
    Ok(segments)
}

// ---------------------------------------------------------------------------
// FD table capture
// ---------------------------------------------------------------------------

fn capture_fd_table(pid: i32) -> io::Result<Vec<FdInfo>> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut fds = Vec::new();

    for entry in std::fs::read_dir(&fd_dir)? {
        let entry = entry?;
        let fd_str = entry.file_name().into_string().unwrap_or_default();
        let fd: i32 = match fd_str.parse() {
            Ok(f) => f,
            Err(_) => continue,
        };

        let path = std::fs::read_link(entry.path())
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        // Parse fdinfo for flags and offset
        let (flags, offset) = parse_fdinfo(pid, fd).unwrap_or((0, 0));

        fds.push(FdInfo {
            fd,
            path,
            flags,
            offset,
        });
    }

    fds.sort_by_key(|f| f.fd);
    Ok(fds)
}

fn parse_fdinfo(pid: i32, fd: i32) -> io::Result<(i32, u64)> {
    let content = std::fs::read_to_string(format!("/proc/{}/fdinfo/{}", pid, fd))?;
    let mut flags = 0i32;
    let mut pos = 0u64;
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("flags:\t") {
            flags = i32::from_str_radix(val.trim(), 8).unwrap_or(0);
        }
        if let Some(val) = line.strip_prefix("pos:\t") {
            pos = val.trim().parse().unwrap_or(0);
        }
    }
    Ok((flags, pos))
}

// ---------------------------------------------------------------------------
// Main capture function
// ---------------------------------------------------------------------------

/// Capture a checkpoint from a running, stopped sandbox.
/// The sandbox must already be frozen (SIGSTOP'd and fork-held).
pub(crate) fn capture(pid: i32, policy: &Policy) -> Result<Checkpoint, SandlockError> {
    // Seize via ptrace (PTRACE_SEIZE + PTRACE_INTERRUPT — doesn't auto-SIGSTOP)
    ptrace_seize(pid).map_err(|e| {
        SandlockError::Sandbox(SandboxError::Child(format!("ptrace seize: {}", e)))
    })?;

    // Capture registers
    let regs = ptrace_getregs(pid).map_err(|e| {
        SandlockError::Sandbox(SandboxError::Child(format!("ptrace getregs: {}", e)))
    })?;

    // Capture memory maps
    let maps =
        parse_proc_maps(pid).map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;

    // Capture memory data
    let memory_data =
        capture_memory(pid, &maps).map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;

    // Capture fd table
    let fd_table =
        capture_fd_table(pid).map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;

    // Detach
    ptrace_detach(pid).map_err(|e| {
        SandlockError::Sandbox(SandboxError::Child(format!("ptrace detach: {}", e)))
    })?;

    // Capture cwd and exe from /proc
    let cwd = std::fs::read_link(format!("/proc/{}/cwd", pid))
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    Ok(Checkpoint {
        name: String::new(),
        policy: policy.clone(),
        process_state: ProcessState {
            pid,
            cwd,
            exe,
            regs,
            memory_maps: maps,
            memory_data,
        },
        fd_table,
        cow_snapshot: None,
        app_state: None,
    })
}

// ---------------------------------------------------------------------------
// Save / Load — directory-based format
// ---------------------------------------------------------------------------
//
// Layout:
//   <dir>/
//   ├── meta.json            # name, cow_snapshot
//   ├── policy.dat           # bincode-serialized Policy
//   ├── app_state.bin        # optional raw app state
//   └── process/
//       ├── info.json        # pid, cwd, exe
//       ├── fds.json         # file descriptor table
//       ├── memory_map.json  # region metadata
//       ├── threads/
//       │   └── 0.bin        # raw register bytes (main thread)
//       └── memory/
//           └── <index>.bin  # raw memory contents per segment

fn io_err(e: impl std::fmt::Display) -> SandlockError {
    SandlockError::Sandbox(SandboxError::Child(e.to_string()))
}

fn write_json<T: Serialize>(path: &Path, val: &T) -> Result<(), SandlockError> {
    let json = serde_json::to_string_pretty(val).map_err(io_err)?;
    std::fs::write(path, json).map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, SandlockError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
    serde_json::from_str(&data).map_err(io_err)
}

/// JSON schema for meta.json.
#[derive(Serialize, Deserialize)]
struct MetaJson {
    name: String,
    cow_snapshot: Option<String>,
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
                .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        }
        std::fs::create_dir_all(&tmp)
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;

        let res = self.save_inner(&tmp);
        if res.is_err() {
            let _ = std::fs::remove_dir_all(&tmp);
            return res;
        }

        // Atomic rename into place
        if dir.exists() {
            std::fs::remove_dir_all(dir)
                .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        }
        std::fs::rename(&tmp, dir)
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;

        Ok(())
    }

    fn save_inner(&self, dir: &Path) -> Result<(), SandlockError> {
        // meta.json
        write_json(&dir.join("meta.json"), &MetaJson {
            name: self.name.clone(),
            cow_snapshot: self.cow_snapshot.as_ref().map(|p| p.display().to_string()),
        })?;

        // policy.dat (bincode — complex struct, not human-readable anyway)
        let policy_bytes = bincode::serialize(&self.policy).map_err(io_err)?;
        std::fs::write(dir.join("policy.dat"), &policy_bytes)
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;

        // app_state.bin
        if let Some(ref state) = self.app_state {
            std::fs::write(dir.join("app_state.bin"), state)
                .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        }

        // process/
        let proc_dir = dir.join("process");
        std::fs::create_dir(&proc_dir)
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;

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

        // process/memory_map.json — only captured segments (1:1 with memory/*.bin)
        // Build map entries for each captured segment by matching start address
        let maps: Vec<MemoryMapJson> = self.process_state.memory_data.iter().map(|seg| {
            // Find the corresponding full map entry
            let map = self.process_state.memory_maps.iter()
                .find(|m| m.start == seg.start);
            match map {
                Some(m) => MemoryMapJson {
                    start: m.start,
                    end: m.end,
                    perms: m.perms.clone(),
                    offset: m.offset,
                    path: m.path.clone(),
                },
                None => MemoryMapJson {
                    start: seg.start,
                    end: seg.start + seg.data.len() as u64,
                    perms: "rw-p".to_string(),
                    offset: 0,
                    path: None,
                },
            }
        }).collect();
        write_json(&proc_dir.join("memory_map.json"), &maps)?;

        // process/threads/0.bin — main thread register state
        let threads_dir = proc_dir.join("threads");
        std::fs::create_dir(&threads_dir)
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        let reg_bytes: Vec<u8> = self.process_state.regs.iter()
            .flat_map(|r| r.to_le_bytes())
            .collect();
        std::fs::write(threads_dir.join("0.bin"), &reg_bytes)
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;

        // process/memory/<index>.bin — 1:1 with memory_map.json entries
        let mem_dir = proc_dir.join("memory");
        std::fs::create_dir(&mem_dir)
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        for (i, seg) in self.process_state.memory_data.iter().enumerate() {
            std::fs::write(mem_dir.join(format!("{}.bin", i)), &seg.data)
                .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        }

        Ok(())
    }

    /// Load a checkpoint from a directory.
    pub fn load(dir: &Path) -> Result<Self, SandlockError> {
        if !dir.is_dir() {
            return Err(SandlockError::Sandbox(SandboxError::Child(
                format!("Checkpoint not found: {}", dir.display()),
            )));
        }

        // meta.json
        let meta: MetaJson = read_json(&dir.join("meta.json"))?;

        // policy.dat
        let policy_bytes = std::fs::read(dir.join("policy.dat"))
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        let policy: Policy = bincode::deserialize(&policy_bytes).map_err(io_err)?;

        // app_state.bin
        let app_state_path = dir.join("app_state.bin");
        let app_state = if app_state_path.exists() {
            Some(std::fs::read(&app_state_path)
                .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?)
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

        // process/memory_map.json — 1:1 with memory/<i>.bin
        let maps_json: Vec<MemoryMapJson> = read_json(&proc_dir.join("memory_map.json"))?;
        let memory_maps: Vec<MemoryMap> = maps_json.iter().map(|m| MemoryMap {
            start: m.start,
            end: m.end,
            perms: m.perms.clone(),
            offset: m.offset,
            path: m.path.clone(),
        }).collect();

        // process/threads/0.bin
        let reg_bytes = std::fs::read(proc_dir.join("threads").join("0.bin"))
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        let regs: Vec<u64> = reg_bytes.chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect();

        // process/memory/<i>.bin — 1:1 with memory_map.json
        let mem_dir = proc_dir.join("memory");
        let mut memory_data = Vec::new();
        for (i, map) in maps_json.iter().enumerate() {
            let seg_path = mem_dir.join(format!("{}.bin", i));
            let data = std::fs::read(&seg_path)
                .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
            memory_data.push(MemorySegment {
                start: map.start,
                data,
            });
        }

        Ok(Checkpoint {
            name: meta.name,
            policy,
            process_state: ProcessState {
                pid: info.pid,
                cwd: info.cwd,
                exe: info.exe,
                regs,
                memory_maps,
                memory_data,
            },
            fd_table,
            cow_snapshot: meta.cow_snapshot.map(PathBuf::from),
            app_state,
        })
    }
}
