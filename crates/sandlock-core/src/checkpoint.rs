use serde::{Serialize, Deserialize};
use crate::policy::Policy;
use crate::error::{SandlockError, SandboxError};
use std::io;
use std::path::PathBuf;

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

/// Captured process state via ptrace + /proc.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProcessState {
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
// ptrace helpers
// ---------------------------------------------------------------------------

fn ptrace_attach(pid: i32) -> io::Result<()> {
    let ret = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // Wait for the process to stop
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
    // user_regs_struct is 27 u64 fields on x86_64 (216 bytes)
    let mut regs = vec![0u64; 27];
    let ret = unsafe { libc::ptrace(libc::PTRACE_GETREGS, pid, 0, regs.as_mut_ptr()) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(regs)
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
// Memory capture
// ---------------------------------------------------------------------------

fn capture_memory(pid: i32, maps: &[MemoryMap]) -> io::Result<Vec<MemorySegment>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut mem_file = std::fs::File::open(format!("/proc/{}/mem", pid))?;
    let mut segments = Vec::new();

    for map in maps {
        // Only capture writable, private, non-special segments
        if !map.writable() || !map.private() || map.is_special() {
            continue;
        }
        let size = (map.end - map.start) as usize;
        if size > 256 * 1024 * 1024 {
            continue; // skip segments > 256MB
        }

        let mut data = vec![0u8; size];
        if mem_file.seek(SeekFrom::Start(map.start)).is_ok()
            && mem_file.read_exact(&mut data).is_ok()
        {
            segments.push(MemorySegment {
                start: map.start,
                data,
            });
        }
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
    // Attach via ptrace
    ptrace_attach(pid).map_err(|e| {
        SandlockError::Sandbox(SandboxError::Child(format!("ptrace attach: {}", e)))
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

    Ok(Checkpoint {
        name: String::new(),
        policy: policy.clone(),
        process_state: ProcessState {
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
// Save / Load
// ---------------------------------------------------------------------------

impl Checkpoint {
    pub fn save(&self, path: &std::path::Path) -> Result<(), SandlockError> {
        let file = std::fs::File::create(path)
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        bincode::serialize_into(file, self).map_err(|e| {
            SandlockError::Sandbox(SandboxError::Child(format!("serialize: {}", e)))
        })?;
        Ok(())
    }

    pub fn load(path: &std::path::Path) -> Result<Self, SandlockError> {
        let file = std::fs::File::open(path)
            .map_err(|e| SandlockError::Sandbox(SandboxError::Io(e)))?;
        bincode::deserialize_from(file).map_err(|e| {
            SandlockError::Sandbox(SandboxError::Child(format!("deserialize: {}", e)))
        })
    }
}
