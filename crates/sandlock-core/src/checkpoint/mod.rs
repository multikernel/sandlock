use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use crate::sandbox::Sandbox;

pub(crate) mod capture;
mod image;
mod inject;
mod regs;
pub(crate) mod resume;

pub(crate) use capture::capture;

/// A frozen snapshot of sandbox state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub name: String,
    pub policy: Sandbox,
    pub process_state: ProcessState,
    pub fd_table: Vec<FdInfo>,
    pub cow_snapshot: Option<PathBuf>,
    pub app_state: Option<Vec<u8>>,
}

/// Captured process state via ptrace (registers) + process_vm_readv (memory) + /proc (metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessState {
    pub pid: i32,
    pub cwd: String,
    pub exe: String,
    pub regs: Vec<u64>,
    pub fpregs: Vec<u8>,
    pub memory_maps: Vec<MemoryMap>,
    pub memory_data: Vec<MemorySegment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySegment {
    pub start: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdInfo {
    pub fd: i32,
    pub path: String,
    pub flags: i32,
    pub offset: u64,
}

/// An fd that a restore could not transparently recreate (socket, pipe,
/// memfd, deleted or pseudo-filesystem path). The restored process runs
/// without it; such resources fall to the `app_state` hatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedFd {
    /// The fd number in the checkpointed process.
    pub fd: i32,
    /// The resource the fd pointed at (e.g. `pipe:[12345]`, `/memfd:x`).
    pub path: String,
}
