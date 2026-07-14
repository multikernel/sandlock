use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use crate::sandbox::Sandbox;

pub(crate) mod capture;
mod image;
mod inject;
mod regs;
pub(crate) mod resume;
// The execve-stub restore path (blob serializer, supervisor pager, fd
// convention) is validated by its own unit tests and the end-to-end
// `test_restore_stub` integration test, but is not yet wired into the live
// restore code (which still uses the injection engine). The `allow(dead_code)`
// stands until the supervisor cutover replaces that path; drop it then.
#[allow(dead_code)]
pub(crate) mod restore_blob;
#[allow(dead_code)]
pub(crate) mod pager;

/// Fixed inherited-fd convention for the execve restore-stub.
#[allow(dead_code)]
pub(crate) const CTRL_FD: i32 = 3;   // control-blob memfd
#[allow(dead_code)]
pub(crate) const READY_FD: i32 = 4;  // eventfd: stub -> supervisor ("uffd ready")
#[allow(dead_code)]
pub(crate) const GO_FD: i32 = 5;     // eventfd: supervisor -> stub ("pager attached")
#[allow(dead_code)]
pub(crate) const UFFD_SLOT: i32 = 6; // stub dup2's its userfaultfd here

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
            // `[vvar_vclock]` is a newer-kernel split of `[vvar]`; it is also
            // kernel-provided and relocated (not captured) during restore.
            p.starts_with("[vdso]")
                || p.starts_with("[vvar]")
                || p.starts_with("[vvar_vclock]")
                || p.starts_with("[vsyscall]")
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
