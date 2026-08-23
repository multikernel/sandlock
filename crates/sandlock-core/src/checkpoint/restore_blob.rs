//! Restore planning and the control blob handed to the freestanding
//! restore-stub through an inherited memfd.
//!
//! Every *decision* a restore makes lives here: which regions are rebuilt from
//! captured bytes and which are mapped from their files, which fds are
//! transparently reopenable, how the kernel's fresh `[vdso]`/`[vvar]` are moved
//! onto the checkpoint-recorded bases, how host-recorded paths translate into
//! the child's in-chroot view, and how the saved register file is re-armed. The
//! stub is a dumb executor of the resulting blob.
//!
//! The blob carries **control data only**: region and fd tables, the register
//! file, and the signal-frame FP image. Page contents are not in it. The stub
//! reads it into a static buffer rather than mapping it, because a
//! kernel-placed mapping could sit where a `MAP_FIXED` checkpoint region lands;
//! the supervisor writes the anonymous page contents into the stub with
//! `process_vm_writev` at the READY barrier (see `resume`).
//!
//! Little-endian, versioned. The C stub in `checkpoint/restore-stub.c` mirrors
//! this layout byte-for-byte.

use std::path::{Path, PathBuf};

use crate::checkpoint::{Checkpoint, FdInfo, MemoryMap, MemorySegment, SkippedFd};

pub(crate) const BLOB_MAGIC: u32 = 0x534c_5242; // "SLRB"
pub(crate) const BLOB_VERSION: u32 = 2;

pub(crate) const HEADER_LEN: usize = 64;
pub(crate) const REGION_ENTRY_LEN: usize = 40;
pub(crate) const FD_ENTRY_LEN: usize = 24;
pub(crate) const VDSO_ENTRY_LEN: usize = 24;

/// `src` discriminant in a region entry.
const SRC_ANON: u8 = 0;
const SRC_FILE: u8 = 1;

/// The stub's own image (text/data/bss, including its private stack and the
/// control buffer) is linked at this fixed base, far outside the address range
/// an ordinary program occupies. It must match the `-Wl,-Ttext-segment=` flag in
/// `build.rs`; `stub_links_at_the_reserved_base` checks the built binary against
/// it. A checkpoint that maps anything into this window cannot be restored
/// through the stub, because the stub's own text would be clobbered while it
/// runs (this is exactly the collision a `-no-pie` stub at the default 0x400000
/// hits against any static `ET_EXEC` workload).
///
/// x86_64 uses 3 TiB, far above any ordinary user address space.  riscv64 must
/// stay below the Sv39 ceiling of 256 GiB.
#[cfg(target_arch = "x86_64")]
pub(crate) const STUB_BASE: u64 = 0x300_0000_0000;
#[cfg(target_arch = "riscv64")]
pub(crate) const STUB_BASE: u64 = 0x30_0000_0000;
#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
pub(crate) const STUB_BASE: u64 = 0;
pub(crate) const STUB_SPAN: u64 = 0x40_0000;

/// x86_64 signal-frame FP image constants. `FP_XSTATE_MAGIC1` in the
/// `sw_reserved` area of the 512-byte fxsave block tells the kernel the buffer
/// holds a full xstate; without it the kernel falls back to `fxrstor` of the
/// legacy area only.
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// Offset of `struct _fpx_sw_bytes` within the 512-byte fxsave block.
const SW_RESERVED_OFF: usize = 464;
/// fxsave block + xstate header: the smallest buffer the kernel accepts as a
/// full xstate image.
const MIN_XSTATE_SIZE: usize = 512 + 64;

/// A restore reduced to the three things the supervisor needs: the control blob
/// for the stub, the anonymous page contents to write into it, and the fds that
/// could not be transparently recreated.
#[derive(Debug)]
pub(crate) struct RestorePlan {
    pub blob: Vec<u8>,
    /// `(start, bytes)` runs the supervisor writes into the stub once it has
    /// mapped its regions read/write.
    pub anon: Vec<(u64, Vec<u8>)>,
    /// The checkpoint's recorded layout, used to tell a restored mapping from a
    /// leftover of the stub's own startup (see [`plan_sweep`]).
    pub maps: Vec<MemoryMap>,
    pub skipped: Vec<SkippedFd>,
}

/// The mappings the stub must unmap before handing control to the restored
/// program: everything present in `current` that the checkpoint did not record.
///
/// The stub `execve`s into an address space the kernel populated for it, and not
/// all of that is overwritten by the checkpoint image. The initial stack in
/// particular sits wherever ASLR put it, which is rarely where the checkpoint's
/// `[stack]` goes, so without this sweep the restored process keeps a second,
/// writable stack it never asked for. That leftover is precisely what the
/// execve stub exists to eliminate, so the diff is computed here (with the
/// supervisor's unrestricted `/proc` access) and handed to the stub to execute.
///
/// Three things are never swept: the checkpoint's own regions, the stub's
/// reserved window (its live text and stack), and the kernel's special
/// mappings. A relocated `[vdso]`/`[vvar]` already sits at a recorded address;
/// one left in place (a checkpoint that recorded no vDSO) is excluded by name,
/// and `[vsyscall]` cannot be unmapped at all.
///
/// The comparison is by *address coverage*, subtracting the keep set from each
/// current mapping and sweeping only what is left over, because a live mapping
/// need not line up with a recorded one on either edge. The kernel merges
/// adjacent VMAs that agree on protections and backing, and the stub maps every
/// data-carrying region read/write until GO, so two recorded regions that
/// differ only in protection arrive as a single VMA spanning both. Asking
/// whether a mapping falls inside one recorded range would call that merged VMA
/// a stray and unmap the restored program's own memory.
pub(crate) fn plan_sweep(current: &[MemoryMap], cp: &[MemoryMap]) -> Vec<(u64, u64)> {
    let base: Vec<(u64, u64)> = if STUB_BASE > 0 {
        vec![(STUB_BASE, STUB_BASE + STUB_SPAN)]
    } else {
        Vec::new()
    };
    let mut keep: Vec<(u64, u64)> = cp
        .iter()
        .map(|m| (m.start, m.end))
        .chain(base)
        .filter(|(lo, hi)| lo < hi)
        .collect();
    keep.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(keep.len());
    for (lo, hi) in keep {
        match merged.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }

    let mut sweep = Vec::new();
    for m in current.iter().filter(|m| !m.is_special()) {
        let mut cursor = m.start;
        for &(lo, hi) in &merged {
            if hi <= cursor {
                continue;
            }
            if lo >= m.end {
                break;
            }
            if lo > cursor {
                sweep.push((cursor, lo - cursor));
            }
            cursor = cursor.max(hi);
            if cursor >= m.end {
                break;
            }
        }
        if cursor < m.end {
            sweep.push((cursor, m.end - cursor));
        }
    }
    sweep
}

/// Check that the kernel's special mappings ended up where the checkpoint
/// recorded them, given the layout the stub built.
///
/// The stub relocates `[vdso]`/`[vvar]` from a base it derives from auxv, and
/// reports success on the `mremap` return value alone. If that landed anywhere
/// other than the recorded base, the restored program's cached vDSO pointers are
/// stale and it dies with a bare SIGSEGV on its first `clock_gettime`, with
/// nothing left to say why. The supervisor is already reading `/proc` here for
/// the sweep, so confirm it and fail the restore with something readable instead.
///
/// Only mappings the checkpoint actually recorded are checked; a checkpoint with
/// no vDSO planned no moves and has nothing to confirm.
pub(crate) fn verify_special_mappings(
    current: &[MemoryMap],
    cp: &[MemoryMap],
) -> Result<(), String> {
    for name in ["[vvar]", "[vvar_vclock]", "[vdso]"] {
        let Some(want) = cp.iter().find(|m| m.path.as_deref() == Some(name)) else {
            continue;
        };
        match current.iter().find(|m| m.path.as_deref() == Some(name)) {
            Some(got) if got.start == want.start => {}
            Some(got) => {
                return Err(format!(
                    "{name} is at {:#x} but the checkpoint recorded {:#x}; the restored \
                     program's cached vDSO pointers would be stale",
                    got.start, want.start,
                ))
            }
            None => {
                return Err(format!(
                    "{name} is missing from the restored layout; the checkpoint recorded \
                     it at {:#x}",
                    want.start,
                ))
            }
        }
    }
    Ok(())
}

/// One planned memory-restore action for a saved region.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RestoreRegion {
    /// mmap MAP_FIXED from `path` at `offset`, prot from `perms`.
    MapFile { start: u64, end: u64, perms: String, offset: u64, path: String },
    /// mmap MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, then fill with `data`.
    Anon { start: u64, end: u64, perms: String, data: Vec<u8> },
}

impl RestoreRegion {
    fn start(&self) -> u64 {
        match self {
            RestoreRegion::MapFile { start, .. } | RestoreRegion::Anon { start, .. } => *start,
        }
    }
    fn end(&self) -> u64 {
        match self {
            RestoreRegion::MapFile { end, .. } | RestoreRegion::Anon { end, .. } => *end,
        }
    }
}

/// Classify saved regions into restore actions. Special kernel maps
/// ([vdso]/[vvar]/[vsyscall]) are skipped: the kernel provides them in the
/// fresh process and they are relocated, not rebuilt. A region with captured
/// bytes becomes `Anon`; otherwise a path-backed region becomes `MapFile`.
/// Regions that are neither are left to the kernel/ABI.
pub(crate) fn build_memory_plan(
    maps: &[MemoryMap],
    data: &[MemorySegment],
) -> Vec<RestoreRegion> {
    let mut plan = Vec::new();
    for m in maps {
        if m.is_special() { continue; }
        if let Some(seg) = data.iter().find(|s| s.start == m.start) {
            plan.push(RestoreRegion::Anon {
                start: m.start, end: m.end, perms: m.perms.clone(), data: seg.data.clone(),
            });
        } else if let Some(ref p) = m.path {
            if p.starts_with('/') {
                plan.push(RestoreRegion::MapFile {
                    start: m.start, end: m.end, perms: m.perms.clone(),
                    offset: m.offset, path: p.clone(),
                });
            }
        }
    }
    plan
}

/// Return true only for paths that refer to a reopenable regular file.
/// memfd and "(deleted)" paths start with '/' but are not reopenable, so they
/// are skipped. Pseudo-filesystem paths (/proc/, /sys/, /dev/) are also skipped:
/// they are ephemeral, may not exist at restore time, and cannot be
/// transparently reopened in the new process.
fn is_restorable_file_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("/memfd:")
        && !path.ends_with(" (deleted)")
        && !path.starts_with("/proc/")
        && !path.starts_with("/sys/")
        && !path.starts_with("/dev/")
}

/// Split the saved fd table into transparently restorable regular files and a
/// list of skipped non-regular fds (sockets, pipes, eventfd, ...). The skipped
/// list is surfaced to the caller; those resources fall to the app_state hatch.
/// memfd, "(deleted)", and pseudo-filesystem (/proc/, /sys/, /dev/) paths start
/// with '/' but are not transparently reopenable, so they are skipped.
pub(crate) fn build_fd_plan(fds: &[FdInfo]) -> (Vec<FdInfo>, Vec<SkippedFd>) {
    let mut restorable = Vec::new();
    let mut skipped = Vec::new();
    for f in fds {
        if is_restorable_file_path(&f.path) {
            restorable.push(f.clone());
        } else {
            skipped.push(SkippedFd { fd: f.fd, path: f.path.clone() });
        }
    }
    (restorable, skipped)
}

/// One planned relocation of a kernel special mapping. The stub learns its own
/// `[vdso]` base from `AT_SYSINFO_EHDR` in auxv and derives each mapping's
/// current base as `vdso_base + delta`; `[vvar]` has no auxv entry of its own,
/// but the kernel maps the whole block rigidly, so the checkpoint-recorded
/// distance to the vDSO holds in the fresh process too (same-kernel restore).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VdsoMove {
    /// Signed distance from the vDSO base to this mapping's base.
    pub delta: i64,
    pub len: u64,
    /// The base the checkpoint recorded, where this mapping must end up.
    pub target: u64,
}

/// Plan the relocations that put the stub's `[vvar]`/`[vdso]` at the addresses
/// the checkpoint recorded, in ascending target order.
///
/// Rationale for same-kernel restore: the vDSO/vvar *code and data* the kernel
/// mapped into the stub are identical to the checkpoint's; only the ASLR base
/// differs. Moving each mapping to its recorded base makes every pointer
/// glibc/musl cached into the vDSO resolve correctly on resume. Because the
/// whole block shifts by one constant amount, the stub avoids destroying a
/// source before relocating it by walking the (ascending) list backwards when
/// shifting up and forwards when shifting down; no ordering search is needed.
///
/// Returns an empty plan for a checkpoint with no recorded vDSO (a freestanding
/// image), which needs no relocation.
pub(crate) fn plan_vdso_moves(cp: &[MemoryMap]) -> Vec<VdsoMove> {
    let named = |name: &str| -> Option<(u64, u64)> {
        cp.iter()
            .find(|m| m.path.as_deref() == Some(name))
            .map(|m| (m.start, m.end))
    };
    let Some((vdso_base, _)) = named("[vdso]") else { return Vec::new() };

    let mut moves: Vec<VdsoMove> = ["[vvar]", "[vvar_vclock]", "[vdso]"]
        .into_iter()
        .filter_map(named)
        .map(|(start, end)| VdsoMove {
            delta: start as i64 - vdso_base as i64,
            len: end - start,
            target: start,
        })
        .collect();
    moves.sort_by_key(|m| m.target);
    moves
}

fn prot_bits(perms: &str) -> u32 {
    let b = perms.as_bytes();
    let mut p = 0u32;
    if b.first() == Some(&b'r') { p |= libc::PROT_READ as u32; }
    if b.get(1) == Some(&b'w') { p |= libc::PROT_WRITE as u32; }
    if b.get(2) == Some(&b'x') { p |= libc::PROT_EXEC as u32; }
    p
}

/// Translate a HOST path recorded by capture into the path the confined child
/// sees.
///
/// A confined process records its mapping/fd paths as host paths: capture reads
/// `/proc/<pid>/maps` and `/proc/<pid>/fd`, whose entries resolve in the mount
/// namespace and so ignore the process's chroot (a file the workload sees at
/// `/lib/ld-musl...` appears as `<rootfs>/lib/ld-musl...`). The stub's `openat`
/// calls run in the already-confined child, where those host paths do not
/// resolve. Without a chroot the recorded paths are already the child's view.
fn to_child_path(
    host_path: &str,
    chroot_root: Option<&Path>,
    mounts: &[(PathBuf, PathBuf)],
) -> String {
    match chroot_root {
        Some(root) => crate::chroot::resolve::host_to_virtual(root, mounts, Path::new(host_path))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| host_path.to_string()),
        None => host_path.to_string(),
    }
}

/// The kernel's restart sentinels for an aborted restartable syscall:
/// -ERESTARTSYS / -ERESTARTNOINTR / -ERESTARTNOHAND / -ERESTART_RESTARTBLOCK.
/// -515 (ENOIOCTLCMD) is NOT a restart code and must not be matched.
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "riscv64")),
    allow(dead_code)
)]
fn is_restart_sentinel(v: i64) -> bool {
    matches!(v, -512 | -513 | -514 | -516)
}

/// Return the restart sentinel a riscv64 register file holds in `a0`, if any.
///
/// On riscv64 `a0` is both the first syscall argument and the return value, so
/// an aborted restartable syscall overwrites the original argument with the
/// sentinel. The original (`orig_a0`) is not part of the ptrace-exposed
/// `user_regs_struct`, so neither capture nor restore can recover it. Callers
/// reject the checkpoint rather than resume with a corrupt return value.
#[cfg(target_arch = "riscv64")]
fn restart_sentinel_in_a0(regs: &[u64]) -> Option<i64> {
    // riscv64 user_regs_struct order: pc, ra, sp, gp, tp, t0-t2, s0-s1,
    // a0-a7, s2-s11, t3-t6 — so a0 is index 10.
    const A0: usize = 10;
    let a0 = *regs.get(A0)? as i64;
    if is_restart_sentinel(a0) { Some(a0) } else { None }
}

/// Refuse a riscv64 register file whose `a0` holds a restart sentinel, with
/// the shared error text; both capture and restore reject through here.
#[cfg(target_arch = "riscv64")]
pub(crate) fn reject_restart_sentinel(regs: &[u64]) -> Result<(), String> {
    match restart_sentinel_in_a0(regs) {
        Some(sentinel) => Err(format!(
            "checkpoint captured an interrupted restartable syscall \
             (a0 = {sentinel}); riscv64 cannot recover its original argument, \
             so restore would resume with a corrupt return value; retry the \
             checkpoint while the workload is not blocked in a syscall"
        )),
        None => Ok(()),
    }
}

/// Re-arm an interrupted, restartable syscall in the saved register file.
///
/// When the checkpoint was taken (via `PTRACE_INTERRUPT`) while the process sat
/// in a syscall, the kernel aborted it with a restart sentinel in the return
/// register. At the ptrace stop the PC still points just PAST the syscall
/// instruction. The kernel's restart fixup (rewind PC, reload the return
/// register with the original syscall number) normally runs on the
/// syscall-return path, which a restore bypasses. Without it, userspace resumes
/// one instruction past the syscall with the raw sentinel (e.g. -514) in the
/// return register and faults. Applying the fixup here re-executes the syscall
/// cleanly with its arguments still in registers (this is what CRIU does).
///
/// For ERESTART_RESTARTBLOCK (-516) the original syscall is re-run rather than
/// the kernel's `restart_syscall` path (restart_block is not captured), so
/// timeout-bearing syscalls restart with their full original timeout: an
/// accepted approximation for fresh-process restore.
#[cfg(target_arch = "x86_64")]
fn rearm_restartable_syscall(regs: &mut [u64]) -> Result<(), String> {
    // x86_64 user_regs_struct layout indices.
    const RAX: usize = 10;
    const ORIG_RAX: usize = 15;
    const RIP: usize = 16;
    if let (Some(&rax), Some(&orig_rax)) = (regs.get(RAX), regs.get(ORIG_RAX)) {
        if is_restart_sentinel(rax as i64) {
            regs[RAX] = orig_rax;
            regs[RIP] = regs[RIP].wrapping_sub(2);
        }
    }
    Ok(())
}

/// riscv64 re-arm is deliberately not implemented (see `restart_sentinel_in_a0`):
/// a correct restart needs the original `a0` argument, which ptrace does not
/// expose. On kernels ≥ 6.6 the kernel has already applied the restart fixup
/// before the ptrace stop, so `a0` is the original argument and this check is a
/// no-op. On older kernels the sentinel is visible here, and rejecting is the
/// only safe answer — resuming would hand userspace a raw `-ERESTART*` as the
/// syscall result.
#[cfg(target_arch = "riscv64")]
fn rearm_restartable_syscall(regs: &mut [u64]) -> Result<(), String> {
    reject_restart_sentinel(regs)
}

/// Build the FP image the stub points the signal frame's `fpstate` at.
///
/// The kernel decides between `xrstor` and legacy `fxrstor` by reading a
/// `struct _fpx_sw_bytes` at offset 464 of the fxsave block: with
/// `FP_XSTATE_MAGIC1` there, a matching `xstate_size`, and `FP_XSTATE_MAGIC2`
/// immediately after the image, it restores the full extended state. Capture
/// takes `NT_X86_XSTATE` (already in xsave layout) when it can, so framing it
/// this way preserves AVX/AVX-512 state across a restore; a short capture (the
/// 512-byte `NT_PRFPREG` fallback) is passed through unframed and the kernel
/// restores x87/SSE only.
///
/// Returns an empty image when there is nothing to restore, which the stub
/// signals to the kernel as `fpstate = 0`.
#[cfg(target_arch = "x86_64")]
fn build_fpstate_image(fpregs: &[u8]) -> Vec<u8> {
    if fpregs.len() < 512 {
        return Vec::new();
    }
    // Legacy fxsave only: hand it over with a cleared sw_reserved so the kernel
    // takes the fxrstor path rather than reading stale magic. Also the fallback
    // whenever the capture does not look like a complete xstate the signal frame
    // can consume: losing the extended components costs fidelity, whereas
    // pointing `xrstor` at a buffer that is not what it claims to be corrupts
    // the resumed program's FP state or faults outright.
    let fx_only = || {
        let mut img = fpregs[..512].to_vec();
        img[SW_RESERVED_OFF..512].fill(0);
        img
    };
    if fpregs.len() < MIN_XSTATE_SIZE {
        return fx_only();
    }

    // The xsave header follows the 512-byte fxsave block: xstate_bv at 512,
    // xcomp_bv at 520, then 48 reserved bytes. Bit 63 of xcomp_bv marks the
    // *compacted* format, which the signal frame does not accept, and the
    // reserved bytes must be zero. Either being otherwise means this is not the
    // uncompacted image ptrace is supposed to hand back, so do not tell the
    // kernel it is one.
    let xcomp_bv = u64::from_le_bytes(fpregs[520..528].try_into().unwrap());
    if xcomp_bv & (1 << 63) != 0 || fpregs[528..576].iter().any(|&b| b != 0) {
        return fx_only();
    }

    let xstate_size = fpregs.len();
    let mut img = Vec::with_capacity(xstate_size + 4);
    img.extend_from_slice(fpregs);

    // xstate_bv, the first u64 of the xsave header, is the feature mask the
    // kernel restores with.
    let xfeatures = u64::from_le_bytes(img[512..520].try_into().unwrap());

    // struct _fpx_sw_bytes { u32 magic1; u32 extended_size; u64 xfeatures;
    //                        u32 xstate_size; u32 padding[7]; }
    let mut sw = Vec::with_capacity(48);
    sw.extend_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
    sw.extend_from_slice(&((xstate_size + 4) as u32).to_le_bytes());
    sw.extend_from_slice(&xfeatures.to_le_bytes());
    sw.extend_from_slice(&(xstate_size as u32).to_le_bytes());
    sw.resize(48, 0);
    img[SW_RESERVED_OFF..SW_RESERVED_OFF + 48].copy_from_slice(&sw);

    img.extend_from_slice(&FP_XSTATE_MAGIC2.to_le_bytes());
    img
}

/// Build the FP image for the riscv64 signal frame. Unlike x86_64, riscv64 has
/// no xstate/magic framing — the kernel stores the FPU context inline in
/// `uc.uc_mcontext.__fpregs` as a raw `struct __riscv_d_ext_state` (or
/// `__riscv_f_ext_state` for single-precision). The stub copies it verbatim into
/// the ucontext's fp slot; the kernel reads it back from the signal frame on
/// rt_sigreturn.
#[cfg(target_arch = "riscv64")]
fn build_fpstate_image(fpregs: &[u8]) -> Vec<u8> {
    if fpregs.is_empty() {
        return Vec::new();
    }
    fpregs.to_vec()
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
fn build_fpstate_image(_fpregs: &[u8]) -> Vec<u8> {
    Vec::new()
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
fn rearm_restartable_syscall(_regs: &mut [u64]) -> Result<(), String> {
    Ok(())
}

/// Interns NUL-terminated strings into the blob's string table, deduplicating
/// repeats (a multi-segment ELF mapping names the same file once per segment).
#[derive(Default)]
struct StringTable {
    bytes: Vec<u8>,
    seen: std::collections::HashMap<String, u32>,
}

impl StringTable {
    fn intern(&mut self, s: &str) -> Result<u32, String> {
        if let Some(&off) = self.seen.get(s) {
            return Ok(off);
        }
        if s.as_bytes().contains(&0) {
            return Err(format!("restore path contains a NUL byte: {s:?}"));
        }
        let off = u32::try_from(self.bytes.len())
            .map_err(|_| "restore string table exceeds 4 GiB".to_string())?;
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
        self.seen.insert(s.to_string(), off);
        Ok(off)
    }
}

/// Turn a checkpoint into everything the restore needs: the stub's control blob,
/// the anonymous page contents for the supervisor to write in, and the fds that
/// could not be transparently recreated.
pub(crate) fn plan(
    cp: &Checkpoint,
    chroot_root: Option<&Path>,
    mounts: &[(PathBuf, PathBuf)],
) -> Result<RestorePlan, String> {
    let ps = &cp.process_state;
    let regions = build_memory_plan(&ps.memory_maps, &ps.memory_data);

    // The stub's own text/data/bss/stack live at a fixed far base. A checkpoint
    if STUB_BASE > 0 {
        if let Some(r) = regions
            .iter()
            .find(|r| r.start() < STUB_BASE + STUB_SPAN && STUB_BASE < r.end())
        {
            return Err(format!(
                "checkpoint region {:#x}-{:#x} overlaps the restore-stub's reserved \
                 window {:#x}-{:#x}",
                r.start(), r.end(), STUB_BASE, STUB_BASE + STUB_SPAN,
            ));
        }
    }

    let (restorable_fds, skipped) = build_fd_plan(&cp.fd_table);
    let vdso = plan_vdso_moves(&ps.memory_maps);

    let mut regs = ps.regs.clone();
    rearm_restartable_syscall(&mut regs)?;
    let fpstate = build_fpstate_image(&ps.fpregs);

    let mut strings = StringTable::default();
    let mut anon = Vec::new();

    // Region table entries, built before the header so string offsets are known.
    let mut region_tbl = Vec::with_capacity(regions.len() * REGION_ENTRY_LEN);
    for r in &regions {
        let (start, end, perms, src, file_off, path_off) = match r {
            RestoreRegion::Anon { start, end, perms, data } => {
                anon.push((*start, data.clone()));
                (*start, *end, perms, SRC_ANON, 0u64, 0u32)
            }
            RestoreRegion::MapFile { start, end, perms, offset, path } => {
                let off = strings.intern(&to_child_path(path, chroot_root, mounts))?;
                (*start, *end, perms, SRC_FILE, *offset, off)
            }
        };
        region_tbl.extend_from_slice(&start.to_le_bytes());
        region_tbl.extend_from_slice(&end.to_le_bytes());
        region_tbl.extend_from_slice(&prot_bits(perms).to_le_bytes());
        region_tbl.push(src);
        region_tbl.extend_from_slice(&[0u8; 3]);
        region_tbl.extend_from_slice(&file_off.to_le_bytes());
        region_tbl.extend_from_slice(&path_off.to_le_bytes());
        region_tbl.extend_from_slice(&0u32.to_le_bytes());
    }

    let mut fd_tbl = Vec::with_capacity(restorable_fds.len() * FD_ENTRY_LEN);
    for f in &restorable_fds {
        let path_off = strings.intern(&to_child_path(&f.path, chroot_root, mounts))?;
        // Mask creation/truncation flags so the reopen cannot create, truncate,
        // or fail-exclusive on the workload's real file. The kernel strips these
        // in fdinfo, but mask defensively since O_TRUNC would be destructive.
        let flags = f.flags & !(libc::O_CREAT | libc::O_TRUNC | libc::O_EXCL);
        fd_tbl.extend_from_slice(&(f.fd as u32).to_le_bytes());
        fd_tbl.extend_from_slice(&(flags as u32).to_le_bytes());
        fd_tbl.extend_from_slice(&f.offset.to_le_bytes());
        fd_tbl.extend_from_slice(&path_off.to_le_bytes());
        fd_tbl.extend_from_slice(&0u32.to_le_bytes());
    }

    let mut vdso_tbl = Vec::with_capacity(vdso.len() * VDSO_ENTRY_LEN);
    for m in &vdso {
        vdso_tbl.extend_from_slice(&m.delta.to_le_bytes());
        vdso_tbl.extend_from_slice(&m.len.to_le_bytes());
        vdso_tbl.extend_from_slice(&m.target.to_le_bytes());
    }

    // Layout: header | regions | fds | vdso moves | regs | fpstate | strings
    let regs_off = HEADER_LEN + region_tbl.len() + fd_tbl.len() + vdso_tbl.len();
    let fpstate_off = regs_off + regs.len() * 8;
    let strings_off = fpstate_off + fpstate.len();

    let mut out = Vec::with_capacity(strings_off + strings.bytes.len());
    out.extend_from_slice(&BLOB_MAGIC.to_le_bytes());
    out.extend_from_slice(&BLOB_VERSION.to_le_bytes());
    out.extend_from_slice(&(regions.len() as u32).to_le_bytes());
    out.extend_from_slice(&(restorable_fds.len() as u32).to_le_bytes());
    out.extend_from_slice(&(regs_off as u64).to_le_bytes());
    out.extend_from_slice(&((regs.len() * 8) as u32).to_le_bytes());
    out.extend_from_slice(&(fpstate.len() as u32).to_le_bytes());
    out.extend_from_slice(&(fpstate_off as u64).to_le_bytes());
    out.extend_from_slice(&(strings_off as u64).to_le_bytes());
    out.extend_from_slice(&(strings.bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(vdso.len() as u32).to_le_bytes());
    out.extend_from_slice(&((HEADER_LEN + region_tbl.len() + fd_tbl.len()) as u64).to_le_bytes());
    debug_assert_eq!(out.len(), HEADER_LEN);

    out.extend_from_slice(&region_tbl);
    out.extend_from_slice(&fd_tbl);
    out.extend_from_slice(&vdso_tbl);
    debug_assert_eq!(out.len(), regs_off);
    for r in &regs {
        out.extend_from_slice(&r.to_le_bytes());
    }
    out.extend_from_slice(&fpstate);
    out.extend_from_slice(&strings.bytes);

    Ok(RestorePlan { blob: out, anon, maps: ps.memory_maps.clone(), skipped })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{FdInfo, MemoryMap, MemorySegment, ProcessState};
    use crate::sandbox::Sandbox;

    fn map(start: u64, end: u64, path: Option<&str>) -> MemoryMap {
        MemoryMap { start, end, perms: "rw-p".into(), offset: 0, path: path.map(Into::into) }
    }

    #[test]
    fn restart_sentinel_matches_only_restart_codes() {
        assert!(is_restart_sentinel(-512)); // ERESTARTSYS
        assert!(is_restart_sentinel(-513)); // ERESTARTNOINTR
        assert!(is_restart_sentinel(-514)); // ERESTARTNOHAND
        assert!(is_restart_sentinel(-516)); // ERESTART_RESTARTBLOCK
        assert!(!is_restart_sentinel(-515)); // ENOIOCTLCMD, not a restart code
        assert!(!is_restart_sentinel(0));
        assert!(!is_restart_sentinel(-1)); // EPERM
    }

    #[test]
    #[cfg(target_arch = "riscv64")]
    fn riscv64_rearm_rejects_an_in_flight_restartable_syscall() {
        // riscv64 user_regs_struct order: a0 is index 10.
        let mut regs = vec![0u64; 32];

        regs[10] = (-514i64) as u64; // ERESTARTNOHAND
        let err = rearm_restartable_syscall(&mut regs)
            .expect_err("a restart sentinel in a0 must be rejected");
        assert!(err.contains("restartable"), "names the cause: {err}");

        regs[10] = (-515i64) as u64; // ENOIOCTLCMD is not a restart code
        rearm_restartable_syscall(&mut regs).expect("ENOIOCTLCMD must not be rejected");

        regs[10] = 7; // ordinary return value
        rearm_restartable_syscall(&mut regs).expect("a normal return value passes");
    }

    #[test]
    fn fd_plan_keeps_regular_files_only() {
        let fds = vec![
            FdInfo { fd: 3, path: "/etc/hostname".into(), flags: 0, offset: 5 },
            FdInfo { fd: 4, path: "socket:[12345]".into(), flags: 0, offset: 0 },
            FdInfo { fd: 5, path: "pipe:[6789]".into(), flags: 0, offset: 0 },
        ];
        let (restorable, skipped) = build_fd_plan(&fds);
        assert_eq!(restorable.len(), 1);
        assert_eq!(restorable[0].fd, 3);
        assert_eq!(skipped, vec![
            SkippedFd { fd: 4, path: "socket:[12345]".into() },
            SkippedFd { fd: 5, path: "pipe:[6789]".into() },
        ]);
    }

    #[test]
    fn fd_plan_skips_deleted_and_memfd() {
        let fds = vec![
            FdInfo { fd: 3, path: "/etc/hostname".into(), flags: 0, offset: 5 },
            FdInfo { fd: 6, path: "/tmp/gone (deleted)".into(), flags: 0, offset: 0 },
            FdInfo { fd: 7, path: "/memfd:scratch (deleted)".into(), flags: 0, offset: 0 },
            FdInfo { fd: 8, path: "/proc/1234/maps".into(), flags: 0, offset: 0 },
            FdInfo { fd: 9, path: "/dev/pts/3".into(), flags: 0, offset: 0 },
            FdInfo { fd: 10, path: "/sys/kernel/x".into(), flags: 0, offset: 0 },
        ];
        let (restorable, skipped) = build_fd_plan(&fds);
        assert_eq!(restorable.len(), 1);
        assert_eq!(restorable[0].fd, 3);
        assert!(restorable.iter().all(|f| f.fd != 6 && f.fd != 7 && f.fd != 8 && f.fd != 9 && f.fd != 10),
            "deleted, memfd, and pseudo-filesystem fds must not appear in restorable");
        assert!(skipped.contains(&SkippedFd { fd: 6, path: "/tmp/gone (deleted)".into() }));
        assert!(skipped.contains(&SkippedFd { fd: 7, path: "/memfd:scratch (deleted)".into() }));
        assert!(skipped.contains(&SkippedFd { fd: 8, path: "/proc/1234/maps".into() }),
            "/proc/ paths must be skipped");
        assert!(skipped.contains(&SkippedFd { fd: 9, path: "/dev/pts/3".into() }),
            "/dev/ paths must be skipped");
        assert!(skipped.contains(&SkippedFd { fd: 10, path: "/sys/kernel/x".into() }),
            "/sys/ paths must be skipped");
    }

    #[test]
    fn plan_classifies_regions() {
        let maps = vec![
            MemoryMap { start: 0x1000, end: 0x2000, perms: "r-xp".into(), offset: 0,
                        path: Some("/bin/app".into()) },          // code: map from file
            MemoryMap { start: 0x3000, end: 0x4000, perms: "rw-p".into(), offset: 0,
                        path: None },                              // anon writable: fill bytes
            MemoryMap { start: 0x5000, end: 0x6000, perms: "r--p".into(), offset: 0,
                        path: Some("[vvar]".into()) },             // special: skip
        ];
        let data = vec![MemorySegment { start: 0x3000, data: vec![7u8; 0x1000] }];
        let plan = build_memory_plan(&maps, &data);
        assert!(matches!(plan[0], RestoreRegion::MapFile { .. }));
        assert!(matches!(plan[1], RestoreRegion::Anon { .. }));
        assert_eq!(plan.len(), 2, "special regions are skipped, not planned");
    }

    #[test]
    fn vdso_moves_are_deltas_from_the_vdso_base_in_ascending_target_order() {
        let cp = vec![
            map(0x2000, 0x3000, Some("[vdso]")),
            map(0x1000, 0x2000, Some("[vvar]")),
            map(0x9000, 0xa000, None),
        ];
        let moves = plan_vdso_moves(&cp);
        assert_eq!(moves, vec![
            VdsoMove { delta: -0x1000, len: 0x1000, target: 0x1000 }, // [vvar]
            VdsoMove { delta: 0, len: 0x1000, target: 0x2000 },       // [vdso]
        ], "both special mappings relocate, ordered by ascending target");
    }

    #[test]
    fn special_mappings_verify_against_the_recorded_bases() {
        let cp = vec![map(0x1000, 0x2000, Some("[vvar]")), map(0x2000, 0x3000, Some("[vdso]"))];
        assert!(verify_special_mappings(&cp.clone(), &cp).is_ok(), "an exact match passes");

        // Relocated to the wrong base: the resumed program would jump into a
        // vDSO that is no longer there.
        let moved = vec![map(0x1000, 0x2000, Some("[vvar]")), map(0x9000, 0xa000, Some("[vdso]"))];
        let err = verify_special_mappings(&moved, &cp).expect_err("a stale base is caught");
        assert!(err.contains("[vdso]") && err.contains("0x2000"), "names what moved: {err}");

        // Gone entirely (unmapped by a MAP_FIXED that landed on it).
        let gone = vec![map(0x1000, 0x2000, Some("[vvar]"))];
        assert!(verify_special_mappings(&gone, &cp).unwrap_err().contains("missing"));
    }

    #[test]
    fn special_mappings_verify_nothing_a_checkpoint_did_not_record() {
        // A freestanding checkpoint has no vDSO, so the fresh one is wherever
        // the kernel put it and that is fine.
        let cp = vec![map(0x1000, 0x2000, None)];
        let current = vec![map(0x8000, 0x9000, Some("[vdso]"))];
        assert!(verify_special_mappings(&current, &cp).is_ok());
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
    #[test]
    fn sweep_removes_a_leftover_stack_but_spares_the_image_and_the_stub() {
        // The layout the stub is in at READY: the checkpoint's regions, the
        // kernel's specials, its own image, and the initial stack ASLR gave it.
        let cp = vec![
            map(0x40_0000, 0x40_1000, Some("/bin/app")),
            map(0x7ffd_0000_0000, 0x7ffd_0002_0000, Some("[stack]")),
            map(0x7f00_0000_0000, 0x7f00_0000_2000, Some("[vdso]")),
        ];
        let current = vec![
            map(0x40_0000, 0x40_1000, Some("/bin/app")),
            map(0x7ffd_0000_0000, 0x7ffd_0002_0000, Some("[stack]")),
            map(0x7f00_0000_0000, 0x7f00_0000_2000, Some("[vdso]")),
            map(STUB_BASE, STUB_BASE + 0x117000, None),          // the running stub
            map(0x7ffc_a06a_0000, 0x7ffc_a06c_2000, Some("[stack]")), // leftover
        ];
        assert_eq!(
            plan_sweep(&current, &cp),
            vec![(0x7ffc_a06a_0000, 0x2_2000)],
            "only the stub's own startup stack is swept",
        );
    }

    #[test]
    fn sweep_spares_a_mapping_the_kernel_merged_into_a_recorded_range() {
        // A restored mapping can be a strict subrange of what the checkpoint
        // recorded. That is not a stray.
        let cp = vec![map(0x1000, 0x9000, None)];
        let current = vec![map(0x3000, 0x5000, None)];
        assert!(plan_sweep(&current, &cp).is_empty());
    }

    #[test]
    fn sweep_spares_one_vma_the_kernel_merged_from_two_recorded_regions() {
        // The stub maps every data-carrying region read/write until GO, so two
        // adjacent regions that differ only in protection arrive as one VMA
        // spanning both recorded ranges. Unmapping that would destroy the
        // restored program's own memory.
        let cp = vec![map(0x1000, 0x2000, None), map(0x2000, 0x3000, None)];
        let current = vec![map(0x1000, 0x3000, None)];
        assert!(plan_sweep(&current, &cp).is_empty());
    }

    #[test]
    fn sweep_takes_only_the_uncovered_part_of_a_partly_recorded_mapping() {
        // A live VMA that runs past a recorded region loses only the excess:
        // sweeping the whole thing would take the recorded part with it.
        let cp = vec![map(0x2000, 0x3000, None)];
        let current = vec![map(0x1000, 0x5000, None)];
        assert_eq!(
            plan_sweep(&current, &cp),
            vec![(0x1000, 0x1000), (0x3000, 0x2000)],
            "only the ranges outside the checkpoint are shed",
        );
    }

    #[test]
    fn vdso_moves_empty_without_a_recorded_vdso() {
        // A freestanding checkpoint records no vdso; nothing to relocate, and
        // the stub has no base to anchor a [vvar] delta against either.
        let cp = vec![map(0x1000, 0x2000, Some("[vvar]")), map(0x2000, 0x3000, None)];
        assert!(plan_vdso_moves(&cp).is_empty());
    }

    fn tiny_checkpoint(maps: Vec<MemoryMap>, data: Vec<MemorySegment>) -> Checkpoint {
        Checkpoint {
            name: String::new(),
            policy: Sandbox::builder().build().unwrap(),
            process_state: ProcessState {
                pid: 1234,
                cwd: "/".into(),
                exe: "/x".into(),
                regs: (0..27u64).collect(), // recognizable
                fpregs: Vec::new(),
                memory_maps: maps,
                memory_data: data,
            },
            fd_table: Vec::new(),
            cow_snapshot: None,
            app_state: None,
        }
    }

    #[test]
    fn blob_header_region_and_regs_roundtrip() {
        const START: u64 = 0x4500_0000_0000;
        let cp = tiny_checkpoint(
            vec![MemoryMap {
                start: START, end: START + 0x1000, perms: "rwxp".into(), offset: 0, path: None,
            }],
            vec![MemorySegment { start: START, data: vec![0xC7u8; 0x1000] }],
        );
        let p = plan(&cp, None, &[]).expect("plan");
        let blob = &p.blob;

        assert_eq!(u32::from_le_bytes(blob[0..4].try_into().unwrap()), BLOB_MAGIC);
        assert_eq!(u32::from_le_bytes(blob[4..8].try_into().unwrap()), BLOB_VERSION);
        assert_eq!(u32::from_le_bytes(blob[8..12].try_into().unwrap()), 1, "n_regions");
        assert_eq!(u32::from_le_bytes(blob[12..16].try_into().unwrap()), 0, "n_fds");

        // Region-table entry, byte-exact.
        let r0 = HEADER_LEN;
        assert_eq!(u64::from_le_bytes(blob[r0..r0 + 8].try_into().unwrap()), START, "start");
        assert_eq!(u64::from_le_bytes(blob[r0 + 8..r0 + 16].try_into().unwrap()), START + 0x1000, "end");
        assert_eq!(u32::from_le_bytes(blob[r0 + 16..r0 + 20].try_into().unwrap()),
                   (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u32, "prot");
        assert_eq!(blob[r0 + 20], SRC_ANON, "src");

        let regs_off = u64::from_le_bytes(blob[16..24].try_into().unwrap()) as usize;
        assert_eq!(u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize, 27 * 8, "regs_len");
        for i in 0..27usize {
            let v = u64::from_le_bytes(blob[regs_off + i * 8..regs_off + i * 8 + 8].try_into().unwrap());
            assert_eq!(v, i as u64);
        }

        // Page contents travel outside the blob, for the supervisor to write in.
        assert_eq!(p.anon.len(), 1);
        assert_eq!(p.anon[0].0, START);
        assert!(p.anon[0].1.iter().all(|&b| b == 0xC7));
    }

    #[test]
    fn blob_interns_a_repeated_mapping_path_once() {
        // A multi-segment ELF names the same file per segment; the string table
        // must carry it once and both regions must point at that one offset.
        let cp = tiny_checkpoint(
            vec![
                MemoryMap { start: 0x1000, end: 0x2000, perms: "r-xp".into(), offset: 0,
                            path: Some("/bin/app".into()) },
                MemoryMap { start: 0x2000, end: 0x3000, perms: "r--p".into(), offset: 0x1000,
                            path: Some("/bin/app".into()) },
            ],
            Vec::new(),
        );
        let blob = plan(&cp, None, &[]).expect("plan").blob;
        let off0 = u32::from_le_bytes(blob[HEADER_LEN + 32..HEADER_LEN + 36].try_into().unwrap());
        let off1 = u32::from_le_bytes(
            blob[HEADER_LEN + REGION_ENTRY_LEN + 32..HEADER_LEN + REGION_ENTRY_LEN + 36]
                .try_into().unwrap());
        assert_eq!(off0, off1, "the repeated path is interned once");

        let strings_off = u64::from_le_bytes(blob[40..48].try_into().unwrap()) as usize;
        let strings_len = u32::from_le_bytes(blob[48..52].try_into().unwrap()) as usize;
        assert_eq!(&blob[strings_off..strings_off + strings_len], b"/bin/app\0");
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
    #[test]
    fn plan_rejects_a_checkpoint_overlapping_the_stub_window() {
        let cp = tiny_checkpoint(
            vec![MemoryMap {
                start: STUB_BASE, end: STUB_BASE + 0x1000, perms: "rw-p".into(),
                offset: 0, path: None,
            }],
            vec![MemorySegment { start: STUB_BASE, data: vec![0u8; 0x1000] }],
        );
        let err = plan(&cp, None, &[]).expect_err("must refuse to clobber the running stub");
        assert!(err.contains("restore-stub"), "error should name the stub window: {err}");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn restart_sentinel_rewinds_rip_onto_the_syscall() {
        // rax = -ERESTARTNOHAND with orig_rax = pause(34): the restored context
        // must re-enter the syscall rather than resume past it with the sentinel.
        let mut regs = vec![0u64; 27];
        regs[10] = (-514i64) as u64; // rax
        regs[15] = 34;               // orig_rax
        regs[16] = 0x4010_0000;      // rip, just past the `syscall`
        rearm_restartable_syscall(&mut regs).unwrap();
        assert_eq!(regs[10], 34, "rax reloaded with the original syscall number");
        assert_eq!(regs[16], 0x4010_0000 - 2, "rip rewound onto the 2-byte syscall");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn non_restart_errno_is_left_alone() {
        // -515 (ENOIOCTLCMD) looks like a sentinel but is not one.
        let mut regs = vec![0u64; 27];
        regs[10] = (-515i64) as u64;
        regs[15] = 34;
        regs[16] = 0x4010_0000;
        rearm_restartable_syscall(&mut regs).unwrap();
        assert_eq!(regs[10], (-515i64) as u64);
        assert_eq!(regs[16], 0x4010_0000);
    }

    // riscv64 has no re-arm to test: it rejects a restart sentinel instead (see
    // `riscv64_rearm_rejects_an_in_flight_restartable_syscall` above), so only
    // x86_64 exercises the rewind here.

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn fpstate_image_frames_a_full_xstate_for_xrstor() {
        // An xsave-sized capture must come back framed so the kernel takes the
        // xrstor path: magic1 in sw_reserved, xstate_bv copied into xfeatures,
        // and magic2 immediately after the image.
        let mut fp = vec![0u8; 1088];
        fp[512..520].copy_from_slice(&0b111u64.to_le_bytes()); // xstate_bv: x87|SSE|AVX
        let img = build_fpstate_image(&fp);
        assert_eq!(img.len(), 1088 + 4);
        assert_eq!(u32::from_le_bytes(img[464..468].try_into().unwrap()), FP_XSTATE_MAGIC1);
        assert_eq!(u32::from_le_bytes(img[468..472].try_into().unwrap()), 1088 + 4, "extended_size");
        assert_eq!(u64::from_le_bytes(img[472..480].try_into().unwrap()), 0b111, "xfeatures");
        assert_eq!(u32::from_le_bytes(img[480..484].try_into().unwrap()), 1088, "xstate_size");
        assert_eq!(u32::from_le_bytes(img[1088..1092].try_into().unwrap()), FP_XSTATE_MAGIC2);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn fpstate_image_refuses_to_frame_a_compacted_xstate() {
        // Bit 63 of xcomp_bv marks the compacted format, which the signal frame
        // cannot consume. Framing it anyway would point xrstor at a buffer whose
        // component layout is not the one it assumes.
        let mut fp = vec![0u8; 1088];
        fp[512..520].copy_from_slice(&0b111u64.to_le_bytes());
        fp[520..528].copy_from_slice(&(1u64 << 63).to_le_bytes());
        let img = build_fpstate_image(&fp);
        assert_eq!(img.len(), 512, "falls back to the legacy fxsave image");
        assert!(img[464..512].iter().all(|&b| b == 0), "no xstate magic claimed");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn fpstate_image_refuses_a_capture_with_a_dirty_xsave_header() {
        // Non-zero reserved bytes mean this is not the uncompacted image ptrace
        // hands back (a truncated or mangled capture, say), so do not claim it.
        let mut fp = vec![0u8; 1088];
        fp[512..520].copy_from_slice(&0b111u64.to_le_bytes());
        fp[540] = 0xAB;
        assert_eq!(build_fpstate_image(&fp).len(), 512);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn fpstate_image_clears_sw_reserved_on_a_legacy_capture() {
        // A 512-byte NT_PRFPREG capture has no xstate header; leaving stale bytes
        // at 464 could make the kernel read past the buffer as an xstate.
        let img = build_fpstate_image(&vec![0xFFu8; 512]);
        assert_eq!(img.len(), 512);
        assert!(img[464..512].iter().all(|&b| b == 0), "sw_reserved cleared");
    }

    #[test]
    #[cfg(target_arch = "riscv64")]
    fn fpstate_image_passes_through_raw_fpregs() {
        // riscv64 has no xstate framing: the kernel stores
        // __riscv_d_ext_state directly in sc_fpregs. build_fpstate_image
        // returns the capture verbatim so the stub copies it as-is into the
        // ucontext's fp slot.
        let fp = vec![0xA5u8; 264];
        let img = build_fpstate_image(&fp);
        assert_eq!(img, fp, "riscv64 fpstate is a raw passthrough");
        assert_eq!(img.len(), 264);
    }

    #[test]
    fn fpstate_image_empty_when_nothing_was_captured() {
        assert!(build_fpstate_image(&[]).is_empty());
    }
}
