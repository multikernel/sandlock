use crate::checkpoint::{Checkpoint, FdInfo, MemoryMap, MemorySegment, SkippedFd};

/// One planned memory-restore action for a saved region.
#[derive(Debug)]
pub(crate) enum RestoreRegion {
    /// mmap MAP_FIXED from `path` at `offset`, prot from `perms`.
    RemapFromFile { start: u64, end: u64, perms: String, offset: u64, path: String },
    /// mmap MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, then write `data`.
    WriteBytes { start: u64, end: u64, perms: String, data: Vec<u8> },
}

/// Classify saved regions into restore actions. Special kernel maps
/// ([vdso]/[vvar]/[vsyscall]) are skipped: the kernel provides them in the
/// fresh process and they must not be overwritten. A region with captured
/// bytes becomes WriteBytes; otherwise a path-backed region becomes
/// RemapFromFile. Regions that are neither are left to the kernel/ABI.
pub(crate) fn build_memory_plan(
    maps: &[MemoryMap],
    data: &[MemorySegment],
) -> Vec<RestoreRegion> {
    let mut plan = Vec::new();
    for m in maps {
        if m.is_special() { continue; }
        if let Some(seg) = data.iter().find(|s| s.start == m.start) {
            plan.push(RestoreRegion::WriteBytes {
                start: m.start, end: m.end, perms: m.perms.clone(), data: seg.data.clone(),
            });
        } else if let Some(ref p) = m.path {
            if p.starts_with('/') {
                plan.push(RestoreRegion::RemapFromFile {
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

/// The (start, end) of the mapping named exactly `name` (e.g. `"[vdso]"`) in
/// `maps`, or `None` if absent.
fn find_named_map(maps: &[MemoryMap], name: &str) -> Option<(u64, u64)> {
    maps.iter()
        .find(|m| m.path.as_deref() == Some(name))
        .map(|m| (m.start, m.end))
}

/// One planned relocation of a kernel special mapping ([vdso]/[vvar]): move the
/// mapping currently at `cur_start` (length `len`) to `target_start`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct VdsoMove {
    pub cur_start: u64,
    pub len: u64,
    pub target_start: u64,
}

/// Plan the relocations that put the stub's `[vvar]`/`[vdso]` at the addresses
/// the checkpoint recorded. A mapping is moved only when present in both layouts
/// and its current base differs from the target. The returned moves are ordered
/// so that no move's *target* range overlaps a not-yet-executed move's *current*
/// range, which would destroy a source before it is relocated. A layout that
/// would require swapping two overlapping ranges (a dependency cycle) is
/// reported as an error rather than corrupting the mappings.
///
/// Rationale for same-kernel restore: the vDSO/vvar *code and data* the kernel
/// mapped into the stub are identical to the checkpoint's (same kernel); only
/// the ASLR base differs. Moving each mapping to its recorded base makes every
/// pointer glibc cached into the vDSO resolve correctly on resume. The constant
/// vvar-to-vdso distance is preserved automatically because both are moved to
/// recorded addresses that already encode that distance.
pub(crate) fn plan_vdso_moves(
    cur: &[MemoryMap],
    cp: &[MemoryMap],
) -> Result<Vec<VdsoMove>, String> {
    let mut remaining: Vec<VdsoMove> = Vec::new();
    for name in ["[vvar]", "[vvar_vclock]", "[vdso]"] {
        if let (Some((cs, ce)), Some((ts, _))) =
            (find_named_map(cur, name), find_named_map(cp, name))
        {
            if cs != ts {
                remaining.push(VdsoMove { cur_start: cs, len: ce - cs, target_start: ts });
            }
        }
    }

    let mut ordered = Vec::new();
    while !remaining.is_empty() {
        // Pick a move whose target does not overlap any *other* remaining move's
        // current range: relocating it cannot clobber a source we still need.
        let pick = remaining.iter().position(|m| {
            let (t_start, t_end) = (m.target_start, m.target_start + m.len);
            !remaining
                .iter()
                .any(|o| o != m && t_start < (o.cur_start + o.len) && o.cur_start < t_end)
        });
        match pick {
            Some(i) => ordered.push(remaining.remove(i)),
            None => {
                return Err(
                    "vdso/vvar relocation requires swapping overlapping ranges".into(),
                )
            }
        }
    }
    Ok(ordered)
}

fn prot_from_perms(perms: &str) -> libc::c_int {
    let mut prot = 0;
    if perms.as_bytes().first() == Some(&b'r') { prot |= libc::PROT_READ; }
    if perms.as_bytes().get(1) == Some(&b'w') { prot |= libc::PROT_WRITE; }
    if perms.as_bytes().get(2) == Some(&b'x') { prot |= libc::PROT_EXEC; }
    if prot == 0 { prot = libc::PROT_NONE; }
    prot
}

/// Reconstruct the process image of `cp` into an already-ptrace-stopped child
/// `pid` (the calling process must be its tracer; the child must be stopped at
/// a valid executable rip). Drives the rebuild entirely via ptrace syscall
/// injection through a trampoline placed in a hole of the CHECKPOINT's layout.
/// Leaves the child stopped with the saved registers loaded; the caller resumes
/// it (PTRACE_CONT / detach). Returns the non-transparently-restored fds
/// (as [`SkippedFd`] fd + path entries) for the caller to surface.
/// On `Err`, the child is left half-built and still ptrace-stopped; the caller
/// MUST kill and reap it.
/// Limitation: file-backed regions are restored `MAP_PRIVATE` from the on-disk
/// file, so a checkpointed `MAP_SHARED` mapping is restored as private
/// (a documented limitation for now).
/// vDSO handling: the kernel-provided `[vdso]`/`[vvar]`/`[vvar_vclock]` mappings
/// are relocated onto the checkpoint-recorded bases (see `plan_vdso_moves`), so
/// libc/glibc programs whose cached vDSO pointers (e.g. `clock_gettime`) target
/// the checkpoint-era base resume correctly. This assumes a same-kernel restore
/// (the vDSO code is byte-identical; only the ASLR base differs).
/// Limitation: the stub's own leftover mappings (launcher text, pre-exec stack,
/// inherited anon) are not swept, so the restored address space is the union of
/// the checkpoint image and those leftovers; `/proc/self/maps` shows them and
/// they remain readable to the workload.
#[cfg(target_arch = "x86_64")]
pub(crate) fn restore_into(
    pid: i32,
    cp: &Checkpoint,
) -> Result<Vec<SkippedFd>, crate::error::SandlockError> {
    use crate::checkpoint::inject;
    use crate::error::{SandboxRuntimeError, SandlockError};

    // x86_64 syscall numbers used by the rebuild.
    const MMAP: u64 = 9;
    const MPROTECT: u64 = 10;
    const MUNMAP: u64 = 11;
    const MREMAP: u64 = 25;
    const OPEN: u64 = 2;
    const CLOSE: u64 = 3;
    const LSEEK: u64 = 8;
    const DUP2: u64 = 33;

    // Build SandlockError::Runtime(Child(..)) the same way capture.rs does.
    let err = |msg: String| SandlockError::Runtime(SandboxRuntimeError::Child(msg));

    let plan = build_memory_plan(&cp.process_state.memory_maps, &cp.process_state.memory_data);
    let (restorable_fds, skipped) = build_fd_plan(&cp.fd_table);

    // CONTRACT: pass the CHECKPOINT's maps so the trampoline lands in a hole of
    // the TARGET layout. That hole is, by construction, never a restored region,
    // so no mmap below can ever clobber the trampoline page.
    let tramp = inject::setup_trampoline(pid, &cp.process_state.memory_maps)
        .map_err(|e| err(format!("restore setup trampoline: {e}")))?;

    // Scratch area for NUL-terminated path strings. The 2-byte gadget lives at
    // `tramp`; the rest of the RWX page (4096 bytes) is free for scratch.
    let scratch = tramp + 64;
    const SCRATCH_MAX: usize = 4096 - 64;
    let write_path = |path: &str| -> Result<(), SandlockError> {
        let mut p = path.as_bytes().to_vec();
        p.push(0);
        if p.len() > SCRATCH_MAX {
            return Err(err("restore path too long for scratch".into()));
        }
        inject::write_child_mem(pid, scratch, &p)
            .map_err(|e| err(format!("restore write path {path}: {e}")))
    };

    // Rebuild every planned memory region. Invariant: none of these regions is
    // the trampoline page -- the trampoline sits in a hole of cp.memory_maps,
    // a region that does not exist in the checkpoint, so it is never restored.
    for region in &plan {
        match region {
            RestoreRegion::WriteBytes { start, end, perms, data } => {
                let len = (end - start) as usize;
                let r = inject::inject_syscall_at(
                    pid,
                    tramp,
                    MMAP,
                    [
                        *start,
                        len as u64,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as u64,
                        (-1i64) as u64,
                        0,
                    ],
                )
                .map_err(|e| err(format!("restore anon mmap at {start:#x}: {e}")))?;
                if r as u64 != *start {
                    return Err(err(format!("restore anon mmap at {start:#x} -> {r:#x}")));
                }
                let n = data.len().min(len);
                inject::write_child_mem(pid, *start, &data[..n])
                    .map_err(|e| err(format!("restore write bytes at {start:#x}: {e}")))?;
                let prot = prot_from_perms(perms);
                if prot != (libc::PROT_READ | libc::PROT_WRITE) {
                    let m = inject::inject_syscall_at(
                        pid,
                        tramp,
                        MPROTECT,
                        [*start, len as u64, prot as u64, 0, 0, 0],
                    )
                    .map_err(|e| err(format!("restore mprotect {start:#x}: {e}")))?;
                    if m != 0 {
                        return Err(err(format!("restore mprotect {start:#x}")));
                    }
                }
            }
            RestoreRegion::RemapFromFile { start, end, perms, offset, path } => {
                let len = (end - start) as usize;
                let prot = prot_from_perms(perms);
                write_path(path)?;
                let fd = inject::inject_syscall_at(
                    pid,
                    tramp,
                    OPEN,
                    [scratch, libc::O_RDONLY as u64, 0, 0, 0, 0],
                )
                .map_err(|e| err(format!("restore open {path}: {e}")))?;
                if fd < 0 {
                    return Err(err(format!("restore open {path} -> {fd}")));
                }
                let r = inject::inject_syscall_at(
                    pid,
                    tramp,
                    MMAP,
                    [
                        *start,
                        len as u64,
                        prot as u64,
                        (libc::MAP_PRIVATE | libc::MAP_FIXED) as u64,
                        fd as u64,
                        *offset,
                    ],
                )
                .map_err(|e| err(format!("restore file mmap at {start:#x}: {e}")))?;
                if r as u64 != *start {
                    return Err(err(format!("restore file mmap at {start:#x} -> {r:#x}")));
                }
                let cl = inject::inject_syscall_at(pid, tramp, CLOSE, [fd as u64, 0, 0, 0, 0, 0])
                    .map_err(|e| err(format!("restore close fd {fd}: {e}")))?;
                if cl < 0 { return Err(err(format!("restore close fd {fd} -> {cl}"))); }
            }
        }
    }

    // Reopen transparently restorable fds at their saved numbers/offsets.
    for f in &restorable_fds {
        write_path(&f.path)?;
        // Mask creation/truncation flags so the restored open cannot create,
        // truncate, or fail-exclusive on the workload's real file. The kernel
        // strips these in fdinfo, but mask defensively since O_TRUNC would be
        // destructive.
        let safe_flags = f.flags & !(libc::O_CREAT | libc::O_TRUNC | libc::O_EXCL);
        let opened = inject::inject_syscall_at(
            pid,
            tramp,
            OPEN,
            [scratch, safe_flags as u64, 0, 0, 0, 0],
        )
        .map_err(|e| err(format!("restore fd open {}: {e}", f.path)))?;
        if opened < 0 {
            return Err(err(format!("restore fd open {} -> {opened}", f.path)));
        }
        if opened as i32 != f.fd {
            // dup2 may clobber an inherited stub fd at this number; that is
            // acceptable -- inherited stub fds are disposable. A documented
            // limitation for now, alongside the W^X trampoline constraint.
            let d = inject::inject_syscall_at(pid, tramp, DUP2, [opened as u64, f.fd as u64, 0, 0, 0, 0])
                .map_err(|e| err(format!("restore dup2 {opened}->{}: {e}", f.fd)))?;
            if d < 0 { return Err(err(format!("restore dup2 {} -> {} failed: {d}", opened, f.fd))); }
            let cl2 = inject::inject_syscall_at(pid, tramp, CLOSE, [opened as u64, 0, 0, 0, 0, 0])
                .map_err(|e| err(format!("restore close dup src {opened}: {e}")))?;
            if cl2 < 0 { return Err(err(format!("restore close dup src {opened} -> {cl2}"))); }
        }
        let ls = inject::inject_syscall_at(
            pid,
            tramp,
            LSEEK,
            [f.fd as u64, f.offset, libc::SEEK_SET as u64, 0, 0, 0],
        )
        .map_err(|e| err(format!("restore lseek fd {}: {e}", f.fd)))?;
        if ls < 0 {
            return Err(err(format!("restore lseek fd {}", f.fd)));
        }
    }

    // Relocate the kernel-provided [vdso]/[vvar] to the addresses the checkpoint
    // recorded. glibc caches vDSO function pointers (clock_gettime, getcpu, ...)
    // in process memory at the vDSO's original base; without this, a restored
    // libc program jumps to the checkpoint-era base, which the fresh stub mapped
    // elsewhere under ASLR, and faults on its first vDSO call. Same-kernel
    // restore only: the vDSO code is byte-identical, so moving it to the recorded
    // base makes every cached pointer valid. A vDSO-free checkpoint yields no
    // moves.
    {
        let cur = crate::checkpoint::capture::parse_proc_maps(pid)
            .map_err(|e| err(format!("restore read maps for vdso relocation: {e}")))?;
        let moves = plan_vdso_moves(&cur, &cp.process_state.memory_maps)
            .map_err(|m| err(format!("restore vdso relocation: {m}")))?;
        for mv in moves {
            let flags = (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64;
            let r = inject::inject_syscall_at(
                pid,
                tramp,
                MREMAP,
                [mv.cur_start, mv.len, mv.len, flags, mv.target_start, 0],
            )
            .map_err(|e| {
                err(format!(
                    "restore mremap {:#x}->{:#x}: {e}",
                    mv.cur_start, mv.target_start
                ))
            })?;
            if r as u64 != mv.target_start {
                return Err(err(format!(
                    "restore mremap {:#x}->{:#x} -> {r:#x}",
                    mv.cur_start, mv.target_start
                )));
            }
        }
    }

    // Unmap the RWX trampoline as the very last injected syscall, after all
    // region and fd injections (which need it), and before the register restores
    // (which use ptrace, not the trampoline). The `syscall` instruction at
    // `tramp` is fetched and executed before the page is removed; after return,
    // rip is restored to the stub's original rip (still mapped), and the
    // following set_gp_regs points rip at the checkpoint's saved value. The
    // unmapped page is therefore never executed again. This closes the W^X gap
    // that would otherwise leave a writable+executable page in the restored process.
    let mu = inject::inject_syscall_at(pid, tramp, MUNMAP, [tramp, 4096, 0, 0, 0, 0])
        .map_err(|e| err(format!("restore munmap trampoline {tramp:#x}: {e}")))?;
    if mu != 0 { return Err(err(format!("restore munmap trampoline {tramp:#x} -> {mu}"))); }

    // Registers last: load the saved FP then GP register files. After this the
    // child is stopped exactly at the checkpoint's execution point.
    crate::checkpoint::regs::set_fp_regs(pid, &cp.process_state.fpregs)
        .map_err(|e| err(format!("restore set fp regs: {e}")))?;

    // Re-arm an interrupted, restartable syscall. When the checkpoint was taken
    // (via PTRACE_INTERRUPT) while the process sat in a syscall, the kernel
    // aborted it with a restart sentinel in rax (-ERESTARTSYS/-ERESTARTNOINTR/
    // -ERESTARTNOHAND/-ERESTART_RESTARTBLOCK). At the ptrace stop, rip still
    // points just PAST the `syscall` instruction (it equals rcx, the return
    // address the CPU latched when `syscall` executed). The kernel's restart
    // fixup -- rewind rip onto the 2-byte `syscall` instruction and reload rax
    // with the original syscall number -- normally runs on the syscall-return /
    // signal-delivery path, which a plain restore + detach bypasses. Without it,
    // userspace would resume one instruction past the syscall with the raw
    // sentinel (e.g. -514) in rax and fault. Apply the fixup ourselves so the
    // syscall re-executes cleanly with its arguments still in registers (this is
    // what CRIU does). x86_64 user_regs_struct layout: rax=10, orig_rax=15, rip=16.
    //
    // Real restart sentinels: -512 ERESTARTSYS, -513 ERESTARTNOINTR,
    // -514 ERESTARTNOHAND, -516 ERESTART_RESTARTBLOCK. -515 (ENOIOCTLCMD) is
    // NOT a restart code and must not be matched. For ERESTART_RESTARTBLOCK
    // (-516) we re-run orig_rax rather than the kernel restart_syscall path
    // (restart_block is not captured), so timeout-bearing syscalls restart with
    // their full original timeout rather than remaining time -- accepted
    // approximation for fresh-process restore.
    const RAX: usize = 10;
    const ORIG_RAX: usize = 15;
    const RIP: usize = 16;
    let mut regs = cp.process_state.regs.clone();
    if let (Some(&rax), Some(&orig_rax)) = (regs.get(RAX), regs.get(ORIG_RAX)) {
        let rax_signed = rax as i64;
        if matches!(rax_signed, -512 | -513 | -514 | -516) {
            regs[RAX] = orig_rax;
            regs[RIP] = regs[RIP].wrapping_sub(2);
        }
    }
    crate::checkpoint::regs::set_gp_regs(pid, &regs)
        .map_err(|e| err(format!("restore set gp regs: {e}")))?;

    Ok(skipped)
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn restore_into(
    _pid: i32,
    _cp: &Checkpoint,
) -> Result<Vec<SkippedFd>, crate::error::SandlockError> {
    Err(crate::error::SandlockError::Runtime(
        crate::error::SandboxRuntimeError::Child(
            "injection-based restore is only implemented on x86_64".into(),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{FdInfo, MemoryMap, MemorySegment, SkippedFd};

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

    fn map(start: u64, end: u64, path: Option<&str>) -> MemoryMap {
        MemoryMap { start, end, perms: "rw-p".into(), offset: 0, path: path.map(Into::into) }
    }

    #[test]
    fn vdso_moves_relocate_present_mappings_only() {
        // Stub layout (cur) and checkpoint layout (cp) disagree on vdso/vvar
        // bases; a non-special region present in both is ignored.
        let cur = vec![
            map(0x1000, 0x2000, Some("[vvar]")),
            map(0x2000, 0x3000, Some("[vdso]")),
            map(0x9000, 0xa000, None),
        ];
        let cp = vec![
            map(0x5000, 0x6000, Some("[vvar]")),
            map(0x6000, 0x7000, Some("[vdso]")),
        ];
        let moves = plan_vdso_moves(&cur, &cp).expect("no cycle");
        assert_eq!(moves.len(), 2, "both special mappings relocate");
        assert!(moves.iter().any(|m| m.cur_start == 0x1000 && m.target_start == 0x5000));
        assert!(moves.iter().any(|m| m.cur_start == 0x2000 && m.target_start == 0x6000));
    }

    #[test]
    fn vdso_moves_skip_when_base_already_matches() {
        let cur = vec![map(0x5000, 0x6000, Some("[vdso]"))];
        let cp = vec![map(0x5000, 0x6000, Some("[vdso]"))];
        assert!(plan_vdso_moves(&cur, &cp).unwrap().is_empty(),
            "no move when the base already matches");
    }

    #[test]
    fn vdso_moves_skip_when_absent_from_checkpoint() {
        // A freestanding checkpoint records no vdso; nothing to relocate.
        let cur = vec![map(0x2000, 0x3000, Some("[vdso]"))];
        let cp = vec![map(0x2000, 0x3000, None)];
        assert!(plan_vdso_moves(&cur, &cp).unwrap().is_empty());
    }

    #[test]
    fn vdso_moves_order_avoids_clobbering_a_source() {
        // vvar must move onto the range vdso currently occupies. Moving vvar
        // first would destroy vdso's source, so vdso must be scheduled first.
        let cur = vec![
            map(0x1000, 0x2000, Some("[vvar]")),
            map(0x5000, 0x6000, Some("[vdso]")),
        ];
        let cp = vec![
            map(0x5000, 0x6000, Some("[vvar]")), // vvar target == vdso's current base
            map(0x8000, 0x9000, Some("[vdso]")),
        ];
        let moves = plan_vdso_moves(&cur, &cp).expect("no cycle");
        assert_eq!(moves[0].cur_start, 0x5000, "vdso relocates before vvar overwrites its base");
        assert_eq!(moves[1].cur_start, 0x1000);
    }

    #[test]
    fn vdso_moves_reject_unresolvable_swap() {
        // Each mapping's target is the other's current base: no safe order.
        let cur = vec![
            map(0x1000, 0x2000, Some("[vvar]")),
            map(0x5000, 0x6000, Some("[vdso]")),
        ];
        let cp = vec![
            map(0x5000, 0x6000, Some("[vvar]")),
            map(0x1000, 0x2000, Some("[vdso]")),
        ];
        assert!(plan_vdso_moves(&cur, &cp).is_err(), "a pure swap is rejected, not corrupted");
    }

    #[test]
    fn plan_classifies_regions() {
        let maps = vec![
            MemoryMap { start: 0x1000, end: 0x2000, perms: "r-xp".into(), offset: 0,
                        path: Some("/bin/app".into()) },          // code: remap from file
            MemoryMap { start: 0x3000, end: 0x4000, perms: "rw-p".into(), offset: 0,
                        path: None },                              // anon writable: write bytes
            MemoryMap { start: 0x5000, end: 0x6000, perms: "r--p".into(), offset: 0,
                        path: Some("[vvar]".into()) },             // special: skip
        ];
        let data = vec![MemorySegment { start: 0x3000, data: vec![7u8; 0x1000] }];
        let plan = build_memory_plan(&maps, &data);
        assert!(matches!(plan[0], RestoreRegion::RemapFromFile { .. }));
        assert!(matches!(plan[1], RestoreRegion::WriteBytes { .. }));
        assert_eq!(plan.len(), 2, "special regions are skipped, not planned");
    }

    /// End-to-end proof of the injection-based rebuild: capture a donor's known
    /// page + registers, then drive `restore_into` against a fresh stub and read
    /// BOTH back from the still-stopped stub before resuming it. No Landlock and
    /// no resume are needed -- the read-back alone proves mmap + writev (memory)
    /// and SETREGSET (registers) flowed through the trampoline correctly.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn restore_into_reconstructs_memory_and_regs() {
        const DON: u64 = 0x4500_0000_0000;
        const PAT: u8 = 0xC7;

        // Donor: raw-libc child that maps a known page at a fixed hole, fills it
        // with a recognizable pattern, then pauses forever. No allocation/panic.
        let donor = unsafe { libc::fork() };
        if donor == 0 {
            unsafe {
                let p = libc::mmap(
                    DON as *mut libc::c_void,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                );
                if p != DON as *mut libc::c_void {
                    libc::_exit(1);
                }
                let mut i = 0usize;
                while i < 4096 {
                    *(DON as *mut u8).add(i) = PAT;
                    i += 1;
                }
                loop {
                    libc::pause();
                }
            }
        }
        assert!(donor > 0, "fork donor");
        // Let the donor finish its mmap+fill before we seize it.
        unsafe {
            libc::usleep(50_000);
        }

        let policy = crate::Sandbox::builder().build().unwrap();
        let cp = crate::checkpoint::capture::capture(donor as i32, &policy).expect("capture");

        // The donor is no longer needed; capture already detached.
        unsafe {
            libc::kill(donor, libc::SIGKILL);
            let mut s = 0;
            libc::waitpid(donor, &mut s, 0);
        }

        // Sanity: the donor's page was captured with our pattern. If not, the
        // test setup -- not restore_into -- is wrong.
        let seg = cp
            .process_state
            .memory_data
            .iter()
            .find(|s| s.start == DON)
            .expect("donor DON page must be captured");
        assert!(
            seg.data.len() >= 4096 && seg.data[..4096].iter().all(|&b| b == PAT),
            "captured DON page must be all 0x{PAT:02x}"
        );

        // Stub: a traceable child that stops and is never continued. The test
        // process becomes its tracer via PTRACE_TRACEME.
        let stub = unsafe { libc::fork() };
        if stub == 0 {
            unsafe {
                libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                libc::raise(libc::SIGSTOP);
                libc::_exit(0); // only reached if continued, which we never do
            }
        }
        assert!(stub > 0, "fork stub");
        let mut st = 0i32;
        unsafe {
            libc::waitpid(stub, &mut st, 0);
        } // catch the SIGSTOP-stop

        let _skipped = restore_into(stub, &cp).expect("restore_into");

        // Read the restored DON page back out of the still-stopped stub.
        let mut buf = vec![0u8; 4096];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: 4096,
        };
        let remote = libc::iovec {
            iov_base: DON as *mut libc::c_void,
            iov_len: 4096,
        };
        let n = unsafe { libc::process_vm_readv(stub, &local, 1, &remote, 1, 0) };

        // Read the restored GP register file back out of the stub.
        let read_regs = crate::checkpoint::capture::ptrace_getregs(stub);

        // Reap the stub before asserting so a failed assert never leaks it.
        unsafe {
            libc::kill(stub, libc::SIGKILL);
            let mut s = 0;
            libc::waitpid(stub, &mut s, 0);
        }

        assert_eq!(n, 4096, "process_vm_readv of restored DON page");
        assert!(
            buf.iter().all(|&b| b == PAT),
            "restored DON page must be all 0x{PAT:02x}"
        );

        let read_regs = read_regs.expect("read stub regs");
        // `restore_into` restores registers verbatim EXCEPT it re-arms an
        // interrupted, restartable syscall: when the checkpoint's rax holds a
        // restart sentinel (-512 ERESTARTSYS, -513 ERESTARTNOINTR, -514
        // ERESTARTNOHAND, -516 ERESTART_RESTARTBLOCK; note -515 ENOIOCTLCMD is
        // NOT a sentinel), it reloads rax with orig_rax and rewinds rip by 2
        // onto the `syscall` instruction so the call re-executes cleanly on
        // resume. The donor here is captured in `pause()`, which is restartable,
        // so apply the same fixup to build the expected register set.
        let mut expected = cp.process_state.regs.clone();
        const RAX: usize = 10;
        const ORIG_RAX: usize = 15;
        const RIP: usize = 16;
        let rax_signed = expected[RAX] as i64;
        if matches!(rax_signed, -512 | -513 | -514 | -516) {
            expected[RAX] = expected[ORIG_RAX];
            expected[RIP] = expected[RIP].wrapping_sub(2);
        }
        assert_eq!(
            read_regs, expected,
            "restored GP registers must match the checkpoint (with syscall-restart re-arm)"
        );
    }
}
