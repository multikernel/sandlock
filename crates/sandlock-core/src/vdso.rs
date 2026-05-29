use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};

use crate::error::SandlockError;

/// Find the base address and size of the vDSO mapping for a given process.
pub(crate) fn find_vdso_range(pid: i32) -> io::Result<(u64, u64)> {
    let path = format!("/proc/{}/maps", pid);
    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.ends_with("[vdso]") {
            // Line format: "7ffd1234000-7ffd1235000 r-xp ... [vdso]"
            let space = line.find(' ').unwrap_or(line.len());
            let range = &line[..space];
            if let Some(dash_pos) = range.find('-') {
                let start = u64::from_str_radix(&range[..dash_pos], 16).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad vDSO start: {}", e))
                })?;
                let end = u64::from_str_radix(&range[dash_pos + 1..], 16).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad vDSO end: {}", e))
                })?;
                return Ok((start, end - start));
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "vDSO mapping not found",
    ))
}

/// Find the base address of the vDSO mapping for a given process.
pub(crate) fn find_vdso_base(pid: i32) -> io::Result<u64> {
    find_vdso_range(pid).map(|(base, _)| base)
}

/// Read `len` bytes from `/proc/{pid}/mem` at the given address.
fn read_proc_mem(pid: i32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut file = File::open(format!("/proc/{}/mem", pid))?;
    file.seek(SeekFrom::Start(addr))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Parse vDSO ELF bytes and return a map of symbol name -> offset from ELF base.
fn parse_vdso_symbols(vdso_bytes: &[u8]) -> HashMap<String, u64> {
    let mut symbols = HashMap::new();

    if let Ok(elf) = goblin::elf::Elf::parse(vdso_bytes) {
        for sym in elf.dynsyms.iter() {
            if sym.st_value != 0 {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        symbols.insert(name.to_string(), sym.st_value);
                    }
                }
            }
        }
    }

    symbols
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn push_insn(stub: &mut Vec<u8>, insn: u32) {
    stub.extend_from_slice(&insn.to_le_bytes());
}

/// Encode an arm64 unconditional `B target` instruction located at `from`.
/// `imm26` is signed and scaled by 4, so the reachable range is ±128 MiB.
#[cfg(target_arch = "aarch64")]
fn arm64_b_insn(from: u64, to: u64) -> Result<u32, SandlockError> {
    let delta = to as i64 - from as i64;
    if delta % 4 != 0 {
        return Err(SandlockError::MemoryProtect(format!(
            "arm64 B target {:#x} not 4-byte aligned from {:#x}",
            to, from
        )));
    }
    let offset = delta / 4;
    if !(-(1i64 << 25)..(1i64 << 25)).contains(&offset) {
        return Err(SandlockError::MemoryProtect(format!(
            "arm64 B {:#x}->{:#x} out of ±128 MiB range",
            from, to
        )));
    }
    Ok(0x14000000u32 | ((offset as u32) & 0x03FF_FFFF))
}

/// Compute the offset within the vDSO mapping where the trampoline area starts —
/// just past the last symbol, rounded up to a 16-byte boundary.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn vdso_tramp_start(vdso_bytes: &[u8]) -> Option<u64> {
    let elf = goblin::elf::Elf::parse(vdso_bytes).ok()?;
    let highest_end = elf
        .dynsyms
        .iter()
        .filter(|s| s.st_value != 0)
        .map(|s| s.st_value + s.st_size)
        .max()?;
    Some((highest_end + 15) & !15)
}

#[cfg(target_arch = "aarch64")]
fn movz_x(reg: u32, imm16: u16, shift: u32) -> u32 {
    0xD280_0000 | (((shift / 16) & 0x3) << 21) | ((imm16 as u32) << 5) | reg
}

#[cfg(target_arch = "aarch64")]
fn movk_x(reg: u32, imm16: u16, shift: u32) -> u32 {
    0xF280_0000 | (((shift / 16) & 0x3) << 21) | ((imm16 as u32) << 5) | reg
}

#[cfg(target_arch = "aarch64")]
fn load_imm64(stub: &mut Vec<u8>, reg: u32, value: u64) {
    push_insn(stub, movz_x(reg, (value & 0xffff) as u16, 0));
    push_insn(stub, movk_x(reg, ((value >> 16) & 0xffff) as u16, 16));
    push_insn(stub, movk_x(reg, ((value >> 32) & 0xffff) as u16, 32));
    push_insn(stub, movk_x(reg, ((value >> 48) & 0xffff) as u16, 48));
}

/// Generate a simple stub that forces a real syscall (replacing the vDSO fast path).
#[cfg(target_arch = "x86_64")]
/// Layout: mov eax, imm32 / syscall / ret — 8 bytes total.
fn simple_stub(syscall_nr: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.push(0xB8); // mov eax, imm32
    stub.extend_from_slice(&syscall_nr.to_le_bytes()); // syscall number
    stub.extend_from_slice(&[0x0F, 0x05]); // syscall
    stub.push(0xC3); // ret
    stub // 8 bytes total
}

#[cfg(target_arch = "aarch64")]
fn simple_stub(syscall_nr: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    push_insn(&mut stub, movz_x(8, syscall_nr as u16, 0)); // mov x8, syscall_nr
    push_insn(&mut stub, 0xD400_0001); // svc #0
    push_insn(&mut stub, 0xD65F_03C0); // ret
    stub
}

/// Generate an offset stub for clock_gettime that forces a real syscall,
/// then adds a time offset to the result for CLOCK_REALTIME and CLOCK_REALTIME_COARSE.
///
#[cfg(target_arch = "x86_64")]
/// Layout (x86-64):
///   push rdi / push rsi
///   mov eax, 228 / syscall          ; do the real syscall
///   pop rsi / pop rdi               ; restore args (rsi = timespec*)
///   cmp edi, 0                      ; CLOCK_REALTIME?
///   je  +5                          ; yes → skip second check, apply offset
///   cmp edi, 5                      ; CLOCK_REALTIME_COARSE?
///   jne +13                         ; neither → skip to ret
///   movabs rcx, offset_secs         ; load 8-byte offset
///   add  [rsi], rcx                 ; adjust tv_sec
///   ret
fn offset_stub_clock_gettime(offset_secs: i64) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.push(0x57); // push rdi
    stub.push(0x56); // push rsi
    stub.extend_from_slice(&[0xB8, 0xE4, 0x00, 0x00, 0x00]); // mov eax, 228
    stub.extend_from_slice(&[0x0F, 0x05]); // syscall
    stub.push(0x5E); // pop rsi
    stub.push(0x5F); // pop rdi
    stub.extend_from_slice(&[0x83, 0xFF, 0x00]); // cmp edi, 0 (CLOCK_REALTIME)
    stub.push(0x74); // je (short jump) — if CLOCK_REALTIME, jump to movabs
    // Skip second check: cmp edi,5 (3 bytes) + jne (2 bytes) = 5
    let jump_to_movabs: u8 = 3 + 2;
    stub.push(jump_to_movabs);
    stub.extend_from_slice(&[0x83, 0xFF, 0x05]); // cmp edi, 5 (CLOCK_REALTIME_COARSE)
    stub.push(0x75); // jne (short jump) — if NOT CLOCK_REALTIME_COARSE, skip to ret
    // Skip: movabs rcx (10) + add [rsi],rcx (3) = 13
    let jump_to_ret: u8 = 10 + 3;
    stub.push(jump_to_ret);
    stub.extend_from_slice(&[0x48, 0xB9]); // movabs rcx, imm64
    stub.extend_from_slice(&offset_secs.to_le_bytes()); // 8-byte offset
    stub.extend_from_slice(&[0x48, 0x01, 0x0E]); // add [rsi], rcx
    stub.push(0xC3); // ret
    stub
}

#[cfg(target_arch = "aarch64")]
fn offset_stub_clock_gettime(offset_secs: i64) -> Vec<u8> {
    let mut stub = Vec::new();
    push_insn(&mut stub, 0xAA00_03E9); // mov x9, x0 (clock id)
    push_insn(&mut stub, 0xAA01_03EA); // mov x10, x1 (timespec*)
    push_insn(&mut stub, movz_x(8, libc::SYS_clock_gettime as u16, 0));
    push_insn(&mut stub, 0xD400_0001); // svc #0
    push_insn(&mut stub, 0x7100_013F); // cmp w9, #0 (CLOCK_REALTIME)
    push_insn(&mut stub, 0x5400_0060); // b.eq +3 instructions
    push_insn(&mut stub, 0x7100_153F); // cmp w9, #5 (CLOCK_REALTIME_COARSE)
    push_insn(&mut stub, 0x5400_0101); // b.ne +8 instructions, to ret
    load_imm64(&mut stub, 11, offset_secs as u64); // x11 = offset
    push_insn(&mut stub, 0xF940_014C); // ldr x12, [x10]
    push_insn(&mut stub, 0x8B0B_018C); // add x12, x12, x11
    push_insn(&mut stub, 0xF900_014C); // str x12, [x10]
    push_insn(&mut stub, 0xD65F_03C0); // ret
    stub
}

/// Generate an offset stub for gettimeofday that forces a real syscall,
/// then adds a time offset to tv_sec.
#[cfg(target_arch = "x86_64")]
fn offset_stub_gettimeofday(offset_secs: i64) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&[0x57, 0x56]); // push rdi, push rsi
    stub.extend_from_slice(&[0xB8, 0x60, 0x00, 0x00, 0x00]); // mov eax, 96
    stub.extend_from_slice(&[0x0F, 0x05]); // syscall
    stub.extend_from_slice(&[0x5E, 0x5F]); // pop rsi, pop rdi
    stub.extend_from_slice(&[0x48, 0xB9]); // movabs rcx, imm64
    stub.extend_from_slice(&offset_secs.to_le_bytes());
    stub.extend_from_slice(&[0x48, 0x01, 0x0E]); // add [rsi], rcx (tv_sec)
    stub.push(0xC3); // ret
    stub
}

#[cfg(target_arch = "aarch64")]
fn offset_stub_gettimeofday(offset_secs: i64) -> Vec<u8> {
    let mut stub = Vec::new();
    push_insn(&mut stub, 0xAA00_03EA); // mov x10, x0 (timeval*)
    push_insn(&mut stub, movz_x(8, libc::SYS_gettimeofday as u16, 0));
    push_insn(&mut stub, 0xD400_0001); // svc #0
    push_insn(&mut stub, 0xB400_010A); // cbz x10, +8 instructions, to ret
    load_imm64(&mut stub, 11, offset_secs as u64); // x11 = offset
    push_insn(&mut stub, 0xF940_014C); // ldr x12, [x10]
    push_insn(&mut stub, 0x8B0B_018C); // add x12, x12, x11
    push_insn(&mut stub, 0xF900_014C); // str x12, [x10]
    push_insn(&mut stub, 0xD65F_03C0); // ret
    stub
}

#[cfg(target_arch = "x86_64")]
fn vdso_targets() -> Vec<(&'static str, &'static str, u32)> {
    vec![
        ("clock_gettime", "__vdso_clock_gettime", libc::SYS_clock_gettime as u32),
        ("gettimeofday", "__vdso_gettimeofday", libc::SYS_gettimeofday as u32),
        ("time", "__vdso_time", libc::SYS_time as u32),
    ]
}

#[cfg(target_arch = "aarch64")]
fn vdso_targets() -> Vec<(&'static str, &'static str, u32)> {
    vec![
        ("clock_gettime", "__kernel_clock_gettime", libc::SYS_clock_gettime as u32),
        ("gettimeofday", "__kernel_gettimeofday", libc::SYS_gettimeofday as u32),
    ]
}

// ============================================================
// riscv64 vDSO codegen
//
// Like aarch64, riscv64 places a full stub in the slack space at the tail of
// the vDSO mapping and patches each function entry with a single 4-byte `j`
// (jal x0) that jumps to its stub. The offset stubs run the real syscall, then
// add the time offset to the returned tv_sec (mirroring x86_64/aarch64). The
// 64-bit offset is stored as data at the tail of each stub and loaded
// PC-relative via `auipc`, so the stub is position-independent. It is read with
// two naturally-aligned 4-byte loads (lwu/lw) to avoid a misaligned 8-byte load.
// ============================================================

/// Emit `li a7, value` (load syscall number into a7/x17). Uses a single `addi`
/// for the 12-bit case (all syscall numbers sandlock patches fit), falling back
/// to `lui`+`addiw` for larger 32-bit values.
#[cfg(target_arch = "riscv64")]
fn riscv_li_a7(stub: &mut Vec<u8>, value: u32) {
    const A7: u32 = 17;
    if value < 2048 {
        // addi a7, x0, value
        push_insn(stub, (value << 20) | (A7 << 7) | 0x13);
    } else {
        let lo12 = value & 0xfff;
        // sign-extend lo12: if bit 11 is set, addiw subtracts, so bump hi20.
        let hi20 = if lo12 & 0x800 != 0 {
            (value >> 12).wrapping_add(1) & 0xf_ffff
        } else {
            (value >> 12) & 0xf_ffff
        };
        push_insn(stub, (hi20 << 12) | (A7 << 7) | 0x37); // lui a7, hi20
        push_insn(stub, ((lo12 & 0xfff) << 20) | (A7 << 15) | (A7 << 7) | 0x1b); // addiw a7, a7, lo12
    }
}

/// Encode a riscv64 unconditional `j target` (jal x0, offset) located at `from`.
/// The JAL immediate is signed and scaled by 2, so the reachable range is ±1 MiB.
#[cfg(target_arch = "riscv64")]
fn riscv_j_insn(from: u64, to: u64) -> Result<u32, SandlockError> {
    let delta = to as i64 - from as i64;
    if delta % 2 != 0 {
        return Err(SandlockError::MemoryProtect(format!(
            "riscv64 J target {:#x} not 2-byte aligned from {:#x}",
            to, from
        )));
    }
    if !(-(1i64 << 20)..(1i64 << 20)).contains(&delta) {
        return Err(SandlockError::MemoryProtect(format!(
            "riscv64 J {:#x}->{:#x} out of ±1 MiB range",
            from, to
        )));
    }
    let imm = delta as u32;
    let b20 = (imm >> 20) & 0x1;
    let b10_1 = (imm >> 1) & 0x3ff;
    let b11 = (imm >> 11) & 0x1;
    let b19_12 = (imm >> 12) & 0xff;
    // jal x0, offset (rd = x0)
    Ok((b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | 0x6f)
}

/// Minimal RV64I instruction encoders for the time-offset stubs. Registers are
/// ABI numbers; the stubs touch only caller-saved temporaries (t0-t6) and the
/// syscall registers (a0/a1/a7), so they need no prologue/epilogue.
#[cfg(target_arch = "riscv64")]
mod rv {
    pub const X0: u32 = 0;
    pub const T0: u32 = 5;
    pub const T1: u32 = 6;
    pub const T2: u32 = 7;
    pub const A0: u32 = 10;
    pub const A1: u32 = 11;
    pub const A7: u32 = 17;
    pub const T3: u32 = 28;
    pub const T4: u32 = 29;
    pub const T5: u32 = 30;
    pub const T6: u32 = 31;
    pub const ECALL: u32 = 0x0000_0073;
    pub const RET: u32 = 0x0000_8067; // jalr x0, 0(ra)

    pub fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
        ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
    }
    /// `mv rd, rs` == `addi rd, rs, 0`
    pub fn mv(rd: u32, rs: u32) -> u32 {
        addi(rd, rs, 0)
    }
    pub fn auipc(rd: u32, imm20: u32) -> u32 {
        (imm20 << 12) | (rd << 7) | 0x17
    }
    pub fn lwu(rd: u32, rs1: u32, imm: i32) -> u32 {
        ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (6 << 12) | (rd << 7) | 0x03
    }
    pub fn lw(rd: u32, rs1: u32, imm: i32) -> u32 {
        ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x03
    }
    pub fn ld(rd: u32, rs1: u32, imm: i32) -> u32 {
        ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (3 << 12) | (rd << 7) | 0x03
    }
    pub fn sd(rs2: u32, rs1: u32, imm: i32) -> u32 {
        let i = imm as u32;
        ((i >> 5 & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | ((i & 0x1f) << 7) | 0x23
    }
    pub fn slli(rd: u32, rs1: u32, shamt: u32) -> u32 {
        ((shamt & 0x3f) << 20) | (rs1 << 15) | (1 << 12) | (rd << 7) | 0x13
    }
    pub fn or(rd: u32, rs1: u32, rs2: u32) -> u32 {
        (rs2 << 20) | (rs1 << 15) | (6 << 12) | (rd << 7) | 0x33
    }
    pub fn add(rd: u32, rs1: u32, rs2: u32) -> u32 {
        (rs2 << 20) | (rs1 << 15) | (rd << 7) | 0x33
    }
    pub fn beq(rs1: u32, rs2: u32, imm: i32) -> u32 {
        branch(0, rs1, rs2, imm)
    }
    pub fn bne(rs1: u32, rs2: u32, imm: i32) -> u32 {
        branch(1, rs1, rs2, imm)
    }
    fn branch(funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
        let i = imm as u32;
        ((i >> 12 & 1) << 31)
            | ((i >> 5 & 0x3f) << 25)
            | (rs2 << 20)
            | (rs1 << 15)
            | (funct3 << 12)
            | ((i >> 1 & 0xf) << 8)
            | ((i >> 11 & 1) << 7)
            | 0x63
    }
}

#[cfg(target_arch = "riscv64")]
fn simple_stub(syscall_nr: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    riscv_li_a7(&mut stub, syscall_nr);
    push_insn(&mut stub, 0x0000_0073); // ecall
    push_insn(&mut stub, 0x0000_8067); // ret (jalr x0, 0(ra))
    stub
}

/// clock_gettime(clockid=a0, timespec*=a1): run the real syscall, then add the
/// time offset to tv_sec for CLOCK_REALTIME (0) and CLOCK_REALTIME_COARSE (5).
#[cfg(target_arch = "riscv64")]
fn offset_stub_clock_gettime(offset_secs: i64) -> Vec<u8> {
    use rv::*;
    const DOFF: i32 = 36; // bytes from the `auipc` to the embedded offset data
    let nr = libc::SYS_clock_gettime as i32;
    let insns: [u32; 16] = [
        mv(T0, A0),           // save clockid (a0 is overwritten by the return)
        mv(T4, A1),           // save timespec*
        addi(A7, X0, nr),     // li a7, SYS_clock_gettime
        ECALL,                // a0 = kernel return value (preserved to the caller)
        beq(T0, X0, 12),      // clockid == CLOCK_REALTIME -> apply
        addi(T1, X0, 5),      // li t1, CLOCK_REALTIME_COARSE
        bne(T0, T1, 36),      // clockid != COARSE -> end (skip offset)
        auipc(T2, 0),         // apply: t2 = &this instruction
        lwu(T5, T2, DOFF),    // t5 = low 32 bits of offset (zero-extended)
        lw(T6, T2, DOFF + 4), // t6 = high 32 bits (sign-extended)
        slli(T6, T6, 32),
        or(T2, T5, T6),       // t2 = full 64-bit offset
        ld(T3, T4, 0),        // t3 = tv_sec
        add(T3, T3, T2),      // t3 += offset
        sd(T3, T4, 0),        // tv_sec = t3
        RET,                  // end
    ];
    let mut stub = Vec::with_capacity(insns.len() * 4 + 8);
    for insn in insns {
        push_insn(&mut stub, insn);
    }
    stub.extend_from_slice(&offset_secs.to_le_bytes());
    stub
}

/// gettimeofday(timeval*=a0): run the real syscall, then add the time offset to
/// tv_sec, unless the timeval pointer is NULL.
#[cfg(target_arch = "riscv64")]
fn offset_stub_gettimeofday(offset_secs: i64) -> Vec<u8> {
    use rv::*;
    const DOFF: i32 = 36;
    let nr = libc::SYS_gettimeofday as i32;
    let insns: [u32; 13] = [
        mv(T4, A0),           // save timeval*
        addi(A7, X0, nr),     // li a7, SYS_gettimeofday
        ECALL,
        beq(T4, X0, 36),      // timeval == NULL -> end
        auipc(T2, 0),
        lwu(T5, T2, DOFF),
        lw(T6, T2, DOFF + 4),
        slli(T6, T6, 32),
        or(T2, T5, T6),
        ld(T3, T4, 0),        // t3 = tv_sec
        add(T3, T3, T2),
        sd(T3, T4, 0),
        RET,                  // end
    ];
    let mut stub = Vec::with_capacity(insns.len() * 4 + 8);
    for insn in insns {
        push_insn(&mut stub, insn);
    }
    stub.extend_from_slice(&offset_secs.to_le_bytes());
    stub
}

#[cfg(target_arch = "riscv64")]
fn vdso_targets() -> Vec<(&'static str, &'static str, u32)> {
    vec![
        ("clock_gettime", "__vdso_clock_gettime", libc::SYS_clock_gettime as u32),
        ("gettimeofday", "__vdso_gettimeofday", libc::SYS_gettimeofday as u32),
    ]
}

/// Patch the vDSO of a target process to force real syscalls (interceptable by seccomp).
/// If `time_offset_secs` is provided, clock_gettime and gettimeofday stubs will add
/// the offset to the returned time.
pub(crate) fn patch(
    pid: i32,
    time_offset_secs: Option<i64>,
    _patch_for_random: bool,
) -> Result<(), SandlockError> {
    let (base, mapping_size) = find_vdso_range(pid).map_err(|e| {
        SandlockError::MemoryProtect(format!("failed to find vDSO range: {}", e))
    })?;

    let read_size = std::cmp::min(mapping_size as usize, 0x4000);
    let vdso_bytes = read_proc_mem(pid, base, read_size).map_err(|e| {
        SandlockError::MemoryProtect(format!("failed to read vDSO memory: {}", e))
    })?;

    let symbols = parse_vdso_symbols(&vdso_bytes);

    let mut mem = OpenOptions::new()
        .write(true)
        .open(format!("/proc/{}/mem", pid))
        .map_err(|e| {
            SandlockError::MemoryProtect(format!("failed to open /proc/{}/mem: {}", pid, e))
        })?;

    // arm64/riscv64: place full stubs in slack space at the tail of the vDSO
    // mapping and patch each function entry with a single 4-byte jump to its stub.
    // x86_64: stubs are short and inter-symbol gaps are wide; patch inline.
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    let mut tramp_offset = vdso_tramp_start(&vdso_bytes).unwrap_or(0);

    for (name, alt_name, syscall_nr) in vdso_targets() {
        if let Some(&offset) = symbols.get(name).or_else(|| symbols.get(alt_name)) {
            let entry_addr = base + offset;
            let stub = match (time_offset_secs, name) {
                (Some(off), "clock_gettime") => offset_stub_clock_gettime(off),
                (Some(off), "gettimeofday") => offset_stub_gettimeofday(off),
                _ => simple_stub(syscall_nr),
            };

            #[cfg(target_arch = "x86_64")]
            {
                mem.seek(SeekFrom::Start(entry_addr)).map_err(|e| {
                    SandlockError::MemoryProtect(format!(
                        "failed to seek to {} at {:#x}: {}",
                        name, entry_addr, e
                    ))
                })?;
                mem.write_all(&stub).map_err(|e| {
                    SandlockError::MemoryProtect(format!(
                        "failed to write {} stub at {:#x}: {}",
                        name, entry_addr, e
                    ))
                })?;
            }

            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            {
                if tramp_offset + stub.len() as u64 > mapping_size {
                    return Err(SandlockError::MemoryProtect(format!(
                        "vDSO trampoline area exhausted: need {} bytes at offset {:#x}, mapping ends at {:#x}",
                        stub.len(), tramp_offset, mapping_size
                    )));
                }
                let tramp_addr = base + tramp_offset;

                mem.seek(SeekFrom::Start(tramp_addr)).map_err(|e| {
                    SandlockError::MemoryProtect(format!(
                        "failed to seek to {} trampoline at {:#x}: {}",
                        name, tramp_addr, e
                    ))
                })?;
                mem.write_all(&stub).map_err(|e| {
                    SandlockError::MemoryProtect(format!(
                        "failed to write {} trampoline at {:#x}: {}",
                        name, tramp_addr, e
                    ))
                })?;

                #[cfg(target_arch = "aarch64")]
                let b_insn = arm64_b_insn(entry_addr, tramp_addr)?;
                #[cfg(target_arch = "riscv64")]
                let b_insn = riscv_j_insn(entry_addr, tramp_addr)?;
                mem.seek(SeekFrom::Start(entry_addr)).map_err(|e| {
                    SandlockError::MemoryProtect(format!(
                        "failed to seek to {} entry at {:#x}: {}",
                        name, entry_addr, e
                    ))
                })?;
                mem.write_all(&b_insn.to_le_bytes()).map_err(|e| {
                    SandlockError::MemoryProtect(format!(
                        "failed to write {} branch at {:#x}: {}",
                        name, entry_addr, e
                    ))
                })?;

                tramp_offset = (tramp_offset + stub.len() as u64 + 3) & !3;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_vdso_self() {
        let base = find_vdso_base(std::process::id() as i32).unwrap();
        assert!(base > 0);
    }

    #[test]
    fn test_parse_vdso_symbols_self() {
        let pid = std::process::id() as i32;
        let base = find_vdso_base(pid).unwrap();
        let bytes = read_proc_mem(pid, base, 0x2000).unwrap();
        let symbols = parse_vdso_symbols(&bytes);
        // Should find at least clock_gettime
        assert!(
            symbols.contains_key("clock_gettime")
                || symbols.contains_key("__vdso_clock_gettime")
                || symbols.contains_key("__kernel_clock_gettime"),
            "Expected clock_gettime in vDSO symbols, found: {:?}",
            symbols.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_simple_stub_size() {
        let stub = simple_stub(228);
        assert_eq!(stub.len(), 8);
        assert_eq!(stub[0], 0xB8); // mov eax
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_simple_stub_size() {
        let stub = simple_stub(228);
        // movz x8, #228 / svc #0 / ret — three 4-byte instructions.
        assert_eq!(stub.len(), 12);
    }

    #[test]
    #[cfg(target_arch = "riscv64")]
    fn test_simple_stub_size() {
        let stub = simple_stub(228);
        // addi a7, x0, 228 / ecall / ret — three 4-byte instructions.
        assert_eq!(stub.len(), 12);
        // ecall and ret are fixed encodings.
        assert_eq!(&stub[4..8], &0x0000_0073u32.to_le_bytes());
        assert_eq!(&stub[8..12], &0x0000_8067u32.to_le_bytes());
    }

    #[test]
    #[cfg(target_arch = "riscv64")]
    fn test_offset_stub_riscv_layout() {
        let off: i64 = -86400; // one day back
        let cg = offset_stub_clock_gettime(off);
        // 16 instructions (64 bytes) + 8-byte embedded offset.
        assert_eq!(cg.len(), 72);
        assert_eq!(&cg[64..72], &off.to_le_bytes(), "offset stored at tail");
        assert_eq!(&cg[12..16], &0x0000_0073u32.to_le_bytes(), "ecall");
        assert_eq!(&cg[60..64], &0x0000_8067u32.to_le_bytes(), "ret");

        let gtod = offset_stub_gettimeofday(off);
        // 13 instructions (52 bytes) + 8-byte embedded offset.
        assert_eq!(gtod.len(), 60);
        assert_eq!(&gtod[52..60], &off.to_le_bytes(), "offset stored at tail");
        assert_eq!(&gtod[48..52], &0x0000_8067u32.to_le_bytes(), "ret");
    }

    /// Execute the generated `clock_gettime` offset stub as real machine code:
    /// map it executable, call it through the `clock_gettime(clockid, *timespec)`
    /// ABI, and confirm CLOCK_REALTIME comes back shifted by exactly the embedded
    /// offset while CLOCK_MONOTONIC is left untouched. Unlike the layout tests
    /// above, this proves the hand-assembled encoding (syscall, clockid branches,
    /// PC-relative offset load, tv_sec add) actually runs correctly on hardware.
    /// Needs no sandbox/Landlock, so it is runnable on any kernel.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
    fn offset_stub_clock_gettime_executes_and_shifts_realtime() {
        use std::ptr;

        const OFFSET: i64 = -86_400; // one day back
        const PAGE: usize = 4096;
        let stub = offset_stub_clock_gettime(OFFSET);
        assert!(stub.len() <= PAGE);

        // Map writable, copy the stub, then flip to read+exec (W^X friendly).
        let page = unsafe {
            libc::mmap(
                ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED, "mmap exec page");
        unsafe {
            ptr::copy_nonoverlapping(stub.as_ptr(), page as *mut u8, stub.len());
            assert_eq!(
                libc::mprotect(page, PAGE, libc::PROT_READ | libc::PROT_EXEC),
                0,
                "mprotect r-x"
            );
        }
        // On riscv64 instruction fetch is not coherent with the stores above
        // until a FENCE.I retires on this hart (x86_64 caches are coherent).
        #[cfg(target_arch = "riscv64")]
        unsafe {
            std::arch::asm!("fence.i");
        }

        let stub_fn: extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int =
            unsafe { std::mem::transmute(page) };

        // CLOCK_REALTIME (0): stub time must equal real time + OFFSET.
        let mut real = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let mut stubbed = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut real) }, 0);
        assert_eq!(stub_fn(libc::CLOCK_REALTIME, &mut stubbed), 0, "stub returns 0");
        let shift = real.tv_sec - stubbed.tv_sec; // real - (real + OFFSET) = -OFFSET
        assert!(
            (shift - (-OFFSET)).abs() <= 2,
            "CLOCK_REALTIME should be shifted by {OFFSET}s, observed real-stub={shift}s"
        );

        // CLOCK_MONOTONIC (1): not in {0,5}, so the stub must leave it unshifted.
        let mut mono_stub = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let mut mono_real = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        assert_eq!(stub_fn(libc::CLOCK_MONOTONIC, &mut mono_stub), 0);
        assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono_real) }, 0);
        assert!(
            (mono_real.tv_sec - mono_stub.tv_sec).abs() <= 2,
            "CLOCK_MONOTONIC must be unshifted, stub={} real={}",
            mono_stub.tv_sec,
            mono_real.tv_sec
        );

        unsafe {
            libc::munmap(page, PAGE);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_offset_stub_contains_offset() {
        let offset: i64 = -86400; // one day back
        let stub = offset_stub_clock_gettime(offset);
        // x86_64 encodes the offset as a single movabs imm64, so the 8 bytes
        // appear contiguously in the stub.
        let offset_bytes = offset.to_le_bytes();
        assert!(stub.windows(8).any(|w| w == offset_bytes));
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_offset_stub_contains_offset() {
        let offset: i64 = -86400;
        let stub = offset_stub_clock_gettime(offset);
        // arm64 splits a 64-bit immediate across movz/movk instructions, so the
        // bytes are not contiguous. Verify each 16-bit chunk is encoded as a
        // movz/movk imm16 field (bits 5..21 of the 32-bit instruction).
        let raw = offset as u64;
        for shift in 0..4 {
            let chunk = ((raw >> (shift * 16)) & 0xFFFF) as u32;
            if chunk == 0 {
                continue; // a zero imm16 collides with too many other instructions to assert on
            }
            let found = stub.chunks_exact(4).any(|insn| {
                let word = u32::from_le_bytes(insn.try_into().unwrap());
                ((word >> 5) & 0xFFFF) == chunk
            });
            assert!(found, "chunk {:#06x} for shift {} not encoded in stub", chunk, shift);
        }
    }
}
