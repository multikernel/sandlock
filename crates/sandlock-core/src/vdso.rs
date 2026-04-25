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

#[cfg(target_arch = "aarch64")]
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
#[cfg(target_arch = "aarch64")]
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

    // arm64: place full stubs in slack space at the tail of the vDSO mapping and
    // patch each function entry with a single 4-byte B that jumps to its stub.
    // x86_64: stubs are short and inter-symbol gaps are wide; patch inline.
    #[cfg(target_arch = "aarch64")]
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

            #[cfg(target_arch = "aarch64")]
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

                let b_insn = arm64_b_insn(entry_addr, tramp_addr)?;
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
