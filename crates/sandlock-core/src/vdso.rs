use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};

use crate::error::SandlockError;

/// Find the base address of the vDSO mapping for a given process.
pub(crate) fn find_vdso_base(pid: i32) -> io::Result<u64> {
    let path = format!("/proc/{}/maps", pid);
    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.ends_with("[vdso]") {
            // Line format: "7ffd1234000-7ffd1235000 r-xp ... [vdso]"
            if let Some(dash_pos) = line.find('-') {
                let start_hex = &line[..dash_pos];
                let addr = u64::from_str_radix(start_hex, 16).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad vDSO address: {}", e))
                })?;
                return Ok(addr);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "vDSO mapping not found",
    ))
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

/// Generate a simple stub that forces a real syscall (replacing the vDSO fast path).
/// Layout: mov eax, imm32 / syscall / ret — 8 bytes total.
fn simple_stub(syscall_nr: u32) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.push(0xB8); // mov eax, imm32
    stub.extend_from_slice(&syscall_nr.to_le_bytes()); // syscall number
    stub.extend_from_slice(&[0x0F, 0x05]); // syscall
    stub.push(0xC3); // ret
    stub // 8 bytes total
}

/// Generate an offset stub for clock_gettime that forces a real syscall,
/// then adds a time offset to the result for CLOCK_REALTIME and CLOCK_REALTIME_COARSE.
///
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

/// Generate an offset stub for gettimeofday that forces a real syscall,
/// then adds a time offset to tv_sec.
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

/// Patch the vDSO of a target process to force real syscalls (interceptable by seccomp).
/// If `time_offset_secs` is provided, clock_gettime and gettimeofday stubs will add
/// the offset to the returned time.
pub(crate) fn patch(
    pid: i32,
    time_offset_secs: Option<i64>,
    _patch_for_random: bool,
) -> Result<(), SandlockError> {
    let base = find_vdso_base(pid).map_err(|e| {
        SandlockError::MemoryProtect(format!("failed to find vDSO base: {}", e))
    })?;

    let vdso_bytes = read_proc_mem(pid, base, 0x2000).map_err(|e| {
        SandlockError::MemoryProtect(format!("failed to read vDSO memory: {}", e))
    })?;

    let symbols = parse_vdso_symbols(&vdso_bytes);

    let mut mem = OpenOptions::new()
        .write(true)
        .open(format!("/proc/{}/mem", pid))
        .map_err(|e| {
            SandlockError::MemoryProtect(format!("failed to open /proc/{}/mem: {}", pid, e))
        })?;

    let targets = [
        ("clock_gettime", "__vdso_clock_gettime", 228u32),
        ("gettimeofday", "__vdso_gettimeofday", 96u32),
        ("time", "__vdso_time", 201u32),
    ];

    for (name, alt_name, syscall_nr) in &targets {
        if let Some(&offset) = symbols.get(*name).or_else(|| symbols.get(*alt_name)) {
            let addr = base + offset;
            let stub = match (time_offset_secs, *name) {
                (Some(off), "clock_gettime") => offset_stub_clock_gettime(off),
                (Some(off), "gettimeofday") => offset_stub_gettimeofday(off),
                _ => simple_stub(*syscall_nr),
            };
            mem.seek(SeekFrom::Start(addr)).map_err(|e| {
                SandlockError::MemoryProtect(format!(
                    "failed to seek to {} at {:#x}: {}",
                    name, addr, e
                ))
            })?;
            mem.write_all(&stub).map_err(|e| {
                SandlockError::MemoryProtect(format!(
                    "failed to write {} stub at {:#x}: {}",
                    name, addr, e
                ))
            })?;
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
    fn test_simple_stub_size() {
        let stub = simple_stub(228);
        assert_eq!(stub.len(), 8);
        assert_eq!(stub[0], 0xB8); // mov eax
    }

    #[test]
    fn test_offset_stub_contains_offset() {
        let offset: i64 = -86400; // one day back
        let stub = offset_stub_clock_gettime(offset);
        // Should contain the offset bytes somewhere
        let offset_bytes = offset.to_le_bytes();
        assert!(stub.windows(8).any(|w| w == offset_bytes));
    }
}
