//! Implementation of `sandlock learn -o <output.toml>`.
//!
//! Runs a workload under observation and emits a sandlock profile TOML
//! usable by `sandlock run -p`.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use sandlock_core::profile::{FilesystemSection, ProfileInput};
use sandlock_core::Sandbox;

use crate::LearnArgs;

// openat flags (from fcntl.h)
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;

fn is_write_open(flags: u64) -> bool {
    flags & (O_WRONLY | O_RDWR | O_CREAT) != 0
}

/// Read the ELF PT_INTERP segment of a binary and return the interpreter path.
/// Returns `None` for statically linked binaries, non-ELF files, or ELF32 binaries.
fn elf_interpreter(binary: &std::path::Path) -> Option<PathBuf> {
    let data = std::fs::read(binary).ok()?;
    // ELF magic: 0x7f 'E' 'L' 'F'
    if data.get(..4) != Some(b"\x7fELF") {
        return None;
    }
    // ELF64 only: class byte at offset 4 must be 2.
    if data.get(4).copied() != Some(2) {
        return None;
    }
    // Endianness byte at offset 5: 1 = little, 2 = big.
    let le = data.get(5).copied()? == 1;
    let read_u16 = |off: usize| -> Option<u16> {
        let b = data.get(off..off + 2)?;
        Some(if le { u16::from_le_bytes(b.try_into().ok()?) } else { u16::from_be_bytes(b.try_into().ok()?) })
    };
    let read_u64 = |off: usize| -> Option<u64> {
        let b = data.get(off..off + 8)?;
        Some(if le { u64::from_le_bytes(b.try_into().ok()?) } else { u64::from_be_bytes(b.try_into().ok()?) })
    };
    // ELF64 header: phoff at 0x20, phentsize at 0x36, phnum at 0x38.
    let phoff = read_u64(0x20)? as usize;
    let phentsize = read_u16(0x36)? as usize;
    let phnum = read_u16(0x38)? as usize;
    // PT_INTERP = 3
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let p_type = data.get(ph..ph + 4)?;
        let p_type = if le { u32::from_le_bytes(p_type.try_into().ok()?) } else { u32::from_be_bytes(p_type.try_into().ok()?) };
        if p_type == 3 {
            // p_offset at ph+8, p_filesz at ph+32 in ELF64
            let offset = read_u64(ph + 8)? as usize;
            let filesz = read_u64(ph + 32)? as usize;
            let interp = data.get(offset..offset + filesz)?;
            // Strip trailing null byte
            let interp = interp.split(|&b| b == 0).next()?;
            return Some(PathBuf::from(std::str::from_utf8(interp).ok()?));
        }
    }
    None
}

pub async fn run(args: LearnArgs) -> Result<()> {
    if args.cmd.is_empty() {
        anyhow::bail!("no command given — use: sandlock learn [flags] -- <cmd> [args...]");
    }

    let cmd_str = args.cmd.join(" ");
    let cmd_refs: Vec<&str> = args.cmd.iter().map(String::as_str).collect();

    // Fully permissive Landlock so nothing is blocked during observation.
    // workdir (COW overlay) lets writes go anywhere without touching the real filesystem.
    let cow_dir = tempfile::Builder::new()
        .prefix("sandlock-learn-")
        .tempdir_in("/var/tmp")
        .map_err(|e| anyhow!("failed to create COW tempdir: {e}"))?;

    let reads: Arc<Mutex<BTreeSet<PathBuf>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let writes: Arc<Mutex<BTreeSet<PathBuf>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let connects: Arc<Mutex<BTreeSet<String>>> = Arc::new(Mutex::new(BTreeSet::new()));

    let (reads_c, writes_c, connects_c) = (Arc::clone(&reads), Arc::clone(&writes), Arc::clone(&connects));
    let policy = Sandbox::builder()
        .fs_read("/")
        .workdir(cow_dir.path())
        .on_file_access(move |path, flags| {
            if is_write_open(flags) {
                writes_c.lock().unwrap().insert(path.to_path_buf());
            } else {
                reads_c.lock().unwrap().insert(path.to_path_buf());
            }
        })
        .on_net_connect(move |ip, port| {
            connects_c.lock().unwrap().insert(format!("tcp://{ip}:{port}"));
        })
        .build()
        .map_err(|e| anyhow!("failed to build sandbox policy: {e}"))?;

    eprintln!("sandlock learn: observing {cmd_str} ...");

    let result = policy
        .with_name("sandlock-learn")
        .run(&cmd_refs)
        .await
        .map_err(|e| anyhow!("sandbox error: {e}"))?;

    eprintln!("sandlock learn: done (exit={:?})", result.code());

    // The dynamic linker is loaded entirely in kernel space
    // during execve, no userspace syscall fires. Find the binary in the captured
    // reads (by basename match) and parse its ELF PT_INTERP to add the linker.
    let cmd_basename = std::path::Path::new(&args.cmd[0]).file_name();
    let candidates: Vec<PathBuf> = reads.lock().unwrap().iter()
        .filter(|p| p.file_name() == cmd_basename)
        .cloned()
        .collect();
    for bin in candidates.iter().filter(|p| p.exists()) {
        if let Some(interp) = elf_interpreter(bin) {
            reads.lock().unwrap().insert(interp);
            break;
        }
    }

    // Build the profile.
    let mut profile_out = ProfileInput::default();
    let cow_path = cow_dir.path().to_path_buf();
    profile_out.filesystem = FilesystemSection {
        // Filter reads by existence to drop failed PATH-probe openats.
        read: reads.lock().unwrap().iter()
            .filter(|p| p.exists() && !p.starts_with(&cow_path))
            .cloned()
            .collect(),
        // For writes: if the file exists, record the specific path (existing file modified).
        // If it doesn't exist on the real FS (COW intercepted a create), record the parent
        // directory instead, Landlock requires the path to exist, and the program needs
        // write access to the directory to create new files inside it.
        write: writes.lock().unwrap().iter()
            .filter(|p| !p.starts_with(&cow_path))
            .filter_map(|p| {
                if p.exists() {
                    Some(p.clone())
                } else {
                    p.parent().filter(|d| d.exists()).map(|d| d.to_path_buf())
                }
            })
            .collect(),
        ..Default::default()
    };
    profile_out.network.allow = connects.lock().unwrap().iter().cloned().collect();

    let header = format!(
        "# generated by sandlock learn\n\
         # command: {}\n\n",
        cmd_str.replace('\n', " ")
    );
    let body = profile_out.to_toml()
        .map_err(|e| anyhow!("failed to serialize profile: {e}"))?;
    let toml_out = format!("{header}{body}");

    match args.output {
        Some(ref path) => {
            std::fs::write(path, &toml_out)
                .map_err(|e| anyhow!("failed to write {}: {e}", path.display()))?;
            eprintln!("sandlock learn: profile written to {}", path.display());
        }
        None => print!("{toml_out}"),
    }

    Ok(())
}

