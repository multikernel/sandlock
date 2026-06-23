//! Implementation of `sandlock learn`.
//!
//! Runs a workload under fully-permissive Landlock (read-everything) and
//! intercepts every file-open syscall via an audit hook registered directly
//! in the sandlock-core supervisor. Emits a sandlock profile TOML readable
//! by `sandlock run --profile-file`.
//!
//! Note: no path collapsing is applied — every individual file is listed.
//! See issue #72 for the planned collapsing design.

use std::collections::BTreeSet;
use std::net::IpAddr;
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

fn resolve_cmd(cmd: &str) -> PathBuf {
    let p = if cmd.contains('/') {
        PathBuf::from(cmd)
    } else {
        std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .map(|dir| PathBuf::from(dir).join(cmd))
            .find(|p| p.exists())
            .unwrap_or_else(|| PathBuf::from(cmd))
    };
    std::fs::canonicalize(&p).unwrap_or(p)
}

/// Read the ELF PT_INTERP segment of a binary and return the interpreter path.
/// Returns `None` for statically linked binaries or non-ELF files.
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
    // Any denial here would make the trace incomplete (workload crashes before
    // reaching other files it needs). See issue #72 open question #1.
    let reads: Arc<Mutex<BTreeSet<PathBuf>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let writes: Arc<Mutex<BTreeSet<PathBuf>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let connects: Arc<Mutex<BTreeSet<String>>> = Arc::new(Mutex::new(BTreeSet::new()));

    let (reads_c, writes_c, connects_c) = (Arc::clone(&reads), Arc::clone(&writes), Arc::clone(&connects));
    let policy = Sandbox::builder()
        .fs_read("/")
        .fs_write("/tmp")
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

    // The executed binary and its dynamic linker are loaded by the kernel during
    // execve — they never appear in the audit hook trace. Add them explicitly.
    let binary = resolve_cmd(&args.cmd[0]);
    if let Some(interp) = elf_interpreter(&binary) {
        reads.lock().unwrap().insert(interp);
    }
    reads.lock().unwrap().insert(binary);

    // Build the profile using the proper struct — same schema `sandlock run -p` reads.
    let mut profile_out = ProfileInput::default();
    profile_out.filesystem = FilesystemSection {
        read: reads.lock().unwrap().iter().filter(|p| p.exists()).cloned().collect(),
        write: writes.lock().unwrap().iter().filter(|p| p.exists()).cloned().collect(),
        ..Default::default()
    };
    profile_out.network.allow = connects.lock().unwrap().iter().cloned().collect();

    let header = format!(
        "# generated by sandlock learn\n\
         # command: {cmd_str}\n\
         # note: raw observation — no path collapsing applied\n\
         #       every file is listed individually (see issue #72 for collapsing design)\n\n"
    );
    let body = profile_out.to_toml()
        .map_err(|e| anyhow!("failed to serialize profile: {e}"))?;
    let body = strip_empty_sections(&body);
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

/// Strip TOML sections that contain only default/empty values.
/// `toml::to_string` emits every field including defaults — this keeps
/// the profile minimal and readable.
fn strip_empty_sections(toml: &str) -> String {
    let mut out = String::new();
    let mut section: Vec<&str> = Vec::new();
    let mut in_section = false;

    for line in toml.lines() {
        if line.starts_with('[') {
            if in_section && section_has_content(&section) {
                for l in &section { out.push_str(l); out.push('\n'); }
            }
            section = vec![line];
            in_section = true;
        } else if in_section {
            section.push(line);
        } else {
            out.push_str(line); out.push('\n');
        }
    }
    if in_section && section_has_content(&section) {
        for l in &section { out.push_str(l); out.push('\n'); }
    }
    out
}

fn section_has_content(lines: &[&str]) -> bool {
    lines.iter().skip(1).any(|l| {
        let v = l.trim();
        !v.is_empty()
            && !v.ends_with("= []")
            && !v.ends_with("= {}")
            && !v.ends_with("= false")
            && v != "[]"
    })
}
