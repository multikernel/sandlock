//! Exec relay: argv safety for policy-checked execs without stopping any task.
//!
//! The supervisor reads argv from the child, judges it, and continues the
//! execve; the kernel then copies argv from the same memory, which sibling
//! threads and CLONE_VM peers can rewrite in between. Instead of freezing
//! those tasks, an approved execve is redirected to `relay.c`: the kernel runs
//! it from a sealed memfd, and it execs the target with the argv the policy
//! saw, read from a trailer on its own image. See `relay.c` for the child side.

use std::io;

/// The relay program, built by build.rs for the target and embedded so a
/// deployed library never depends on a file beside it.
pub(crate) const RELAY_ELF: &[u8] = include_bytes!(env!("EXEC_RELAY_PATH"));

/// Marks the config block in `RELAY_ELF`; the same bytes as relay.c's magic.
const CONFIG_MAGIC: u64 = 0x5359_414c_4552_4c53;
const CONFIG_LEN: usize = 32;

const TRAILER_MAGIC: u32 = 0x5245_4c41;
const TRAILER_VERSION: u32 = 1;
const HEADER_LEN: usize = 40;
pub(crate) const ARGS_MAX: usize = 2 << 20;
pub(crate) const ENTRIES_MAX: usize = 65536;

/// How the relay reaches the target once it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArgsMode {
    /// `execveat(dirfd, base)` after checking the directory's identity, so
    /// swapping a path component after the policy looked has no effect.
    Pinned = 0,
    /// `execve(full_path)`: scripts, whose interpreter re-opens the path
    /// anyway, and COW/chroot modes, whose exec handlers pin the target
    /// themselves against the single-threaded relay.
    ByPath = 1,
}

/// Everything the relay needs, serialized as the trailer on its image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExecArgs {
    pub mode: ArgsMode,
    pub dir_dev: u64,
    pub dir_ino: u64,
    pub dir: Vec<u8>,
    pub base: Vec<u8>,
    pub full_path: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
    pub envp: Vec<Vec<u8>>,
}

impl ExecArgs {
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        if self.argv.len() > ENTRIES_MAX || self.envp.len() > ENTRIES_MAX {
            return Err(io::Error::from_raw_os_error(libc::E2BIG));
        }
        let mut out = Vec::with_capacity(HEADER_LEN + 256);
        for v in [TRAILER_MAGIC, TRAILER_VERSION, self.mode as u32,
                  self.argv.len() as u32, self.envp.len() as u32, 0] {
            out.extend_from_slice(&v.to_ne_bytes());
        }
        out.extend_from_slice(&self.dir_dev.to_ne_bytes());
        out.extend_from_slice(&self.dir_ino.to_ne_bytes());
        let strings = [&self.dir, &self.base, &self.full_path]
            .into_iter()
            .chain(self.argv.iter())
            .chain(self.envp.iter());
        for s in strings {
            if s.contains(&0) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            out.extend_from_slice(s);
            out.push(0);
        }
        if out.len() > ARGS_MAX {
            return Err(io::Error::from_raw_os_error(libc::E2BIG));
        }
        Ok(out)
    }

    /// Mirror of relay.c's reader, kept so the tests pin the wire format.
    #[cfg(test)]
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        let u32_at = |i: usize| u32::from_ne_bytes(bytes[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
        if u32_at(0) != TRAILER_MAGIC || u32_at(4) != TRAILER_VERSION {
            return None;
        }
        let mode = match u32_at(8) {
            0 => ArgsMode::Pinned,
            1 => ArgsMode::ByPath,
            _ => return None,
        };
        let (argc, envc) = (u32_at(12) as usize, u32_at(16) as usize);
        let mut pos = HEADER_LEN;
        let mut next = || {
            let end = bytes[pos..].iter().position(|&b| b == 0)? + pos;
            let s = bytes[pos..end].to_vec();
            pos = end + 1;
            Some(s)
        };
        let dir = next()?;
        let base = next()?;
        let full_path = next()?;
        let argv = (0..argc).map(|_| next()).collect::<Option<Vec<_>>>()?;
        let envp = (0..envc).map(|_| next()).collect::<Option<Vec<_>>>()?;
        Some(Self { mode, dir_dev: u64_at(24), dir_ino: u64_at(32), dir, base, full_path, argv, envp })
    }
}

/// The relay image for one exec: `RELAY_ELF` with the config block pointing
/// at the trailer appended after it, to be read back through `fd`.
pub(crate) fn build_image(args: &ExecArgs, fd: i32) -> io::Result<Vec<u8>> {
    let trailer = args.encode()?;
    let mut image = RELAY_ELF.to_vec();
    let at = image
        .windows(8)
        .position(|w| w == CONFIG_MAGIC.to_ne_bytes())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "exec-relay image has no config block"))?;
    let trailer_off = image.len() as u64;
    let trailer_len = trailer.len() as u64;
    let block = &mut image[at..at + CONFIG_LEN];
    block[8..12].copy_from_slice(&(fd as u32).to_ne_bytes());
    block[16..24].copy_from_slice(&trailer_off.to_ne_bytes());
    block[24..32].copy_from_slice(&trailer_len.to_ne_bytes());
    image.extend_from_slice(&trailer);
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(mode: ArgsMode) -> ExecArgs {
        ExecArgs {
            mode,
            dir_dev: 0x1234,
            dir_ino: 0x5678,
            dir: b"/usr/bin".to_vec(),
            base: b"echo".to_vec(),
            full_path: b"/usr/bin/echo".to_vec(),
            argv: vec![b"echo".to_vec(), b"hello world".to_vec(), Vec::new()],
            envp: vec![b"PATH=/usr/bin".to_vec()],
        }
    }

    #[test]
    fn trailer_roundtrips_both_modes() {
        for mode in [ArgsMode::Pinned, ArgsMode::ByPath] {
            let args = sample(mode);
            assert_eq!(ExecArgs::decode(&args.encode().unwrap()), Some(args));
        }
    }

    #[test]
    fn decode_rejects_bad_magic_and_truncation() {
        let mut bytes = sample(ArgsMode::Pinned).encode().unwrap();
        assert!(ExecArgs::decode(&bytes[..bytes.len() - 1]).is_none());
        bytes[0] ^= 1;
        assert!(ExecArgs::decode(&bytes).is_none());
    }

    #[test]
    fn encode_rejects_embedded_nul_and_too_many_entries() {
        let mut args = sample(ArgsMode::Pinned);
        args.argv.push(b"a\0b".to_vec());
        assert_eq!(args.encode().unwrap_err().raw_os_error(), Some(libc::EINVAL));
        let mut args = sample(ArgsMode::Pinned);
        args.envp = vec![Vec::new(); ENTRIES_MAX + 1];
        assert_eq!(args.encode().unwrap_err().raw_os_error(), Some(libc::E2BIG));
    }

    #[test]
    fn build_image_patches_the_config_block_and_appends_the_trailer() {
        let args = sample(ArgsMode::ByPath);
        let image = build_image(&args, 1023).unwrap();
        assert_eq!(&image[..4], b"\x7fELF");
        let at = image.windows(8).position(|w| w == CONFIG_MAGIC.to_ne_bytes()).unwrap();
        let block = &image[at..at + CONFIG_LEN];
        assert_eq!(u32::from_ne_bytes(block[8..12].try_into().unwrap()), 1023);
        let off = u64::from_ne_bytes(block[16..24].try_into().unwrap()) as usize;
        let len = u64::from_ne_bytes(block[24..32].try_into().unwrap()) as usize;
        assert_eq!(off, RELAY_ELF.len());
        assert_eq!(ExecArgs::decode(&image[off..off + len]), Some(args));
        assert_eq!(RELAY_ELF.windows(8).filter(|w| *w == CONFIG_MAGIC.to_ne_bytes()).count(), 1);
    }
}
