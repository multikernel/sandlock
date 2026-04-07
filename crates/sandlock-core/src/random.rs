// Deterministic random handler — intercepts getrandom() syscall and reads
// from /dev/urandom or /dev/random, returning seeded PRNG bytes instead of
// kernel-provided random bytes.

use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::RawFd;
use std::os::unix::io::{AsRawFd, FromRawFd};

use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;
use crate::sys::syscall;

/// Maximum bytes to fill in a single getrandom() interception.
/// 1 MiB covers all practical use cases (OpenSSL init, key generation, etc.).
const MAX_GETRANDOM_BYTES: usize = 1 << 20; // 1 MiB

/// Handle getrandom(buf, buflen, flags) — write seeded random bytes to child.
pub(crate) fn handle_getrandom(
    notif: &SeccompNotif,
    rng: &mut ChaCha8Rng,
    notif_fd: RawFd,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    let buf_len = notif.data.args[1] as usize;

    let len = buf_len.min(MAX_GETRANDOM_BYTES);
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);

    // Write deterministic bytes to child's buffer
    match write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, &buf) {
        Ok(()) => NotifAction::ReturnValue(len as i64),
        Err(_) => NotifAction::Continue, // fallback to real getrandom
    }
}

/// Pre-fill size for memfd injected in place of /dev/urandom or /dev/random.
/// 1 MiB is generous — most programs read ≤256 bytes for seeding.
const RANDOM_MEMFD_SIZE: usize = 1 << 20; // 1 MiB

/// Handle openat targeting /dev/urandom or /dev/random.
///
/// When `random_seed` is active, we intercept opens of these device files and
/// replace them with a memfd filled with deterministic PRNG bytes. The child
/// sees a normal readable fd and gets seeded data instead of real entropy.
pub(crate) fn handle_random_open(
    notif: &SeccompNotif,
    rng: &mut ChaCha8Rng,
    notif_fd: RawFd,
) -> Option<NotifAction> {
    // openat(dirfd, pathname, flags, mode): args[1] = pathname pointer
    let path_ptr = notif.data.args[1];
    if path_ptr == 0 {
        return None;
    }

    // Read the path from child memory.
    let bytes = read_child_mem(notif_fd, notif.id, notif.pid, path_ptr, 256).ok()?;
    let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let path = std::str::from_utf8(&bytes[..nul_pos]).ok()?;

    if path != "/dev/urandom" && path != "/dev/random" {
        return None;
    }

    // Create a memfd filled with deterministic PRNG bytes.
    let memfd = match syscall::memfd_create("sandlock-random", 0) {
        Ok(fd) => fd,
        Err(_) => return Some(NotifAction::Continue),
    };

    let raw = memfd.as_raw_fd();
    {
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        let mut buf = vec![0u8; RANDOM_MEMFD_SIZE];
        rng.fill_bytes(&mut buf);
        if file.write_all(&buf).is_err() || file.seek(SeekFrom::Start(0)).is_err() {
            std::mem::forget(file);
            return Some(NotifAction::Continue);
        }
        std::mem::forget(file);
    }

    // Move the OwnedFd into InjectFdSend — send_response will close it after the ioctl.
    Some(NotifAction::InjectFdSend { srcfd: memfd, newfd_flags: libc::O_CLOEXEC as u32 })
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_rng_is_deterministic() {
        let mut rng1 = ChaCha8Rng::seed_from_u64(42);
        let mut rng2 = ChaCha8Rng::seed_from_u64(42);

        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng1.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }
}
