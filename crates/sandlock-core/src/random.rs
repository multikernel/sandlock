// Deterministic random handler — intercepts getrandom() syscall and returns
// seeded PRNG bytes instead of kernel-provided random bytes.

use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use std::os::fd::RawFd;

use crate::seccomp::notif::{write_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;

/// Handle getrandom(buf, buflen, flags) — write seeded random bytes to child.
pub(crate) fn handle_getrandom(
    notif: &SeccompNotif,
    rng: &mut ChaCha8Rng,
    notif_fd: RawFd,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    let buf_len = notif.data.args[1] as usize;

    // Cap at 256 bytes per call to avoid huge allocations
    let len = buf_len.min(256);
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);

    // Write deterministic bytes to child's buffer
    match write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, &buf) {
        Ok(()) => NotifAction::ReturnValue(len as i64),
        Err(_) => NotifAction::Continue, // fallback to real getrandom
    }
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
