// Time offset handler — calculates virtual time offset and handles absolute
// timer syscalls for time virtualization support.

use std::time::SystemTime;

use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;
use std::os::unix::io::RawFd;

const TIMER_ABSTIME: u64 = 1;

// Monotonic clocks whose absolute deadlines need un-shifting
const CLOCK_MONOTONIC: u32 = 1;
const CLOCK_MONOTONIC_RAW: u32 = 4;
const CLOCK_MONOTONIC_COARSE: u32 = 6;
const CLOCK_BOOTTIME: u32 = 7;

/// Calculate the time offset in seconds.
/// offset = desired_start_time - current_real_time
/// So that: virtual_time = real_time + offset
pub(crate) fn calculate_time_offset(time_start: SystemTime) -> i64 {
    let now = SystemTime::now();
    let desired = time_start
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let actual = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    desired - actual
}

/// Handle clock_nanosleep/timerfd_settime/timer_settime with TIMER_ABSTIME.
///
/// For absolute monotonic timers, the child computed the deadline using a
/// vDSO-shifted clock (offset was added). We subtract the offset here so the
/// kernel receives the correct real deadline.
///
/// Continue safety (issue #27): every `Continue` in this function is safe.
/// This handler does virtual-time correctness, not access control — it never
/// denies a syscall based on user memory, so the seccomp_unotify TOCTOU
/// re-read does not apply. A racing thread could rewrite the timespec
/// between our adjustment and the kernel's read, but the only effect is
/// that virtual-time bookkeeping is bypassed for that one call. No
/// security boundary depends on the value we read or wrote.
pub(crate) fn handle_timer(
    notif: &SeccompNotif,
    time_offset: i64,
    notif_fd: RawFd,
) -> NotifAction {
    if time_offset == 0 {
        return NotifAction::Continue;
    }

    let nr = notif.data.nr as i64;
    let flags = notif.data.args[1];

    if flags & TIMER_ABSTIME == 0 {
        return NotifAction::Continue;
    }

    if nr == libc::SYS_clock_nanosleep as i64 {
        let clockid = (notif.data.args[0] & 0xFFFFFFFF) as u32;
        // Only un-shift monotonic clocks (realtime is handled differently)
        if clockid != CLOCK_MONOTONIC
            && clockid != CLOCK_MONOTONIC_RAW
            && clockid != CLOCK_MONOTONIC_COARSE
            && clockid != CLOCK_BOOTTIME
        {
            return NotifAction::Continue;
        }
        // timespec is directly at args[2]
        let ts_addr = notif.data.args[2];
        if ts_addr == 0 {
            return NotifAction::Continue;
        }
        adjust_tv_sec(notif_fd, notif.id, notif.pid, ts_addr, time_offset);
    } else {
        // timerfd_settime or timer_settime: it_value at offset 16 in itimerspec
        let itimerspec_addr = notif.data.args[2];
        if itimerspec_addr == 0 {
            return NotifAction::Continue;
        }
        adjust_tv_sec(notif_fd, notif.id, notif.pid, itimerspec_addr + 16, time_offset);
    }

    NotifAction::Continue
}

/// Read tv_sec from child memory at `addr`, subtract `offset`, write back.
fn adjust_tv_sec(notif_fd: RawFd, notif_id: u64, pid: u32, addr: u64, offset: i64) {
    let bytes = match read_child_mem(notif_fd, notif_id, pid, addr, 8) {
        Ok(b) if b.len() == 8 => b,
        _ => return,
    };
    let tv_sec = i64::from_ne_bytes(bytes[..8].try_into().unwrap());
    let adjusted = tv_sec - offset;
    let _ = write_child_mem(notif_fd, notif_id, pid, addr, &adjusted.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_calculate_time_offset_past() {
        // A time in the past should give a negative offset.
        let past = SystemTime::now() - Duration::from_secs(3600);
        let offset = calculate_time_offset(past);
        assert!(offset < 0, "past time should give negative offset, got {}", offset);
    }

    #[test]
    fn test_calculate_time_offset_future() {
        // A time in the future should give a positive offset.
        let future = SystemTime::now() + Duration::from_secs(3600);
        let offset = calculate_time_offset(future);
        assert!(offset > 0, "future time should give positive offset, got {}", offset);
    }

    #[test]
    fn test_calculate_time_offset_now() {
        // A time close to now should give an offset near zero.
        let now = SystemTime::now();
        let offset = calculate_time_offset(now);
        assert!(offset.abs() <= 2, "offset for 'now' should be near zero, got {}", offset);
    }

    #[test]
    fn test_adjust_arithmetic() {
        // Monotonic clock: vDSO adds offset, so absolute deadline is shifted.
        // Un-shifting: adjusted = original - offset
        let offset: i64 = -3600; // 1 hour in past
        let shifted_deadline: i64 = 1700000000;
        let adjusted = shifted_deadline - offset;
        assert_eq!(adjusted, 1700003600);
    }
}
