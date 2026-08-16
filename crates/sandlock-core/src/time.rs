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

/// Whole seconds between `t` and the UNIX epoch, negative before it.
///
/// `SystemTime::duration_since` reports an earlier instant as `Err`, so the
/// usual `.unwrap_or_default()` collapses every pre-1970 instant to the epoch.
/// The grammar the profile, the CLI and the C ABI all share accepts such an
/// instant (`"1969-07-20T20:17:00Z"` parses), so swallowing the sign here made
/// the sandbox run a clock the caller never asked for, with no error anywhere.
///
/// Rounding is floor in both directions, matching `CanonicalTimestamp`: half a
/// second before the epoch is second -1, not second 0.
fn epoch_seconds(t: SystemTime) -> i64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => {
            let d = e.duration();
            let whole = d.as_secs() as i64;
            if d.subsec_nanos() > 0 { -whole - 1 } else { -whole }
        }
    }
}

/// Calculate the time offset in seconds.
/// offset = desired_start_time - current_real_time
/// So that: virtual_time = real_time + offset
pub(crate) fn calculate_time_offset(time_start: SystemTime) -> i64 {
    epoch_seconds(time_start) - epoch_seconds(SystemTime::now())
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

    #[test]
    fn a_pre_epoch_instant_keeps_its_sign() {
        // `--time-start 1969-07-20T20:17:00Z` and its profile and C ABI
        // spellings all parse. `duration_since(UNIX_EPOCH).unwrap_or_default()`
        // used to report this instant as second 0, so the guest ran at
        // 1970-01-01T00:00:00Z instead, silently and 14182980 seconds off.
        let moon_landing = SystemTime::UNIX_EPOCH - Duration::from_secs(14_182_980);
        assert_eq!(epoch_seconds(moon_landing), -14_182_980);
    }

    #[test]
    fn the_epoch_itself_is_second_zero() {
        // Boundary between the two arms: `duration_since` returns `Ok(0)`
        // here, so the sign flip must not fire and produce `-0` by the
        // sub-second path.
        assert_eq!(epoch_seconds(SystemTime::UNIX_EPOCH), 0);
    }

    #[test]
    fn a_sub_second_pre_epoch_instant_floors_like_the_canonical_form() {
        // `CanonicalTimestamp` documents half a second before the epoch as
        // `{seconds: -1, nanoseconds: 500000000}`. This agrees, so the same
        // stamp means the same second whichever surface read it.
        assert_eq!(
            epoch_seconds(SystemTime::UNIX_EPOCH - Duration::from_millis(500)),
            -1,
        );
        assert_eq!(
            epoch_seconds(SystemTime::UNIX_EPOCH + Duration::from_millis(500)),
            0,
        );
    }

    #[test]
    fn a_pre_epoch_start_reaches_the_guest_as_itself() {
        // What the guest's clock reads: real_time + offset. Within a second,
        // because `calculate_time_offset` samples `now` itself.
        let moon_landing = SystemTime::UNIX_EPOCH - Duration::from_secs(14_182_980);
        let offset = calculate_time_offset(moon_landing);
        let now = epoch_seconds(SystemTime::now());
        let landed = now + offset;
        assert!(
            (landed - -14_182_980).abs() <= 1,
            "a pre-epoch start must reach the guest as itself, not as the epoch; got {landed}",
        );
    }
}
