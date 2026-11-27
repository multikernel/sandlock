// Time offset handler — calculates virtual time offset and handles absolute
// timer syscalls for time virtualization support.

use std::time::SystemTime;

use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;
use std::os::unix::io::RawFd;

const TIMER_ABSTIME: u64 = 1;

/// The clocks the vDSO stubs shift. An absolute deadline the child computed
/// from one of them carries the offset; every other clock reads real time.
fn is_shifted_clock(clockid: i64) -> bool {
    clockid == libc::CLOCK_REALTIME as i64 || clockid == libc::CLOCK_REALTIME_COARSE as i64
}

/// Calculate the time offset in seconds.
/// offset = desired_start_time - current_real_time
/// So that: virtual_time = real_time + offset
pub(crate) fn calculate_time_offset(time_start: SystemTime) -> i64 {
    epoch_secs(time_start) - epoch_secs(SystemTime::now())
}

/// Whole seconds since the epoch, floored, so an instant before 1970 keeps
/// its sign instead of collapsing onto the epoch.
fn epoch_secs(t: SystemTime) -> i64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => {
            let d = e.duration();
            -(d.as_secs() as i64) - i64::from(d.subsec_nanos() > 0)
        }
    }
}

/// Handle clock_nanosleep/timerfd_settime/timer_settime with TIMER_ABSTIME.
///
/// An absolute deadline on CLOCK_REALTIME was computed from the vDSO-shifted
/// wall clock (offset added), so the offset is subtracted here and the kernel
/// receives the real deadline. The monotonic and CPU-time clocks are never
/// shifted, so their deadlines pass through untouched.
///
/// Continue safety (issue #27): every `Continue` in this function is safe.
/// This handler does virtual-time correctness, not access control — it never
/// denies a syscall based on user memory, so the seccomp_unotify TOCTOU
/// re-read does not apply. A racing thread could rewrite the timespec
/// between our adjustment and the kernel's read, but the only effect is
/// that virtual-time bookkeeping is bypassed for that one call. No
/// security boundary depends on the value we read or wrote.
pub(crate) fn handle_timer(notif: &SeccompNotif, time_offset: i64, notif_fd: RawFd) -> NotifAction {
    if time_offset == 0 {
        return NotifAction::Continue;
    }

    let nr = notif.data.nr as i64;
    let flags = notif.data.args[1];

    if flags & TIMER_ABSTIME == 0 {
        return NotifAction::Continue;
    }

    if nr == libc::SYS_clock_nanosleep as i64 {
        if !is_shifted_clock(notif.data.args[0] as i32 as i64) {
            return NotifAction::Continue;
        }
        // timespec is directly at args[2]
        let ts_addr = notif.data.args[2];
        if ts_addr == 0 {
            return NotifAction::Continue;
        }
        adjust_tv_sec(notif_fd, notif.id, notif.pid, ts_addr, time_offset);
    } else {
        // timerfd_settime or timer_settime: the clock was fixed when the timer
        // was created, so look it up; it_value is at offset 16 in itimerspec.
        let clockid = if nr == libc::SYS_timerfd_settime {
            timerfd_clock(notif.pid, notif.data.args[0] as i32)
        } else {
            posix_timer_clock(notif.pid, notif.data.args[0] as i32)
        };
        if !clockid.is_some_and(is_shifted_clock) {
            return NotifAction::Continue;
        }
        let itimerspec_addr = notif.data.args[2];
        if itimerspec_addr == 0 {
            return NotifAction::Continue;
        }
        adjust_tv_sec(
            notif_fd,
            notif.id,
            notif.pid,
            itimerspec_addr + 16,
            time_offset,
        );
    }

    NotifAction::Continue
}

/// The clock of timerfd `fd`, from the `clockid:` line of its fdinfo.
fn timerfd_clock(pid: u32, fd: i32) -> Option<i64> {
    let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).ok()?;
    info.lines()
        .find_map(|line| line.strip_prefix("clockid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// The clock of POSIX timer `id`, from the `ClockID:` line that follows its
/// `ID:` line in /proc/<pid>/timers.
fn posix_timer_clock(pid: u32, id: i32) -> Option<i64> {
    let timers = std::fs::read_to_string(format!("/proc/{pid}/timers")).ok()?;
    parse_timer_clock(&timers, id)
}

fn parse_timer_clock(timers: &str, id: i32) -> Option<i64> {
    let mut lines = timers.lines();
    lines.find(|line| line.strip_prefix("ID:").map(str::trim) == Some(&id.to_string()))?;
    lines
        .take_while(|line| !line.starts_with("ID:"))
        .find_map(|line| line.strip_prefix("ClockID:"))
        .and_then(|v| v.trim().parse().ok())
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
        assert!(
            offset < 0,
            "past time should give negative offset, got {}",
            offset
        );
    }

    #[test]
    fn test_calculate_time_offset_future() {
        // A time in the future should give a positive offset.
        let future = SystemTime::now() + Duration::from_secs(3600);
        let offset = calculate_time_offset(future);
        assert!(
            offset > 0,
            "future time should give positive offset, got {}",
            offset
        );
    }

    #[test]
    fn test_calculate_time_offset_now() {
        // A time close to now should give an offset near zero.
        let now = SystemTime::now();
        let offset = calculate_time_offset(now);
        assert!(
            offset.abs() <= 2,
            "offset for 'now' should be near zero, got {}",
            offset
        );
    }

    #[test]
    fn test_calculate_time_offset_before_epoch() {
        let moon = SystemTime::UNIX_EPOCH - Duration::from_secs(14_182_980);
        let expected = -14_182_980 - epoch_secs(SystemTime::now());
        assert!((calculate_time_offset(moon) - expected).abs() <= 2);
    }

    #[test]
    fn test_epoch_secs_floors_before_epoch() {
        let t = SystemTime::UNIX_EPOCH - Duration::from_millis(1500);
        assert_eq!(epoch_secs(t), -2);
    }

    #[test]
    fn test_parse_timer_clock() {
        let timers = "ID: 0\nsignal: 14/0000000000000000\nnotify: signal/pid.7\nClockID: 1\n\
                      ID: 1\nsignal: 14/0000000000000000\nnotify: signal/pid.7\nClockID: -6\n\
                      ID: 10\nsignal: 14/0000000000000000\nnotify: signal/pid.7\nClockID: 0\n";
        assert_eq!(parse_timer_clock(timers, 0), Some(1));
        assert_eq!(parse_timer_clock(timers, 1), Some(-6));
        assert_eq!(parse_timer_clock(timers, 10), Some(0));
        assert_eq!(parse_timer_clock(timers, 2), None);
    }

    #[test]
    fn test_only_wall_clocks_are_shifted() {
        assert!(is_shifted_clock(libc::CLOCK_REALTIME as i64));
        assert!(is_shifted_clock(libc::CLOCK_REALTIME_COARSE as i64));
        for clock in [
            libc::CLOCK_MONOTONIC,
            libc::CLOCK_MONOTONIC_RAW,
            libc::CLOCK_BOOTTIME,
            libc::CLOCK_PROCESS_CPUTIME_ID,
            libc::CLOCK_TAI,
        ] {
            assert!(!is_shifted_clock(clock as i64), "clock {clock}");
        }
    }

    #[test]
    fn test_adjust_arithmetic() {
        // Realtime clock: vDSO adds offset, so absolute deadline is shifted.
        // Un-shifting: adjusted = original - offset
        let offset: i64 = -3600; // 1 hour in past
        let shifted_deadline: i64 = 1700000000;
        let adjusted = shifted_deadline - offset;
        assert_eq!(adjusted, 1700003600);
    }
}
