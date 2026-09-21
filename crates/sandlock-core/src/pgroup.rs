//! Process groups that belong to the sandbox.
//!
//! Kill, pause and resume reach the sandbox one process group at a time, so
//! a process that leaves the child's group through setsid() or setpgid()
//! would be out of reach. Both syscalls are notified: a group the sandbox
//! creates is recorded here before the kernel creates it, and a move into a
//! group that is not recorded is refused, because signalling that group
//! would hit processes outside the sandbox (the supervisor's own group is
//! in the same session and the kernel would allow the move).

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Mutex;

use crate::seccomp::notif::{id_valid, NotifAction};
use crate::seccomp::state::{read_ppid, read_tgid_of_tid};
use crate::sys::structs::SeccompNotif;
use crate::sys::syscall::{pidfd_open, pidfd_signal_group};

/// Groups keyed by pgid, each held by a pidfd of its leader. The pidfd
/// names the group even after the leader is reaped, and never names an
/// unrelated group that later reuses the number.
pub struct ProcessGroups {
    leaders: Mutex<HashMap<i32, OwnedFd>>,
}

impl ProcessGroups {
    pub fn new() -> Self {
        Self {
            leaders: Mutex::new(HashMap::new()),
        }
    }

    // A live group pins its number to its leader's pid, so an entry this
    // replaces is either the same group or one that no longer exists.
    pub fn track(&self, pgid: i32, leader: OwnedFd) {
        if let Ok(mut leaders) = self.leaders.lock() {
            leaders.insert(pgid, leader);
        }
    }

    /// Whether `pgid` names a group of this sandbox that still has members.
    pub fn owns(&self, pgid: i32) -> bool {
        self.leaders
            .lock()
            .map(|leaders| {
                leaders
                    .get(&pgid)
                    .is_some_and(|leader| pidfd_signal_group(leader, 0).is_ok())
            })
            .unwrap_or(false)
    }

    /// Signal every group, returning how many had members. Holding the lock
    /// for the whole sweep keeps a group recorded meanwhile from being
    /// skipped: its creator is still in a group this sweep reaches.
    pub fn signal(&self, sig: i32) -> io::Result<usize> {
        let mut leaders = self
            .leaders
            .lock()
            .map_err(|_| io::Error::other("process group table poisoned"))?;
        let mut reached = 0;
        let mut failure = None;
        leaders.retain(|_, leader| match pidfd_signal_group(leader, sig) {
            Ok(()) => {
                reached += 1;
                true
            }
            // An empty group comes back only through its leader, so the
            // entry of a live leader may describe a group about to exist.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => !has_exited(leader.as_raw_fd()),
            Err(e) => {
                failure.get_or_insert(e);
                true
            }
        });
        match failure {
            Some(e) => Err(e),
            None => Ok(reached),
        }
    }
}

impl Default for ProcessGroups {
    fn default() -> Self {
        Self::new()
    }
}

fn has_exited(pidfd: RawFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut pfd, 1, 0) > 0 }
}

/// setsid() makes the calling process the leader of a new group.
pub(crate) fn handle_setsid(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    groups: &ProcessGroups,
) -> NotifAction {
    let caller = caller_tgid(notif);
    track_new_group(notif, notif_fd, groups, caller, caller)
}

/// setpgid(pid, pgid): `pid` 0 is the caller, `pgid` 0 is the target's pid.
pub(crate) fn handle_setpgid(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    groups: &ProcessGroups,
) -> NotifAction {
    let caller = caller_tgid(notif);
    let pid = notif.data.args[0] as i32;
    let pgid = notif.data.args[1] as i32;
    if pid < 0 || pgid < 0 {
        return NotifAction::Continue;
    }
    let target = if pid == 0 { caller } else { pid };
    let pgid = if pgid == 0 { target } else { pgid };

    if pgid != target {
        return if groups.owns(pgid) {
            NotifAction::Continue
        } else {
            NotifAction::Errno(libc::EPERM)
        };
    }
    track_new_group(notif, notif_fd, groups, caller, target)
}

fn caller_tgid(notif: &SeccompNotif) -> i32 {
    let tid = notif.pid as i32;
    read_tgid_of_tid(tid).unwrap_or(tid)
}

fn track_new_group(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    groups: &ProcessGroups,
    caller: i32,
    leader: i32,
) -> NotifAction {
    let Ok(pidfd) = pidfd_open(leader as u32, 0) else {
        return NotifAction::Continue;
    };
    // The kernel moves only the caller or one of its children. Anything
    // else fails there with ESRCH, and recording it would aim later signals
    // at a process outside the sandbox. The caller is parked in this
    // syscall, and a leader still alive after the read kept its number
    // throughout, so neither pid was recycled under the check.
    if leader != caller && (read_ppid(leader) != Some(caller) || has_exited(pidfd.as_raw_fd())) {
        return NotifAction::Continue;
    }
    if id_valid(notif_fd, notif.id).is_err() {
        return NotifAction::Continue;
    }
    groups.track(leader, pidfd);
    NotifAction::Continue
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fork a child that leads its own group and sleeps, plus a member of
    /// that group when `with_member` is set. Returns (leader, member).
    fn spawn_group(with_member: bool) -> (i32, Option<i32>) {
        let mut pipe = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let leader = unsafe { libc::fork() };
        assert!(leader >= 0);
        if leader == 0 {
            unsafe {
                libc::setpgid(0, 0);
                let member = if with_member { libc::fork() } else { 0 };
                if with_member && member == 0 {
                    libc::pause();
                    libc::_exit(0);
                }
                libc::write(pipe[1], (&member as *const i32).cast(), 4);
                libc::pause();
                libc::_exit(0);
            }
        }
        let mut member = 0i32;
        let n = unsafe { libc::read(pipe[0], (&mut member as *mut i32).cast(), 4) };
        assert_eq!(n, 4);
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        (leader, with_member.then_some(member))
    }

    fn reap(pid: i32) {
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }

    fn wait_gone(pid: i32) {
        for _ in 0..200 {
            if unsafe { libc::kill(pid, 0) } != 0 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("pid {pid} still alive");
    }

    #[test]
    fn signal_reaches_a_group_whose_leader_was_reaped() {
        let (leader, member) = spawn_group(true);
        let member = member.unwrap();
        let groups = ProcessGroups::new();
        groups.track(leader, pidfd_open(leader as u32, 0).unwrap());

        unsafe { libc::kill(leader, libc::SIGKILL) };
        reap(leader);
        assert!(groups.owns(leader));

        assert_eq!(groups.signal(libc::SIGKILL).unwrap(), 1);
        wait_gone(member);
    }

    #[test]
    fn signal_forgets_a_group_that_emptied() {
        let (leader, _) = spawn_group(false);
        let groups = ProcessGroups::new();
        groups.track(leader, pidfd_open(leader as u32, 0).unwrap());

        assert_eq!(groups.signal(libc::SIGKILL).unwrap(), 1);
        reap(leader);
        assert!(!groups.owns(leader));
        assert_eq!(groups.signal(libc::SIGKILL).unwrap(), 0);
        assert!(groups.leaders.lock().unwrap().is_empty());
    }

    #[test]
    fn signal_keeps_a_group_its_live_leader_has_not_created_yet() {
        let leader = unsafe { libc::fork() };
        assert!(leader >= 0);
        if leader == 0 {
            unsafe {
                libc::pause();
                libc::_exit(0);
            }
        }
        let groups = ProcessGroups::new();
        groups.track(leader, pidfd_open(leader as u32, 0).unwrap());

        assert_eq!(groups.signal(0).unwrap(), 0);
        assert_eq!(groups.leaders.lock().unwrap().len(), 1);

        unsafe { libc::kill(leader, libc::SIGKILL) };
        reap(leader);
    }

    #[test]
    fn owns_rejects_an_unrecorded_group() {
        let groups = ProcessGroups::new();
        assert!(!groups.owns(unsafe { libc::getpgrp() }));
    }
}
