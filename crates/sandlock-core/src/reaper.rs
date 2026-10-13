use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(crate) struct Reaper {
    pub pid: i32,
    pub main_pidfd: OwnedFd,
    status: OwnedFd,
    command: Option<OwnedFd>,
}

impl Reaper {
    pub fn shutdown(&mut self) {
        self.command.take();
    }

    pub async fn main_status(&self) -> io::Result<i32> {
        let fd = tokio::io::unix::AsyncFd::new(self.status.try_clone()?)?;
        loop {
            let mut ready = fd.readable().await?;
            let result = ready.try_io(|fd| {
                let mut status = 0i32;
                let n = unsafe {
                    libc::read(
                        fd.get_ref().as_raw_fd(),
                        (&mut status as *mut i32).cast(),
                        4,
                    )
                };
                match n {
                    4 => Ok(status),
                    -1 => Err(io::Error::last_os_error()),
                    _ => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "session reaper lost main status",
                    )),
                }
            });
            match result {
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return result,
                Err(_) => {}
            }
        }
    }
}

/// A private subreaper keeps orphans below the supervisor for Yama checks,
/// without changing the embedding process's child-adoption policy.
pub(crate) fn fork() -> io::Result<(i32, Option<Reaper>)> {
    let mut pipe = [0; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let pinned_r = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let pinned_w = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let owner = unsafe { libc::getpid() };
    let reaper = crate::control::fork_without_control_fds();
    if reaper < 0 {
        return Err(io::Error::last_os_error());
    }
    if reaper == 0 {
        unsafe {
            let mut blocked = std::mem::zeroed();
            let mut previous_mask = std::mem::zeroed();
            libc::sigfillset(&mut blocked);
            libc::sigprocmask(libc::SIG_SETMASK, &blocked, &mut previous_mask);
            let mut previous_chld = std::mem::zeroed();
            let mut default_chld: libc::sigaction = std::mem::zeroed();
            default_chld.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGCHLD, &default_chld, &mut previous_chld);
            if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() != owner
            {
                libc::_exit(127);
            }
            let parent = libc::getpid();
            let child = libc::fork();
            if child < 0 {
                libc::_exit(127);
            }
            if child == 0 {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                {
                    libc::_exit(127);
                }
                libc::sigaction(libc::SIGCHLD, &previous_chld, std::ptr::null_mut());
                libc::sigprocmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut());
                drop(read);
                drop(write);
                drop(pinned_r);
                drop(pinned_w);
                return Ok((0, None));
            }
            let fd = write.as_raw_fd();
            let gate = pinned_r.as_raw_fd();
            let lo = fd.min(gate) as u32;
            let hi = fd.max(gate) as u32;
            if lo > 0 {
                libc::syscall(libc::SYS_close_range, 0u32, lo - 1, 0u32);
            }
            if hi > lo + 1 {
                libc::syscall(libc::SYS_close_range, lo + 1, hi - 1, 0u32);
            }
            libc::syscall(libc::SYS_close_range, hi + 1, u32::MAX, 0u32);
            if !send(fd, child) {
                libc::_exit(127);
            }
            // Keep the main PID pinned as a child until the supervisor has a pidfd.
            let mut ack = 0i32;
            let acknowledged = loop {
                let n = libc::read(gate, (&mut ack as *mut i32).cast(), 4);
                if n >= 0 {
                    break n == 4;
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    libc::_exit(127);
                }
            };
            supervise(child, fd, gate, !acknowledged);
        }
    }
    drop(write);
    drop(pinned_r);
    let child = loop {
        match crate::context::read_u32_fd(read.as_raw_fd()) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => break result,
        }
    };
    match child {
        Ok(pid) if pid > 0 => {
            let main_pidfd = match crate::sys::syscall::pidfd_open(pid, 0) {
                Ok(fd) => fd,
                Err(e) => {
                    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
                    drop(pinned_w);
                    reap(reaper);
                    return Err(e);
                }
            };
            unsafe { send(pinned_w.as_raw_fd(), 1) };
            unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
            Ok((
                pid as i32,
                Some(Reaper {
                    pid: reaper,
                    main_pidfd,
                    status: read,
                    command: Some(pinned_w),
                }),
            ))
        }
        _ => {
            drop(pinned_w);
            reap(reaper);
            Err(io::Error::other("session reaper failed to start"))
        }
    }
}

unsafe fn supervise(main: i32, status_fd: i32, command_fd: i32, mut stopping: bool) -> ! {
    let mut mask = std::mem::zeroed();
    libc::sigemptyset(&mut mask);
    libc::sigaddset(&mut mask, libc::SIGCHLD);
    let signal_fd = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
    let mut poll = [
        libc::pollfd {
            fd: command_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: signal_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        if stopping {
            kill_children();
        }
        loop {
            let mut status = 0;
            let pid = libc::waitpid(-1, &mut status, libc::WNOHANG);
            if pid == 0 {
                break;
            }
            if pid < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                libc::_exit(0);
            }
            if pid == main && !send(status_fd, status) {
                stopping = true;
            }
        }
        // A killed parent may have just transferred more children to us.
        if stopping {
            kill_children();
        }
        libc::poll(poll.as_mut_ptr(), 2, if signal_fd < 0 { 10 } else { -1 });
        if poll[0].revents != 0 {
            stopping = true;
            poll[0].fd = -1;
        }
        if poll[1].revents != 0 {
            let mut signal: libc::signalfd_siginfo = std::mem::zeroed();
            libc::read(
                signal_fd,
                (&mut signal as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of_val(&signal),
            );
        }
    }
}

unsafe fn kill_children() {
    let fd = libc::open(
        b"/proc/thread-self/children\0".as_ptr().cast(),
        libc::O_RDONLY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return;
    }
    let mut buffer = [0u8; 4096];
    let mut pid = 0i32;
    loop {
        let n = libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len());
        if n <= 0 {
            break;
        }
        for &byte in &buffer[..n as usize] {
            if byte.is_ascii_digit() {
                pid = pid * 10 + (byte - b'0') as i32;
            } else if pid > 0 {
                // Only this process reaps these children, so their PIDs cannot be reused here.
                libc::kill(pid, libc::SIGKILL);
                pid = 0;
            }
        }
    }
    if pid > 0 {
        libc::kill(pid, libc::SIGKILL);
    }
    libc::close(fd);
}

fn reap(pid: i32) {
    loop {
        if unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } >= 0 {
            return;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

unsafe fn send(fd: i32, value: i32) -> bool {
    loop {
        if libc::write(fd, (&value as *const i32).cast(), 4) == 4 {
            return true;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reports_an_exit_before_the_caller_starts_waiting() {
        let (pid, reaper) = fork().unwrap();
        if pid == 0 {
            unsafe { libc::_exit(42) }
        }
        let reaper = reaper.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let status = reaper.main_status().await.unwrap();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 42);
        let mut ready = libc::pollfd {
            fd: reaper.main_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut ready, 1, 0) }, 1);
        assert_eq!(
            unsafe { libc::waitpid(reaper.pid, std::ptr::null_mut(), 0) },
            reaper.pid
        );
    }
}
