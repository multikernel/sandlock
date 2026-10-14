use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(crate) struct Reaper {
    pub pid: i32,
    pub pidfd: OwnedFd,
    pub main_pidfd: OwnedFd,
    status: OwnedFd,
    finish: Option<OwnedFd>,
    /// Set once the main process is known to have been the last one left.
    pub empty: bool,
}

pub(crate) struct MainExit {
    pub status: i32,
    pub last: bool,
}

impl Reaper {
    pub async fn main_exit(&self) -> io::Result<MainExit> {
        let fd = tokio::io::unix::AsyncFd::new(self.status.try_clone()?)?;
        loop {
            let mut ready = fd.readable().await?;
            let result = ready.try_io(|fd| {
                let mut message = [0i32; 2];
                let n = unsafe {
                    libc::read(fd.get_ref().as_raw_fd(), message.as_mut_ptr().cast(), 8)
                };
                match n {
                    8 => Ok(MainExit { status: message[0], last: message[1] != 0 }),
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

    /// Collect what has exited, then exit. Children still alive are not in
    /// any tracked group, so nothing could kill them; they are released.
    pub fn finish(&mut self) {
        // A byte, not EOF: children parked before exec may hold a copy of this fd.
        if let Some(fd) = self.finish.take() {
            unsafe { send(fd.as_raw_fd(), &[0]) };
        }
    }

    pub async fn join(&self) -> io::Result<()> {
        crate::sandbox::wait_child_exit_via_pidfd(self.pidfd.try_clone()?, self.pid).await;
        Ok(())
    }

    pub fn join_blocking(self) {
        reap(self.pid);
    }
}

/// A private subreaper keeps orphans below the supervisor for Yama checks,
/// without changing the embedding process's child-adoption policy. It never
/// kills: the supervisor kills through the tracked process groups, and the
/// reaper exits once nothing is left to reap or it is told to finish.
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
            // Watch the owning process rather than set PDEATHSIG, which fires
            // when the forking thread exits and would end the session with it.
            let owner_fd = libc::syscall(libc::SYS_pidfd_open, owner, 0) as i32;
            if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0
                || owner_fd < 0
                || libc::getppid() != owner
            {
                libc::_exit(127);
            }
            let mut chld = std::mem::zeroed();
            libc::sigemptyset(&mut chld);
            libc::sigaddset(&mut chld, libc::SIGCHLD);
            let signal_fd = libc::signalfd(-1, &chld, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if signal_fd < 0 {
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
            let mut keep = [fd, gate, signal_fd, owner_fd];
            keep.sort_unstable();
            let mut next = 0u32;
            for kept in keep {
                if kept as u32 > next {
                    libc::syscall(libc::SYS_close_range, next, kept as u32 - 1, 0u32);
                }
                next = kept as u32 + 1;
            }
            libc::syscall(libc::SYS_close_range, next, u32::MAX, 0u32);
            if !send(fd, &[child]) {
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
                    break false;
                }
            };
            if !acknowledged {
                libc::kill(child, libc::SIGKILL);
            }
            supervise(child, fd, gate, signal_fd, owner_fd);
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
    let opened = match child {
        Ok(pid) if pid > 0 => crate::sys::syscall::pidfd_open(pid, 0)
            .and_then(|main| Ok((pid as i32, main, crate::sys::syscall::pidfd_open(reaper as u32, 0)?))),
        _ => Err(io::Error::other("session reaper failed to start")),
    };
    match opened {
        Ok((pid, main_pidfd, pidfd)) => {
            unsafe { send(pinned_w.as_raw_fd(), &[1]) };
            unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
            Ok((
                pid,
                Some(Reaper {
                    pid: reaper,
                    pidfd,
                    main_pidfd,
                    status: read,
                    finish: Some(pinned_w),
                    empty: false,
                }),
            ))
        }
        Err(e) => {
            // Without the ack the reaper kills its pinned child itself.
            drop(pinned_w);
            reap(reaper);
            Err(e)
        }
    }
}

unsafe fn supervise(main: i32, status_fd: i32, finish_fd: i32, signal_fd: i32, owner_fd: i32) -> ! {
    let mut poll = [
        libc::pollfd { fd: finish_fd, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: signal_fd, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: owner_fd, events: libc::POLLIN, revents: 0 },
    ];
    let mut finishing = false;
    let mut main_alive = true;
    loop {
        let alive = loop {
            let mut status = 0;
            match libc::waitpid(-1, &mut status, libc::WNOHANG | libc::__WALL) {
                0 => break true,
                pid if pid == main => {
                    main_alive = false;
                    let last = !has_children();
                    send(status_fd, &[status, last as i32]);
                }
                pid if pid > 0 => {}
                _ if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) => {}
                // No child means no descendant: the session is over.
                _ => break false,
            }
        };
        if !alive || finishing {
            libc::_exit(0);
        }
        libc::poll(poll.as_mut_ptr(), 3, -1);
        if poll[0].revents != 0 {
            finishing = true;
        }
        if poll[2].revents != 0 {
            // Unreaped, the main pid cannot have been reused.
            if main_alive {
                libc::kill(main, libc::SIGKILL);
            }
            finishing = true;
        }
        if poll[1].revents != 0 {
            let mut info: libc::signalfd_siginfo = std::mem::zeroed();
            libc::read(signal_fd, (&mut info as *mut libc::signalfd_siginfo).cast(), std::mem::size_of_val(&info));
        }
    }
}

unsafe fn has_children() -> bool {
    loop {
        match libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG | libc::__WALL) {
            0 => return true,
            pid if pid > 0 => {}
            _ if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) => {}
            _ => return false,
        }
    }
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

unsafe fn send(fd: i32, values: &[i32]) -> bool {
    let len = std::mem::size_of_val(values);
    loop {
        if libc::write(fd, values.as_ptr().cast(), len) == len as isize {
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
        let exit = reaper.main_exit().await.unwrap();
        assert!(libc::WIFEXITED(exit.status));
        assert_eq!(libc::WEXITSTATUS(exit.status), 42);
        assert!(exit.last);
        let mut ready = libc::pollfd {
            fd: reaper.main_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut ready, 1, 0) }, 1);
        reaper.join().await.unwrap();
    }

    #[tokio::test]
    async fn outlives_the_main_process_until_orphans_are_reaped() {
        let (pid, reaper) = fork().unwrap();
        if pid == 0 {
            unsafe {
                if libc::fork() == 0 {
                    libc::usleep(300_000);
                    libc::_exit(0);
                }
                libc::_exit(7);
            }
        }
        let reaper = reaper.unwrap();
        let exit = reaper.main_exit().await.unwrap();
        assert_eq!(libc::WEXITSTATUS(exit.status), 7);
        assert!(!exit.last);
        let mut ready = libc::pollfd {
            fd: reaper.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut ready, 1, 50) }, 0);
        reaper.join().await.unwrap();
    }

    #[tokio::test]
    async fn outlives_the_thread_that_created_it() {
        let (pid, reaper) = std::thread::spawn(|| {
            let (pid, reaper) = fork().unwrap();
            if pid == 0 {
                unsafe {
                    libc::pause();
                    libc::_exit(0);
                }
            }
            (pid, reaper)
        })
        .join()
        .unwrap();
        let mut reaper = reaper.unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        for fd in [&reaper.pidfd, &reaper.main_pidfd] {
            let mut ready = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            assert_eq!(unsafe { libc::poll(&mut ready, 1, 0) }, 0);
        }
        unsafe { libc::kill(pid, libc::SIGKILL) };
        reaper.finish();
        reaper.join().await.unwrap();
    }

    #[tokio::test]
    async fn finish_releases_children_still_running() {
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let (pid, reaper) = fork().unwrap();
        if pid == 0 {
            unsafe {
                let orphan = libc::fork();
                if orphan == 0 {
                    libc::pause();
                    libc::_exit(0);
                }
                libc::write(pipe[1], (&orphan as *const i32).cast(), 4);
                libc::_exit(0);
            }
        }
        let mut orphan = 0i32;
        assert_eq!(unsafe { libc::read(pipe[0], (&mut orphan as *mut i32).cast(), 4) }, 4);
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        let mut reaper = reaper.unwrap();
        assert!(!reaper.main_exit().await.unwrap().last);
        reaper.finish();
        reaper.join().await.unwrap();
        assert_eq!(unsafe { libc::kill(orphan, libc::SIGKILL) }, 0);
    }
}
