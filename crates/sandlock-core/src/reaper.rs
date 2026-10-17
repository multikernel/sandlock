//! Main's parent and the session's subreaper, outside the sandbox.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(crate) struct Reaper {
    pub pid: i32,
    pub pidfd: OwnedFd,
    status: Option<OwnedFd>,
    finish: Option<OwnedFd>,
}

impl Reaper {
    /// Carries main's raw wait status as four little-endian bytes, then EOF.
    pub fn take_status(&mut self) -> Option<OwnedFd> {
        self.status.take()
    }

    /// Exit after reaping what has exited; jobs still alive are released.
    /// A byte rather than EOF: children parked before exec may hold a copy.
    pub fn finish(&mut self) {
        if let Some(fd) = self.finish.take() {
            unsafe { send(fd.as_raw_fd(), &[0]) };
        }
    }

    #[cfg(test)]
    pub fn exited(&self) -> bool {
        crate::pgroup::has_exited(self.pidfd.as_raw_fd())
    }

    pub async fn join(&self) {
        if let Ok(fd) = tokio::io::unix::AsyncFd::new(self.pidfd.as_raw_fd()) {
            let _ = fd.readable().await;
        }
        reap(self.pid);
    }

    pub fn join_blocking(&self) {
        reap(self.pid);
    }
}

/// Group R is named after the reaper's pid: while the reaper lives no other
/// process can hold that number, so signalling R by number stays exact on
/// every kernel, even after main has been reaped.
pub(crate) fn fork() -> io::Result<(i32, Option<Reaper>)> {
    let (status_r, status_w) = pipe()?;
    let (finish_r, finish_w) = pipe()?;
    let owner = unsafe { libc::getpid() };
    let owner_pgid = unsafe { libc::getpgrp() };
    let reaper = crate::control::fork_without_control_fds();
    if reaper < 0 {
        return Err(io::Error::last_os_error());
    }
    if reaper == 0 {
        unsafe {
            let mut all = std::mem::zeroed();
            let mut previous_mask = std::mem::zeroed();
            libc::sigfillset(&mut all);
            libc::sigprocmask(libc::SIG_SETMASK, &all, &mut previous_mask);
            let mut previous_chld = std::mem::zeroed();
            let mut default_chld: libc::sigaction = std::mem::zeroed();
            default_chld.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGCHLD, &default_chld, &mut previous_chld);
            // A pidfd of the owning process, not PDEATHSIG: that fires when
            // the forking thread exits and would end the session with it.
            let owner_fd = libc::syscall(libc::SYS_pidfd_open, owner, 0) as i32;
            let mut chld = std::mem::zeroed();
            libc::sigemptyset(&mut chld);
            libc::sigaddset(&mut chld, libc::SIGCHLD);
            let signal_fd = libc::signalfd(-1, &chld, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if owner_fd < 0
                || signal_fd < 0
                || libc::getppid() != owner
                || libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0
                || libc::setpgid(0, 0) != 0
            {
                libc::_exit(127);
            }
            let me = libc::getpid();
            let main = libc::fork();
            if main < 0 {
                libc::_exit(127);
            }
            if main == 0 {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != me
                {
                    libc::_exit(127);
                }
                libc::sigaction(libc::SIGCHLD, &previous_chld, std::ptr::null_mut());
                libc::sigprocmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut());
                libc::close(owner_fd);
                libc::close(signal_fd);
                drop((status_r, status_w, finish_r, finish_w));
                return Ok((0, None));
            }
            // Out of R, so a sweep of R never takes the reaper with it.
            if libc::setpgid(0, owner_pgid) != 0 {
                libc::kill(main, libc::SIGKILL);
                libc::_exit(127);
            }
            close_all_but([
                status_w.as_raw_fd(),
                finish_r.as_raw_fd(),
                signal_fd,
                owner_fd,
            ]);
            if !send(status_w.as_raw_fd(), &main.to_le_bytes()) {
                libc::kill(main, libc::SIGKILL);
            }
            supervise(
                main,
                me,
                status_w.as_raw_fd(),
                finish_r.as_raw_fd(),
                signal_fd,
                owner_fd,
            );
        }
    }
    drop(status_w);
    drop(finish_r);
    let main = loop {
        match crate::context::read_u32_fd(status_r.as_raw_fd()) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => break result,
        }
    };
    let pidfd = crate::sys::syscall::pidfd_open(reaper as u32, 0);
    match (main, pidfd) {
        (Ok(main), Ok(pidfd)) if main > 0 => Ok((
            main as i32,
            Some(Reaper {
                pid: reaper,
                pidfd,
                status: Some(status_r),
                finish: Some(finish_w),
            }),
        )),
        (main, pidfd) => {
            unsafe { libc::kill(reaper, libc::SIGKILL) };
            reap(reaper);
            Err(main
                .err()
                .or(pidfd.err())
                .unwrap_or_else(|| io::Error::other("session reaper failed to start")))
        }
    }
}

unsafe fn supervise(
    main: i32,
    group: i32,
    status_fd: i32,
    finish_fd: i32,
    signal_fd: i32,
    owner_fd: i32,
) -> ! {
    let mut poll = [
        libc::pollfd {
            fd: finish_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: signal_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: owner_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        loop {
            // WNOWAIT: main's status is sent before its pid is freed, so no
            // reader can see main alive once that number is reusable.
            let mut info: libc::siginfo_t = std::mem::zeroed();
            if libc::waitid(
                libc::P_ALL,
                0,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            ) < 0
            {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                // No child left means no session process left.
                libc::_exit(0);
            }
            let pid = info.si_pid();
            if pid == 0 {
                break;
            }
            if pid == main {
                send(status_fd, &wait_status(&info).to_le_bytes());
                libc::close(status_fd);
            }
            while libc::waitpid(pid, std::ptr::null_mut(), libc::__WALL) < 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
            {}
        }
        libc::poll(poll.as_mut_ptr(), 3, -1);
        // Owner death also closes its end of the finish pipe, so it must be
        // seen first; EOF alone likewise means nobody can finish or join.
        if poll[2].revents != 0 || (poll[0].revents != 0 && !read_finish(finish_fd)) {
            libc::kill(-group, libc::SIGKILL);
            libc::_exit(0);
        }
        if poll[0].revents != 0 {
            libc::_exit(0);
        }
        if poll[1].revents != 0 {
            let mut info: libc::signalfd_siginfo = std::mem::zeroed();
            libc::read(
                signal_fd,
                (&mut info as *mut libc::signalfd_siginfo).cast(),
                std::mem::size_of_val(&info),
            );
        }
    }
}

/// The raw wait status that `waitpid` would have returned for `info`.
unsafe fn wait_status(info: &libc::siginfo_t) -> i32 {
    let status = info.si_status();
    match info.si_code {
        libc::CLD_EXITED => (status & 0xff) << 8,
        libc::CLD_DUMPED => status | 0x80,
        _ => status,
    }
}

/// True for the finish byte, false for EOF.
unsafe fn read_finish(fd: i32) -> bool {
    let mut byte = 0u8;
    loop {
        match libc::read(fd, (&mut byte as *mut u8).cast(), 1) {
            1 => return true,
            -1 if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) => {}
            _ => return false,
        }
    }
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

unsafe fn close_all_but(mut keep: [i32; 4]) {
    keep.sort_unstable();
    let mut next = 0u32;
    for kept in keep {
        if kept as u32 > next {
            libc::syscall(libc::SYS_close_range, next, kept as u32 - 1, 0u32);
        }
        next = kept as u32 + 1;
    }
    libc::syscall(libc::SYS_close_range, next, u32::MAX, 0u32);
}

fn reap(pid: i32) {
    while unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } < 0
        && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
    {}
}

unsafe fn send(fd: i32, bytes: &[u8]) -> bool {
    loop {
        if libc::write(fd, bytes.as_ptr().cast(), bytes.len()) == bytes.len() as isize {
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

    fn read_status(fd: &OwnedFd) -> i32 {
        let mut raw = [0u8; 4];
        assert_eq!(
            unsafe { libc::read(fd.as_raw_fd(), raw.as_mut_ptr().cast(), 4) },
            4
        );
        i32::from_le_bytes(raw)
    }

    #[tokio::test]
    async fn relays_main_status_and_names_its_group() {
        let (main, reaper) = fork().unwrap();
        if main == 0 {
            unsafe {
                libc::_exit(if libc::getpgrp() == libc::getppid() {
                    42
                } else {
                    1
                })
            }
        }
        let mut reaper = reaper.unwrap();
        let status = read_status(&reaper.take_status().unwrap());
        assert_eq!(libc::WEXITSTATUS(status), 42);
        assert_ne!(
            unsafe { libc::getpgid(reaper.pid) },
            reaper.pid,
            "reaper left group R"
        );
        reaper.join().await;
    }

    #[tokio::test]
    async fn outlives_main_until_orphans_are_reaped() {
        let (main, reaper) = fork().unwrap();
        if main == 0 {
            unsafe {
                if libc::fork() == 0 {
                    libc::usleep(300_000);
                    libc::_exit(0);
                }
                libc::_exit(7);
            }
        }
        let mut reaper = reaper.unwrap();
        assert_eq!(
            libc::WEXITSTATUS(read_status(&reaper.take_status().unwrap())),
            7
        );
        assert!(!reaper.exited());
        reaper.join().await;
    }

    #[tokio::test]
    async fn outlives_the_thread_that_created_it() {
        let reaper = std::thread::spawn(|| {
            let (main, reaper) = fork().unwrap();
            if main == 0 {
                unsafe {
                    libc::pause();
                    libc::_exit(0);
                }
            }
            reaper
        })
        .join()
        .unwrap()
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!reaper.exited());
        unsafe { libc::kill(-reaper.pid, libc::SIGKILL) };
        reaper.join().await;
    }

    #[tokio::test]
    async fn finish_releases_jobs_still_running() {
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let (main, reaper) = fork().unwrap();
        if main == 0 {
            unsafe {
                let job = libc::fork();
                if job == 0 {
                    libc::setsid();
                    libc::pause();
                    libc::_exit(0);
                }
                libc::write(pipe[1], (&job as *const i32).cast(), 4);
                libc::_exit(0);
            }
        }
        let mut job = 0i32;
        assert_eq!(
            unsafe { libc::read(pipe[0], (&mut job as *mut i32).cast(), 4) },
            4
        );
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        let mut reaper = reaper.unwrap();
        read_status(&reaper.take_status().unwrap());
        reaper.finish();
        reaper.join().await;
        assert_eq!(unsafe { libc::kill(job, libc::SIGKILL) }, 0);
    }

    /// The owner is a re-executed copy of this test, so its death can be
    /// observed here without running Rust code in a forked child.
    #[test]
    fn owner_death_kills_group_r() {
        const OWNER: &str = "SANDLOCK_TEST_REAPER_OWNER";
        if std::env::var_os(OWNER).is_some() {
            let (main, reaper) = fork().unwrap();
            if main == 0 {
                unsafe {
                    if libc::fork() == 0 {
                        libc::pause();
                    }
                    libc::pause();
                    libc::_exit(0);
                }
            }
            use std::io::Write;
            let mut out = std::io::stdout();
            let _ = writeln!(out, "group={}", reaper.unwrap().pid);
            let _ = out.flush();
            unsafe { libc::_exit(0) }
        }
        let mut owner = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "reaper::tests::owner_death_kills_group_r",
                "--exact",
                "--nocapture",
            ])
            .env(OWNER, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Read only up to the report: concurrent forks in this test binary
        // may hold the pipe's write end, so EOF can come late.
        let group: i32 =
            std::io::BufRead::lines(std::io::BufReader::new(owner.stdout.take().unwrap()))
                .find_map(|l| l.ok()?.strip_prefix("group=")?.parse().ok())
                .expect("owner reported group R");
        owner.wait().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while unsafe { libc::kill(-group, 0) } == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "group R outlived its owner"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
