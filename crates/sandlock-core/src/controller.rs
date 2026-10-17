//! Acts on a running session while `Sandbox::wait()` holds it mutably.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

use crate::error::{SandboxRuntimeError, SandlockError};
use crate::result::ExitStatus;

#[derive(Clone)]
pub struct Controller {
    pub(crate) groups: Arc<crate::pgroup::ProcessGroups>,
    pub(crate) stop: tokio_util::sync::CancellationToken,
    pub(crate) main_exit: Arc<MainExit>,
    pub(crate) pid: i32,
}

impl Controller {
    pub fn kill(&self) -> Result<(), SandlockError> {
        self.signal(libc::SIGKILL).map(|_| ())
    }

    pub fn pause(&self) -> Result<(), SandlockError> {
        self.signal_live(libc::SIGSTOP)
    }

    pub fn resume(&self) -> Result<(), SandlockError> {
        self.signal_live(libc::SIGCONT)
    }

    /// Sorted pgids that still have members; may change as soon as it returns.
    pub fn process_groups(&self) -> Result<Vec<i32>, SandlockError> {
        Ok(self.groups.live().map_err(SandboxRuntimeError::Io)?)
    }

    pub fn main_exited(&self) -> bool {
        self.main_exit.get().is_some()
    }

    /// Main's pid until it exits; afterwards the number may name another process.
    pub fn pid(&self) -> Option<i32> {
        (!self.main_exited()).then_some(self.pid)
    }

    /// Signal every group, returning how many had members left.
    pub fn signal(&self, sig: i32) -> Result<usize, SandlockError> {
        if sig == libc::SIGKILL {
            self.stop.cancel();
        }
        Ok(self.groups.signal(sig).map_err(SandboxRuntimeError::Io)?)
    }

    fn signal_live(&self, sig: i32) -> Result<(), SandlockError> {
        if self.signal(sig)? == 0 {
            return Err(
                SandboxRuntimeError::Io(std::io::Error::from_raw_os_error(libc::ESRCH)).into(),
            );
        }
        Ok(())
    }
}

/// Main's exit status, read straight from the reaper's status pipe so that no
/// background task, and no particular runtime, has to be alive to learn it.
pub(crate) struct MainExit {
    pipe: Option<OwnedFd>,
    status: Mutex<Option<ExitStatus>>,
}

impl MainExit {
    /// `pipe` carries main's raw wait status as four bytes; without one, the
    /// owner publishes the status through [`MainExit::set`].
    pub(crate) fn new(pipe: Option<OwnedFd>) -> Arc<Self> {
        if let Some(fd) = &pipe {
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        }
        Arc::new(MainExit {
            pipe,
            status: Mutex::new(None),
        })
    }

    pub(crate) fn get(&self) -> Option<ExitStatus> {
        let mut status = self.status.lock().unwrap();
        if status.is_none() {
            if let Some(fd) = &self.pipe {
                let mut raw = [0u8; 4];
                let n = unsafe { libc::read(fd.as_raw_fd(), raw.as_mut_ptr().cast(), raw.len()) };
                *status = match n {
                    4 => Some(crate::sandbox::sandbox_wait_status_to_exit(
                        i32::from_le_bytes(raw),
                    )),
                    // The write is atomic, so anything else but EAGAIN means
                    // the reaper died without reporting main.
                    n if n < 0
                        && std::io::Error::last_os_error().kind()
                            == std::io::ErrorKind::WouldBlock =>
                    {
                        None
                    }
                    _ => Some(ExitStatus::Killed),
                };
            }
        }
        status.clone()
    }

    pub(crate) fn set(&self, exit: ExitStatus) {
        self.status.lock().unwrap().get_or_insert(exit);
    }

    pub(crate) async fn wait(&self) -> std::io::Result<ExitStatus> {
        let Some(fd) = &self.pipe else {
            return Err(std::io::Error::other("main's exit has no status pipe"));
        };
        let ready =
            tokio::io::unix::AsyncFd::with_interest(fd.as_raw_fd(), tokio::io::Interest::READABLE)?;
        loop {
            if let Some(exit) = self.get() {
                return Ok(exit);
            }
            ready.readable().await?.clear_ready();
        }
    }
}
