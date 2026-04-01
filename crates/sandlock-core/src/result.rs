/// The result of running a sandboxed process.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub exit_status: ExitStatus,
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<Vec<u8>>,
}

impl RunResult {
    pub fn success(&self) -> bool {
        matches!(self.exit_status, ExitStatus::Code(0))
    }

    pub fn code(&self) -> Option<i32> {
        match self.exit_status {
            ExitStatus::Code(c) => Some(c),
            _ => None,
        }
    }

    pub fn stdout_str(&self) -> Option<&str> {
        self.stdout
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok().map(|s| s.trim_end_matches('\n')))
    }

    pub fn timeout() -> Self {
        RunResult {
            exit_status: ExitStatus::Timeout,
            stdout: None,
            stderr: None,
        }
    }

    pub fn stderr_str(&self) -> Option<&str> {
        self.stderr
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok().map(|s| s.trim_end_matches('\n')))
    }
}

/// How a sandboxed process exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitStatus {
    Code(i32),
    Signal(i32),
    Killed,
    Timeout,
}
