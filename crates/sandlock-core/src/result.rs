use std::fmt;
use std::path::PathBuf;

/// The result of running a sandboxed process.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub exit_status: ExitStatus,
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<Vec<u8>>,
    /// What the run did to its COW branch, read before the branch action was
    /// applied. Empty when the sandbox has no workdir.
    pub changes: Vec<Change>,
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
            changes: Vec::new(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    /// Exists in the branch but not in the workdir.
    Added,
    /// Exists on both sides; the bytes are not compared, so a rewrite with
    /// identical contents, a mode change, or a rename over the path all count.
    Modified,
    /// Exists in the workdir but not in the branch.
    Deleted,
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChangeKind::Added => write!(f, "A"),
            ChangeKind::Modified => write!(f, "M"),
            ChangeKind::Deleted => write!(f, "D"),
        }
    }
}

/// One filesystem change a run made to its COW branch.
#[derive(Debug, Clone)]
pub struct Change {
    pub kind: ChangeKind,
    /// Relative to the workdir.
    pub path: PathBuf,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}  {}", self.kind, self.path.display())
    }
}
