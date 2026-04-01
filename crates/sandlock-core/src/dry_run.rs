use crate::result::RunResult;
use std::fmt;
use std::path::PathBuf;

/// Kind of filesystem change detected by dry-run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    /// File was created (exists in upper but not in workdir).
    Added,
    /// File was modified (exists in both, content differs).
    Modified,
    /// File was deleted.
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

/// A single filesystem change detected by dry-run.
#[derive(Debug, Clone)]
pub struct Change {
    pub kind: ChangeKind,
    /// Path relative to workdir.
    pub path: PathBuf,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}  {}", self.kind, self.path.display())
    }
}

/// Result of a dry-run execution.
#[derive(Debug)]
pub struct DryRunResult {
    pub run_result: RunResult,
    pub changes: Vec<Change>,
}
