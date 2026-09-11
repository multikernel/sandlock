use std::fmt;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// No entry at the path when the run first touched it.
    Added,
    /// An entry on both sides; compare the entries to see what differs.
    Modified,
    /// The run removed the entry.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    /// A fifo, socket, or device node: no bytes, only a mode.
    Other,
}

/// One side of a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// Permission bits only.
    pub mode: u32,
    /// Byte length for a file; 0 otherwise.
    pub size: u64,
    /// SHA-256 of the bytes. Files only.
    pub digest: Option<[u8; 32]>,
    /// Link target, verbatim. Symlinks only.
    pub target: Option<String>,
}

impl Entry {
    fn same_content(&self, other: &Entry) -> bool {
        self.kind == other.kind && self.digest == other.digest && self.target == other.target
    }
}

/// One filesystem change a run made to its COW branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// Relative to the workdir.
    pub path: PathBuf,
    /// The workdir entry when the run first touched the path. `None` for a
    /// path that did not exist, or for a deletion of one the run could not
    /// inspect.
    pub before: Option<Entry>,
    /// The branch entry when the change set was read.
    pub after: Option<Entry>,
}

impl Change {
    pub fn kind(&self) -> ChangeKind {
        match (&self.before, &self.after) {
            (_, None) => ChangeKind::Deleted,
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), Some(_)) => ChangeKind::Modified,
        }
    }

    /// Both sides present with the same kind and bytes or target: a touch,
    /// a mode change, or a rewrite with identical contents.
    pub fn content_unchanged(&self) -> bool {
        matches!((&self.before, &self.after), (Some(b), Some(a)) if b.same_content(a))
    }

    pub fn type_changed(&self) -> bool {
        matches!((&self.before, &self.after), (Some(b), Some(a)) if b.kind != a.kind)
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}  {}", self.kind(), self.path.display())
    }
}

/// Pair each deleted file with the added file carrying the same digest. A
/// digest seen more than once on either side is ambiguous and left unpaired.
pub fn renames(changes: &[Change]) -> Vec<(&Path, &Path)> {
    use std::collections::HashMap;
    fn unique_by_digest<'a>(
        entries: impl Iterator<Item = (&'a Path, &'a Entry)>,
    ) -> HashMap<[u8; 32], Option<&'a Path>> {
        let mut by_digest: HashMap<[u8; 32], Option<&Path>> = HashMap::new();
        for (path, entry) in entries {
            if let Some(d) = entry.digest {
                by_digest.entry(d).and_modify(|slot| *slot = None).or_insert(Some(path));
            }
        }
        by_digest
    }
    let deleted = unique_by_digest(changes.iter().filter_map(|c| match (&c.before, &c.after) {
        (Some(b), None) => Some((c.path.as_path(), b)),
        _ => None,
    }));
    let added = unique_by_digest(changes.iter().filter_map(|c| match (&c.before, &c.after) {
        (None, Some(a)) => Some((c.path.as_path(), a)),
        _ => None,
    }));
    let mut pairs: Vec<(&Path, &Path)> = deleted
        .iter()
        .filter_map(|(d, old)| Some(((*old)?, (*added.get(d)?)?)))
        .collect();
    pairs.sort();
    pairs
}

#[cfg(test)]
mod change_tests {
    use super::*;

    fn file(mode: u32, size: u64, digest: u8) -> Entry {
        Entry { kind: EntryKind::File, mode, size, digest: Some([digest; 32]), target: None }
    }

    fn link(target: &str) -> Entry {
        Entry { kind: EntryKind::Symlink, mode: 0o777, size: 0, digest: None, target: Some(target.into()) }
    }

    fn change(path: &str, before: Option<Entry>, after: Option<Entry>) -> Change {
        Change { path: PathBuf::from(path), before, after }
    }

    #[test]
    fn kind_is_derived_from_which_sides_are_present() {
        assert_eq!(change("a", None, Some(file(0o644, 1, 1))).kind(), ChangeKind::Added);
        assert_eq!(change("m", Some(file(0o644, 1, 1)), Some(file(0o644, 2, 2))).kind(), ChangeKind::Modified);
        assert_eq!(change("d", Some(file(0o644, 1, 1)), None).kind(), ChangeKind::Deleted);
        assert_eq!(change("unseen", None, None).kind(), ChangeKind::Deleted);
    }

    #[test]
    fn content_unchanged_means_same_kind_and_same_digest_or_target() {
        assert!(change("touch", Some(file(0o644, 1, 1)), Some(file(0o644, 1, 1))).content_unchanged());
        assert!(change("chmod", Some(file(0o644, 1, 1)), Some(file(0o755, 1, 1))).content_unchanged());
        assert!(!change("edit", Some(file(0o644, 1, 1)), Some(file(0o644, 1, 2))).content_unchanged());
        assert!(change("same-link", Some(link("t")), Some(link("t"))).content_unchanged());
        assert!(!change("retarget", Some(link("t")), Some(link("u"))).content_unchanged());
        assert!(!change("added", None, Some(file(0o644, 1, 1))).content_unchanged());
    }

    #[test]
    fn type_changed_needs_both_sides_with_different_kinds() {
        assert!(change("f2l", Some(file(0o644, 1, 1)), Some(link("t"))).type_changed());
        assert!(!change("edit", Some(file(0o644, 1, 1)), Some(file(0o644, 1, 2))).type_changed());
        assert!(!change("added", None, Some(link("t"))).type_changed());
    }

    #[test]
    fn renames_pairs_a_deleted_file_with_the_added_file_of_equal_digest() {
        let changes = vec![
            change("old.txt", Some(file(0o644, 5, 7)), None),
            change("new.txt", None, Some(file(0o644, 5, 7))),
            change("other.txt", None, Some(file(0o644, 5, 8))),
        ];
        assert_eq!(
            renames(&changes),
            vec![(Path::new("old.txt"), Path::new("new.txt"))],
        );
    }

    #[test]
    fn renames_leaves_ambiguous_digests_unpaired() {
        let changes = vec![
            change("a", Some(file(0o644, 5, 7)), None),
            change("b", Some(file(0o644, 5, 7)), None),
            change("c", None, Some(file(0o644, 5, 7))),
        ];
        assert!(renames(&changes).is_empty());
    }

    #[test]
    fn display_keeps_the_kind_and_path_form() {
        let c = change("dir/f.txt", None, Some(file(0o644, 1, 1)));
        assert_eq!(c.to_string(), "A  dir/f.txt");
    }
}
