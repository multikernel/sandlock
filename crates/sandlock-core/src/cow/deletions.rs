//! Subtree-aware whiteout tracking for the seccomp COW branch.
//!
//! A whiteout entered here hides the entered path AND everything beneath it
//! in the merged view, the way removing a directory hides its contents.
//! Entries are never removed: a path re-created after deletion is exposed by
//! existing in the upper layer (upper presence shadows the whiteout), which
//! is what makes an entry whose directory reappears behave as an opaque
//! directory. The set therefore only grows, and the on-disk log is
//! append-only.
//!
//! The log exists so the deletion half of a change set survives the process:
//! the upper directory is self-describing on disk, the RAM-only deletion set
//! was not (issues #159/#160/#161 all grew from that asymmetry). RAM stays
//! the in-process source of truth; a log write failure degrades durability,
//! not correctness, so it is deliberately not fatal.

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, Write};
use std::path::Path;

pub(crate) struct DeletionSet {
    entries: BTreeSet<String>,
    log: Option<fs::File>,
}

fn escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            // BufRead::lines strips a trailing \r on replay; unescaped, a
            // path ending in \r would round-trip to the \r-less sibling,
            // hiding that one and resurrecting the deleted path.
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut it = raw.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Persist the log's directory entry. `insert` only fdatasyncs the file
/// itself, which does not cover the name in the parent directory: without
/// this, a power loss after the first deletion can drop the whole log, the
/// exact crash class it exists for. Best-effort like every other log write.
fn sync_parent_dir(p: &Path) {
    if let Some(dir) = p.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

impl DeletionSet {
    /// Open a fresh set. `log_path` is opened for appending; `None`, or a
    /// path that cannot be created, gives a RAM-only set.
    pub fn create(log_path: Option<&Path>) -> Self {
        let log = log_path.and_then(|p| {
            let f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()?;
            sync_parent_dir(p);
            Some(f)
        });
        Self {
            entries: BTreeSet::new(),
            log,
        }
    }

    /// Rebuild a set from an existing log and reopen the log for append.
    /// Unreadable log lines are skipped, not fatal: a torn final line from a
    /// crash must not hide the deletions before it.
    // No production caller: the preserved-branch sweep reads the OUTSTANDING
    // deletions from the branch's PRESERVED marker, not this log. This log is
    // the full whiteout history and must not be replayed against a partly
    // merged branch — entries that already landed have had their upper copies
    // drained, so re-applying them destroys work that landed. Kept for a
    // future sweep that has to recover a branch whose marker is missing.
    #[allow(dead_code)]
    pub fn load(log_path: &Path) -> Self {
        let mut entries = BTreeSet::new();
        if let Ok(f) = fs::File::open(log_path) {
            for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                if !line.is_empty() {
                    entries.insert(unescape(&line));
                }
            }
        }
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .ok()
            .inspect(|_| sync_parent_dir(log_path));
        Self { entries, log }
    }

    /// Record `rel` as deleted. Idempotent; the log line and its fdatasync
    /// happen only on first insertion.
    pub fn insert(&mut self, rel: &str) {
        if !self.entries.insert(rel.to_string()) {
            return;
        }
        if let Some(f) = self.log.as_mut() {
            let _ = writeln!(f, "{}", escape(rel));
            let _ = f.sync_data();
        }
    }

    /// True when `rel` or any ancestor directory of it has been deleted.
    /// Matching is per path component: "d" covers "d/x" but never "d2".
    pub fn covers(&self, rel: &str) -> bool {
        if self.entries.contains(rel) {
            return true;
        }
        let mut end = rel.len();
        while let Some(i) = rel[..end].rfind('/') {
            if self.entries.contains(&rel[..i]) {
                return true;
            }
            end = i;
        }
        false
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_exact_and_descendants_not_siblings() {
        let mut s = DeletionSet::create(None);
        s.insert("d");
        assert!(s.covers("d"));
        assert!(s.covers("d/x"));
        assert!(s.covers("d/x/y"));
        assert!(!s.covers("d2"));
        assert!(!s.covers("d2/x"));
        assert!(!s.covers("e"));
    }

    #[test]
    fn covers_nested_entry() {
        let mut s = DeletionSet::create(None);
        s.insert("a/b");
        assert!(!s.covers("a"));
        assert!(s.covers("a/b/c"));
        assert!(!s.covers("a/bc"));
    }

    #[test]
    fn insert_is_idempotent() {
        let mut s = DeletionSet::create(None);
        s.insert("f");
        s.insert("f");
        assert_eq!(s.iter().collect::<Vec<_>>(), vec!["f"]);
    }

    #[test]
    fn log_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("deleted.log");
        {
            let mut s = DeletionSet::create(Some(&log));
            s.insert("plain.txt");
            s.insert("dir/with\nnewline");
            s.insert("back\\slash");
        }
        let replayed = DeletionSet::load(&log);
        assert_eq!(
            replayed.iter().collect::<Vec<_>>(),
            vec!["back\\slash", "dir/with\nnewline", "plain.txt"]
        );
        assert!(replayed.covers("dir/with\nnewline/child"));
    }

    #[test]
    fn log_roundtrip_carriage_return() {
        // A trailing \r is stripped by the line reader; without escaping,
        // "d/file\r" would replay as "d/file", after which covers() hides
        // the wrong sibling and the actually-deleted path resurrects.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("deleted.log");
        {
            let mut s = DeletionSet::create(Some(&log));
            s.insert("d/file\r");
            s.insert("mid\rdle");
        }
        let replayed = DeletionSet::load(&log);
        assert!(replayed.covers("d/file\r"));
        assert!(!replayed.covers("d/file"));
        assert!(replayed.covers("mid\rdle"));
        assert!(replayed.covers("mid\rdle/child"));
    }

    #[test]
    fn load_appends_not_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("deleted.log");
        {
            let mut s = DeletionSet::create(Some(&log));
            s.insert("one");
        }
        {
            let mut s = DeletionSet::load(&log);
            s.insert("two");
        }
        let s = DeletionSet::load(&log);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec!["one", "two"]);
    }

    #[test]
    fn ram_only_when_no_log() {
        let mut s = DeletionSet::create(None);
        s.insert("x");
        assert!(s.covers("x"));
        assert_eq!(s.iter().count(), 1);
    }
}
