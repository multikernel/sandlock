//! What the workdir held for each path the run touched, recorded at first
//! touch so the change set can report the side the branch replaced.
//!
//! Not a source of correctness: the upper and the whiteout set are the
//! change set. Losing this only turns a Modified into an Added in the
//! report, so nothing here is written to disk during the run.

use std::collections::BTreeMap;

use crate::result::{Entry, EntryKind};

#[derive(Debug, Default)]
pub(crate) struct Origins {
    entries: BTreeMap<String, Option<Entry>>,
}

impl Origins {
    /// Record what the workdir held at `rel`; `None` for no entry. Only the
    /// first record for a path is kept. Returns whether this was the first.
    pub fn record(&mut self, rel: &str, before: Option<Entry>) -> bool {
        if self.entries.contains_key(rel) {
            return false;
        }
        self.entries.insert(rel.to_string(), before);
        true
    }

    /// Fill in the digest of a recorded file whose bytes were streamed later.
    pub fn set_digest(&mut self, rel: &str, digest: [u8; 32]) {
        if let Some(Some(e)) = self.entries.get_mut(rel) {
            if e.kind == EntryKind::File && e.digest.is_none() {
                e.digest = Some(digest);
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Option<Entry>)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn get(&self, rel: &str) -> Option<&Option<Entry>> {
        self.entries.get(rel)
    }

    /// Every recorded path strictly beneath `prefix`, by path component:
    /// "d" yields "d/x" but never "d2".
    pub fn under<'a>(&'a self, prefix: &str) -> impl Iterator<Item = (&'a str, &'a Option<Entry>)> {
        let start = format!("{prefix}/");
        self.entries
            .range(start.clone()..)
            .take_while(move |(k, _)| k.starts_with(&start))
            .map(|(k, v)| (k.as_str(), v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{Entry, EntryKind};

    fn file(digest: u8) -> Entry {
        Entry { kind: EntryKind::File, mode: 0o644, size: 1, digest: Some([digest; 32]), target: None }
    }

    #[test]
    fn first_record_wins() {
        let mut o = Origins::default();
        assert!(o.record("f", Some(file(1))));
        assert!(!o.record("f", Some(file(2))));
        assert_eq!(o.get("f"), Some(&Some(file(1))));
        assert_eq!(o.get("missing"), None);
    }

    #[test]
    fn an_absent_lower_is_recorded_as_none_and_still_counts_as_recorded() {
        let mut o = Origins::default();
        assert!(o.record("new", None));
        assert!(!o.record("new", Some(file(1))));
        assert_eq!(o.get("new"), Some(&None));
    }

    #[test]
    fn set_digest_only_fills_an_empty_file_digest() {
        let mut o = Origins::default();
        let mut undigested = file(0);
        undigested.digest = None;
        o.record("f", Some(undigested));
        o.record("keep", Some(file(1)));
        o.record("gone", None);
        o.set_digest("f", [9; 32]);
        o.set_digest("keep", [9; 32]);
        o.set_digest("gone", [9; 32]);
        assert_eq!(o.get("f").unwrap().as_ref().unwrap().digest, Some([9; 32]));
        assert_eq!(o.get("keep").unwrap().as_ref().unwrap().digest, Some([1; 32]));
        assert_eq!(o.get("gone"), Some(&None));
    }

    #[test]
    fn under_matches_path_components_not_string_prefixes() {
        let mut o = Origins::default();
        o.record("d", Some(file(0)));
        o.record("d/x", Some(file(1)));
        o.record("d/y/z", Some(file(2)));
        o.record("d2", Some(file(3)));
        o.record("d2/x", Some(file(4)));
        let got: Vec<&str> = o.under("d").map(|(p, _)| p).collect();
        assert_eq!(got, vec!["d/x", "d/y/z"]);
    }
}
