use std::borrow::Cow;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A filesystem grant: a path, or a descriptor open on the tree it grants.
///
/// Landlock confines a descriptor grant's inode and the supervisor's checks
/// follow it across renames, so nothing done to a path can move the grant.
#[derive(Debug, Clone)]
pub struct Grant(Repr);

// Shared so a cloned sandbox grants the same descriptor.
#[derive(Debug, Clone)]
enum Repr {
    Path(PathBuf),
    Fd(Arc<OwnedFd>),
}

impl Grant {
    /// Where the grant is now. A descriptor grant reads this from the kernel
    /// on every call, and has none once its tree has no path.
    pub fn path(&self) -> Option<Cow<'_, Path>> {
        match &self.0 {
            Repr::Path(path) => Some(Cow::Borrowed(path)),
            Repr::Fd(fd) => std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                .ok()
                .filter(|path| path.is_absolute())
                .map(Cow::Owned),
        }
    }

    pub fn is_fd(&self) -> bool {
        matches!(self.0, Repr::Fd(_))
    }

    pub(crate) fn as_path(&self) -> Option<&Path> {
        match &self.0 {
            Repr::Path(path) => Some(path),
            Repr::Fd(_) => None,
        }
    }

    pub(crate) fn as_fd(&self) -> Option<&OwnedFd> {
        match &self.0 {
            Repr::Path(_) => None,
            Repr::Fd(fd) => Some(fd),
        }
    }

    pub(crate) fn covers(&self, path: &Path) -> bool {
        self.path().is_some_and(|grant| path.starts_with(grant))
    }

    pub(crate) fn is(&self, path: &Path) -> bool {
        self.path().is_some_and(|grant| grant == path)
    }
}

/// Descriptor grants are equal only when one is a clone of the other.
impl PartialEq for Grant {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Repr::Path(a), Repr::Path(b)) => a == b,
            (Repr::Fd(a), Repr::Fd(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl From<OwnedFd> for Grant {
    fn from(fd: OwnedFd) -> Self {
        Grant(Repr::Fd(Arc::new(fd)))
    }
}

impl From<PathBuf> for Grant {
    fn from(path: PathBuf) -> Self {
        Grant(Repr::Path(path))
    }
}

impl From<&Path> for Grant {
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

impl From<&str> for Grant {
    fn from(path: &str) -> Self {
        PathBuf::from(path).into()
    }
}

impl From<String> for Grant {
    fn from(path: String) -> Self {
        PathBuf::from(path).into()
    }
}

/// A descriptor cannot travel in a policy file, so a saved grant is the path
/// its tree has at the time and comes back as a path grant.
impl Serialize for Grant {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.path() {
            Some(path) => path.serialize(serializer),
            None => Err(serde::ser::Error::custom("fd grant has no path")),
        }
    }
}

impl<'de> Deserialize<'de> for Grant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        PathBuf::deserialize(deserializer).map(Grant::from)
    }
}
