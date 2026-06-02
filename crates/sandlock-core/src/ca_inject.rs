// Trust-store injection: splice the active MITM CA into user-declared trust
// bundles at openat time. The child's open is intercepted before the kernel
// performs it; we read the child's real file via /proc/<pid>/root, append the
// CA PEM, and inject the combined bytes as a sealed memfd. Landlock is never
// consulted for the intercepted open (the syscall result is our memfd).

use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

use crate::seccomp::notif::NotifAction;
use crate::sys::structs::SeccompNotif;

/// Append `ca_pem` to `original` bundle contents, ensuring a newline between
/// them so the concatenation is a valid multi-cert PEM file.
pub(crate) fn combine_bundle(original: &[u8], ca_pem: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(original.len() + ca_pem.len() + 1);
    out.extend_from_slice(original);
    if !original.is_empty() && !original.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(ca_pem);
    out
}

/// True if `resolved` exactly matches one of the user-declared inject paths.
pub(crate) fn path_matches(resolved: &Path, inject_paths: &[PathBuf]) -> bool {
    inject_paths.iter().any(|p| p == resolved)
}

/// Intercept an open-family syscall targeting a declared trust bundle and
/// return a memfd containing the original bundle plus the active CA.
///
/// Returns `None` (fall through to the kernel) when: the syscall is not an
/// open variant, the path is not a declared bundle, or the child's file
/// cannot be read host-side. Falling through is safe: it just lets the
/// normal open proceed, subject to the rest of the policy.
pub(crate) fn handle_ca_inject_open(
    notif: &SeccompNotif,
    inject_paths: &[PathBuf],
    ca_pem: &[u8],
    notif_fd: RawFd,
) -> Option<NotifAction> {
    let resolved = crate::procfs::resolve_open_target(notif, notif_fd)?;
    if !path_matches(&resolved, inject_paths) {
        return None;
    }
    // Read the file as the child sees it (chroot/COW aware) via /proc/<pid>/root.
    let child_view = format!("/proc/{}/root{}", notif.pid, resolved.to_str()?);
    let original = std::fs::read(&child_view).ok()?;
    let combined = combine_bundle(&original, ca_pem);
    Some(NotifAction::inject_bytes(&combined))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_inserts_newline_when_missing() {
        let out = combine_bundle(b"AAA", b"BBB\n");
        assert_eq!(out, b"AAA\nBBB\n");
    }

    #[test]
    fn combine_no_extra_newline_when_present() {
        let out = combine_bundle(b"AAA\n", b"BBB\n");
        assert_eq!(out, b"AAA\nBBB\n");
    }

    #[test]
    fn combine_empty_original() {
        let out = combine_bundle(b"", b"BBB\n");
        assert_eq!(out, b"BBB\n");
    }

    #[test]
    fn path_matches_exact_only() {
        let paths = vec![PathBuf::from("/etc/ssl/certs/ca-certificates.crt")];
        assert!(path_matches(Path::new("/etc/ssl/certs/ca-certificates.crt"), &paths));
        assert!(!path_matches(Path::new("/etc/ssl/certs/other.crt"), &paths));
    }
}
