// Nesting-detection helpers used by sandbox.rs.

use std::sync::atomic::{AtomicBool, Ordering};

// ============================================================
// Nesting detection
// ============================================================

/// Set after seccomp confinement in the child process.
/// Any subsequent Sandbox in this process is nested.
pub(crate) static CONFINED: AtomicBool = AtomicBool::new(false);

/// Detect if this process is already inside a sandbox.
///
/// Checks both the in-process flag and /proc/self/status (Seccomp: 2)
/// to catch cross-process nesting (e.g. `sandlock run -- python agent.py`
/// where agent.py creates inner sandboxes).
pub fn is_nested() -> bool {
    if CONFINED.load(Ordering::Relaxed) {
        return true;
    }
    // Check /proc/self/status for active seccomp filter
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Seccomp:") {
                return line.trim().ends_with('2');
            }
        }
    }
    false
}
