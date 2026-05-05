//! Audit every `openat(2)` that a sandboxed process performs.
//!
//! Demonstrates [`Sandbox::run_with_extra_handlers`]: a downstream crate
//! registers a user handler for `SYS_openat` that logs the call and falls
//! through to default (builtin) processing.
//!
//! Run:
//!
//! ```sh
//! # From the sandlock repo root.
//! cargo run --example openat_audit -- /usr/bin/python3 -c 'open("/etc/hostname").read()'
//! ```
//!
//! Expected output:
//!
//! ```text
//! [audit] pid=... openat
//! [audit] pid=... openat
//! [audit] pid=... openat
//! exit=Some(0) stdout=...
//! ```

use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sandlock_core::seccomp::dispatch::{ExtraHandler, HandlerFn};
use sandlock_core::seccomp::notif::NotifAction;
use sandlock_core::{Policy, Sandbox};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmd: Vec<String> = env::args().skip(1).collect();
    if cmd.is_empty() {
        eprintln!("usage: openat_audit <cmd> [args...]");
        std::process::exit(2);
    }
    let cmd_ref: Vec<&str> = cmd.iter().map(String::as_str).collect();

    // Minimal policy: read /usr, /lib, /etc, /proc; write /tmp.
    let policy = Policy::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/lib64")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_write("/tmp")
        .build()?;

    // User handler: count + log every openat, fall through to builtin.
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

    let audit: HandlerFn = Box::new(move |notif, _ctx, _fd| {
        let counter = Arc::clone(&counter_clone);
        Box::pin(async move {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            eprintln!("[audit #{n}] pid={} openat", notif.pid);
            // Continue = let the default table and the kernel handle it.
            NotifAction::Continue
        })
    });

    let result = Sandbox::run_with_extra_handlers(
        &policy,
        Some("openat-audit"),
        &cmd_ref,
        vec![ExtraHandler::new(libc::SYS_openat, audit)],
    )
    .await?;

    println!(
        "exit={:?} opens={} stdout={:?}",
        result.code(),
        counter.load(Ordering::SeqCst),
        result.stdout_str().unwrap_or(""),
    );
    Ok(())
}
