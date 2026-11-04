//! Synchronous work run on behalf of a parked notification.
//!
//! A native closure cannot be cancelled, so it has no deadline: its caller
//! waits for it as for the syscall itself. A trapped task has at most one
//! notification outstanding, which bounds how many a sandbox can run.

use std::sync::OnceLock;

use tokio::runtime::Runtime;

use super::notif::NotifAction;

const MAX_THREADS: usize = 512;

// The embedder's runtime waits for its blocking tasks on shutdown, and a
// closure stuck on a peer would hold that shutdown hostage.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(MAX_THREADS)
            .thread_name("sandlock-native")
            .build()
            .expect("building a runtime without drivers cannot fail")
    })
}

/// Run `work` on a native thread.
pub(crate) async fn run(work: Box<dyn FnOnce() -> NotifAction + Send>) -> NotifAction {
    let job = runtime().spawn_blocking(work);
    job.await.unwrap_or(NotifAction::Errno(libc::EIO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn abandoned_work_runs_to_completion() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(run(Box::new(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            let _ = done_tx.send(());
            NotifAction::Continue
        })));
        started_rx.await.unwrap();
        waiter.abort();
        let _ = waiter.await;
        release_tx.send(()).unwrap();
        done_rx.await.unwrap();
    }

    #[tokio::test]
    async fn panicking_work_fails_closed() {
        let action = run(Box::new(|| panic!("native panic"))).await;
        assert!(matches!(action, NotifAction::Errno(libc::EIO)));
    }
}
