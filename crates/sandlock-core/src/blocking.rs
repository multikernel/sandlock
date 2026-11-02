//! Bounded synchronous work, isolated from the embedding runtime's blocking pool.
//!
//! Dropping a waiter does not stop running work. Its closure retains admission
//! until it returns; process-wide pools keep that bound across sandbox restarts.

use std::io;
use std::sync::{Arc, OnceLock};

use tokio::runtime::{Builder, Runtime};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

struct BlockingPool {
    runtime: Option<Runtime>,
    slots: Arc<Semaphore>,
}

impl BlockingPool {
    fn new(name: &str, capacity: usize) -> io::Result<Self> {
        let runtime = Builder::new_current_thread()
            .max_blocking_threads(capacity)
            .thread_name(name)
            .build()?;
        Ok(Self {
            runtime: Some(runtime),
            slots: Arc::new(Semaphore::new(capacity)),
        })
    }

    fn spawn<F, T>(&self, work: F) -> io::Result<JoinHandle<T>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))?;
        Ok(self.runtime.as_ref().unwrap().spawn_blocking(move || {
            let _permit = permit;
            work()
        }))
    }
}

impl Drop for BlockingPool {
    fn drop(&mut self) {
        self.slots.close();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

fn pool(
    storage: &'static OnceLock<io::Result<BlockingPool>>,
    name: &str,
    capacity: usize,
) -> io::Result<&'static BlockingPool> {
    storage
        .get_or_init(|| BlockingPool::new(name, capacity))
        .as_ref()
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

async fn run_on<F, T>(pool: io::Result<&BlockingPool>, work: F) -> io::Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    pool?.spawn(work)?.await.map_err(io::Error::other)
}

/// Run synchronous supervised work with bounded admission.
///
/// Saturation returns EAGAIN without executing the closure. A timeout or dropped
/// future stops waiting only; running work and its owned resources may outlive
/// the caller. Capture owners rather than borrowed fd numbers or pointers.
pub async fn run<F, T>(work: F) -> io::Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    static POOL: OnceLock<io::Result<BlockingPool>> = OnceLock::new();
    run_on(pool(&POOL, "sandlock-blocking", 64), work).await
}

pub(crate) async fn filesystem<F, T>(work: F) -> io::Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    // A stalled external peer must not occupy the workers needed by filesystem work.
    static POOL: OnceLock<io::Result<BlockingPool>> = OnceLock::new();
    run_on(pool(&POOL, "sandlock-filesystem", 16), work).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropped_waiter_keeps_running_work_admitted() {
        let pool = BlockingPool::new("blocking-test", 1).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let job = pool
            .spawn(move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
            })
            .unwrap();
        started_rx.await.unwrap();
        drop(job);
        let error = pool.spawn(|| ()).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
        release_tx.send(()).unwrap();
        let permit = Arc::clone(&pool.slots).acquire_owned().await.unwrap();
        drop(permit);
        assert_eq!(pool.spawn(|| 42).unwrap().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_for_running_work() {
        let pool = BlockingPool::new("blocking-shutdown-test", 1).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let job = pool
            .spawn(move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                42
            })
            .unwrap();
        started_rx.await.unwrap();
        drop(pool);
        release_tx.send(()).unwrap();
        assert_eq!(job.await.unwrap(), 42);
    }

    #[tokio::test]
    async fn panicking_work_releases_admission() {
        let pool = BlockingPool::new("blocking-panic-test", 1).unwrap();
        assert!(pool
            .spawn(|| panic!("worker panic"))
            .unwrap()
            .await
            .unwrap_err()
            .is_panic());
        assert_eq!(pool.spawn(|| 42).unwrap().await.unwrap(), 42);
    }
}
