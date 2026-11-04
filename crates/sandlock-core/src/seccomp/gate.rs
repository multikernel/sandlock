//! Orders off-loop writes to child memory against execve argv validation.
//!
//! Parked work runs with its sandbox's gate installed, and every write to
//! child memory holds the shared side for that one write. The exec freeze
//! holds the exclusive side, so no parked write can land on a peer's argv
//! between its validation and the kernel copying it.

use std::cell::RefCell;
use std::future::Future;
use std::sync::{Arc, RwLock, RwLockWriteGuard};

#[derive(Clone, Default)]
pub(crate) struct MemGate(Arc<RwLock<()>>);

tokio::task_local! {
    static TASK_GATE: MemGate;
}

thread_local! {
    static THREAD_GATE: RefCell<Option<MemGate>> = const { RefCell::new(None) };
}

impl MemGate {
    /// Writes only hold the shared side for a single copy, so this waits
    /// microseconds, never for parked work to finish.
    pub(crate) fn exclusive(&self) -> RwLockWriteGuard<'_, ()> {
        self.0.write().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) async fn scope<F: Future>(self, future: F) -> F::Output {
        TASK_GATE.scope(self, future).await
    }

    pub(crate) fn enter<T>(self, work: impl FnOnce() -> T) -> T {
        let previous = THREAD_GATE.with(|gate| gate.replace(Some(self)));
        let result = work();
        THREAD_GATE.with(|gate| *gate.borrow_mut() = previous);
        result
    }
}

/// Run one write to child memory under the installed gate, if any. The
/// notification loop installs none: nothing else runs on it during a freeze.
pub(crate) fn write<T>(work: impl FnOnce() -> T) -> T {
    let gate = TASK_GATE
        .try_with(MemGate::clone)
        .ok()
        .or_else(|| THREAD_GATE.with(|gate| gate.borrow().clone()));
    match gate {
        Some(gate) => {
            let _shared = gate.0.read().unwrap_or_else(|e| e.into_inner());
            work()
        }
        None => work(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exclusive_waits_for_a_write_in_progress() {
        let gate = MemGate::default();
        let (writing_tx, writing_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn({
            let gate = gate.clone();
            move || {
                gate.enter(|| {
                    write(|| {
                        writing_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                    })
                })
            }
        });
        writing_rx.recv().unwrap();
        assert!(gate.0.try_write().is_err());
        release_tx.send(()).unwrap();
        writer.join().unwrap();
        drop(gate.exclusive());
    }

    #[tokio::test]
    async fn parked_futures_write_under_the_gate() {
        let gate = MemGate::default();
        let held = gate.clone();
        gate.scope(async move {
            write(|| assert!(held.0.try_write().is_err()));
        })
        .await;
    }

    #[test]
    fn writes_outside_parked_work_are_ungated() {
        let gate = MemGate::default();
        let _exclusive = gate.exclusive();
        write(|| ());
    }
}
