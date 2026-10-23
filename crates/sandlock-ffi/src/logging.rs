//! Route the library's diagnostics to a host callback, never to stderr.

use std::ffi::{c_char, c_int, c_void, CString};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Mutex, OnceLock, PoisonError};

/// `level` of an error record, and the `max_level` that keeps only errors.
pub const SANDLOCK_LOG_ERROR: u32 = 1;
/// `level` of a warning record.
pub const SANDLOCK_LOG_WARN: u32 = 2;
/// `level` of an informational record.
pub const SANDLOCK_LOG_INFO: u32 = 3;
/// `level` of a debug record.
pub const SANDLOCK_LOG_DEBUG: u32 = 4;
/// `level` of a trace record.
pub const SANDLOCK_LOG_TRACE: u32 = 5;

/// C log sink. `level` is a `SANDLOCK_LOG_*` value; `message` is UTF-8 and
/// valid only for the call.
#[allow(non_camel_case_types)]
pub type sandlock_log_fn_t =
    unsafe extern "C" fn(level: u32, message: *const c_char, user_data: *mut c_void);

// Records reach the sink through a bounded queue drained by one thread, so a
// slow host logger never stalls the supervisor answering the child's syscalls.
const QUEUE_DEPTH: usize = 256;

type Record = (u32, CString);

struct Sink {
    cb: sandlock_log_fn_t,
    user_data: *mut c_void,
}

// SAFETY: the caller of `sandlock_set_logger` promises `user_data` may be used
// from the drain thread until the sink is replaced.
unsafe impl Send for Sink {}

static SINK: Mutex<Option<Sink>> = Mutex::new(None);
static QUEUE: OnceLock<Option<SyncSender<Record>>> = OnceLock::new();

struct Forwarder;

impl log::Log for Forwarder {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().starts_with("sandlock") && metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let Some(queue) = QUEUE.get_or_init(spawn_drain) else {
            return;
        };
        let message = CString::new(record.args().to_string()).unwrap_or_default();
        let _ = queue.try_send((record.level() as u32, message));
    }

    fn flush(&self) {}
}

// Spawned on the first record rather than at install, so a host whose seccomp
// profile refuses new threads (#47) can still install a logger.
fn spawn_drain() -> Option<SyncSender<Record>> {
    let (tx, rx) = sync_channel(QUEUE_DEPTH);
    std::thread::Builder::new()
        .name("sandlock-log".into())
        .spawn(move || drain(rx))
        .ok()?;
    Some(tx)
}

fn drain(rx: Receiver<Record>) {
    for (level, message) in rx {
        let sink = SINK.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(sink) = sink.as_ref() {
            unsafe { (sink.cb)(level, message.as_ptr(), sink.user_data) };
        }
    }
}

fn level_filter(max_level: u32) -> log::LevelFilter {
    match max_level {
        0 => log::LevelFilter::Off,
        SANDLOCK_LOG_ERROR => log::LevelFilter::Error,
        SANDLOCK_LOG_WARN => log::LevelFilter::Warn,
        SANDLOCK_LOG_INFO => log::LevelFilter::Info,
        SANDLOCK_LOG_DEBUG => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

/// Send sandlock's diagnostics up to `max_level` (a `SANDLOCK_LOG_*` value, 0
/// for none) to `cb`, or stop sending them when `cb` is NULL. Without a
/// logger the library is silent. Records arrive on a sandlock thread and are
/// dropped while the sink falls behind. Returns 0, or `-EBUSY` when another
/// `log` logger already owns this process.
///
/// # Safety
/// `cb` must stay callable and `user_data` usable from another thread until a
/// later call replaces them; once that call returns, neither is used again.
/// `cb` must not call `sandlock_set_logger` and must not unwind.
#[no_mangle]
pub unsafe extern "C" fn sandlock_set_logger(
    cb: Option<unsafe extern "C" fn(level: u32, message: *const c_char, user_data: *mut c_void)>,
    max_level: u32,
    user_data: *mut c_void,
) -> c_int {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    if !*INSTALLED.get_or_init(|| log::set_logger(&Forwarder).is_ok()) {
        return -libc::EBUSY;
    }
    let mut sink = SINK.lock().unwrap_or_else(PoisonError::into_inner);
    *sink = cb.map(|cb| Sink { cb, user_data });
    log::set_max_level(if sink.is_some() {
        level_filter(max_level)
    } else {
        log::LevelFilter::Off
    });
    0
}
