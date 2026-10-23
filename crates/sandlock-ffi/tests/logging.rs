//! The C log sink receives the library's diagnostics instead of stderr.

use std::ffi::{c_char, c_void, CStr};
use std::ptr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::Duration;

use sandlock_ffi::logging::{sandlock_set_logger, SANDLOCK_LOG_ERROR, SANDLOCK_LOG_INFO};
use sandlock_ffi::sandlock_popen;

static RECORDS: Mutex<Option<Sender<(u32, String)>>> = Mutex::new(None);

unsafe extern "C" fn record(level: u32, message: *const c_char, _: *mut c_void) {
    let message = CStr::from_ptr(message).to_string_lossy().into_owned();
    if let Some(tx) = RECORDS.lock().unwrap().as_ref() {
        let _ = tx.send((level, message));
    }
}

fn reject_stdio() {
    let h = unsafe {
        sandlock_popen(
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            7,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert!(h.is_null());
}

fn next(rx: &Receiver<(u32, String)>) -> Option<(u32, String)> {
    rx.recv_timeout(Duration::from_secs(2)).ok()
}

// One test: the logger is process-wide, so parallel tests would race on it.
#[test]
fn diagnostics_reach_the_sink_until_it_is_removed() {
    let (tx, rx) = channel();
    *RECORDS.lock().unwrap() = Some(tx);

    reject_stdio();
    assert_eq!(
        unsafe { sandlock_set_logger(Some(record), SANDLOCK_LOG_INFO, ptr::null_mut()) },
        0
    );
    reject_stdio();
    let (level, message) = next(&rx).expect("an error record");
    assert_eq!(level, SANDLOCK_LOG_ERROR);
    assert!(message.contains("unknown StdioMode"), "got: {message}");
    assert!(!message.starts_with("sandlock:"), "got: {message}");

    assert_eq!(
        unsafe { sandlock_set_logger(Some(record), 0, ptr::null_mut()) },
        0
    );
    reject_stdio();
    assert_eq!(
        unsafe { sandlock_set_logger(None, SANDLOCK_LOG_INFO, ptr::null_mut()) },
        0
    );
    reject_stdio();
    assert_eq!(
        next(&rx),
        None,
        "a silenced or removed sink must get nothing"
    );
}
