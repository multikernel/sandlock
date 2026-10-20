use std::ffi::{c_void, CString};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use sandlock_ffi::{
    sandlock_approval_free, sandlock_approval_is_cancelled, sandlock_approval_resolve,
    sandlock_approval_t, sandlock_ctx_t, sandlock_event_t, sandlock_result_free,
    sandlock_result_success, sandlock_run, sandlock_sandbox_build,
    sandlock_sandbox_builder_fs_read, sandlock_sandbox_builder_new,
    sandlock_sandbox_builder_policy_fn, sandlock_sandbox_builder_policy_fn_deferred,
    sandlock_sandbox_free, SANDLOCK_EVENT_ALL,
};

static DROP_COUNT: AtomicUsize = AtomicUsize::new(0);
const USER_DATA_TOKEN: usize = 0x5150;

unsafe extern "C" fn policy_callback(
    _event: *const sandlock_event_t,
    _ctx: *mut sandlock_ctx_t,
    user_data: *mut c_void,
) -> i32 {
    assert_eq!(user_data as usize, USER_DATA_TOKEN);
    0
}

unsafe extern "C" fn drop_user_data(user_data: *mut c_void) {
    assert_eq!(user_data as usize, USER_DATA_TOKEN);
    DROP_COUNT.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn policy_fn_user_data_drop_fires_on_policy_free() {
    DROP_COUNT.store(0, Ordering::SeqCst);

    let mut builder = sandlock_sandbox_builder_new();
    builder = unsafe {
        sandlock_sandbox_builder_policy_fn(
            builder,
            policy_callback,
            5000,
            SANDLOCK_EVENT_ALL,
            USER_DATA_TOKEN as *mut c_void,
            Some(drop_user_data),
        )
    };

    let mut err = 0;
    let policy = unsafe { sandlock_sandbox_build(builder, &mut err, ptr::null_mut()) };
    assert!(!policy.is_null(), "build failed with err={err}");
    assert_eq!(DROP_COUNT.load(Ordering::SeqCst), 0);

    unsafe { sandlock_sandbox_free(policy) };
    assert_eq!(DROP_COUNT.load(Ordering::SeqCst), 1);
}

struct Approver {
    tx: std::sync::Mutex<std::sync::mpsc::Sender<usize>>,
}

unsafe extern "C" fn deferred_callback(
    _event: *const sandlock_event_t,
    _ctx: *mut sandlock_ctx_t,
    approval: *mut sandlock_approval_t,
    user_data: *mut c_void,
) {
    if !approval.is_null() {
        let approver = &*(user_data as *const Approver);
        approver.tx.lock().unwrap().send(approval as usize).unwrap();
    }
}

unsafe extern "C" fn drop_approver(user_data: *mut c_void) {
    drop(Box::from_raw(user_data as *mut Approver));
}

/// Answers every approval from another thread after the callback returned:
/// `Some(verdict)` resolves, `None` frees it unresolved.
fn run_with_approver(verdict: Option<i32>) -> bool {
    let (tx, rx) = std::sync::mpsc::channel::<usize>();
    let approver = Box::into_raw(Box::new(Approver {
        tx: std::sync::Mutex::new(tx),
    }));
    let resolver = std::thread::spawn(move || {
        for approval in rx {
            let approval = approval as *mut sandlock_approval_t;
            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(!unsafe { sandlock_approval_is_cancelled(approval) });
            match verdict {
                Some(v) => unsafe { sandlock_approval_resolve(approval, v) },
                None => unsafe { sandlock_approval_free(approval) },
            }
        }
    });

    let mut b = sandlock_sandbox_builder_new();
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc"] {
        if !std::path::Path::new(p).exists() {
            continue;
        }
        let c = CString::new(p).unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    b = unsafe {
        sandlock_sandbox_builder_policy_fn_deferred(
            b,
            deferred_callback,
            5000,
            SANDLOCK_EVENT_ALL,
            approver as *mut c_void,
            Some(drop_approver),
        )
    };
    let mut err = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert!(!policy.is_null(), "build failed with err={err}");

    let cmd = CString::new("/bin/true").unwrap();
    let argv = [cmd.as_ptr()];
    let result = unsafe { sandlock_run(policy, ptr::null(), argv.as_ptr(), 1) };
    let success = !result.is_null() && unsafe { sandlock_result_success(result) };
    unsafe {
        sandlock_result_free(result);
        sandlock_sandbox_free(policy);
    }
    resolver.join().unwrap();
    success
}

#[test]
fn deferred_approval_resolved_from_another_thread() {
    assert!(run_with_approver(Some(0)));
}

#[test]
fn deferred_approval_denies_with_errno_or_when_freed() {
    assert!(!run_with_approver(Some(13)));
    assert!(!run_with_approver(None));
}
