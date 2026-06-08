use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use sandlock_ffi::{
    sandlock_ctx_t, sandlock_event_t, sandlock_sandbox_build, sandlock_sandbox_builder_new,
    sandlock_sandbox_builder_policy_fn, sandlock_sandbox_free,
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
