//! The C ABI side of `BranchAction::Defer`: a handle that outlives its wait
//! holds the change set until `sandlock_handle_commit` / `_abort`.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::path::Path;
use std::ptr;

use sandlock_ffi::{
    sandlock_create_for_run, sandlock_handle_abort, sandlock_handle_commit, sandlock_handle_free,
    sandlock_handle_pending, sandlock_handle_upper_dir, sandlock_handle_wait,
    sandlock_result_change_entry, sandlock_result_change_path, sandlock_result_changes_len,
    sandlock_result_free, sandlock_result_success, sandlock_sandbox_build,
    sandlock_sandbox_builder_cwd, sandlock_sandbox_builder_fs_read,
    sandlock_sandbox_builder_fs_storage, sandlock_sandbox_builder_fs_write,
    sandlock_sandbox_builder_new, sandlock_sandbox_builder_on_exit,
    sandlock_sandbox_builder_workdir, sandlock_sandbox_free, sandlock_sandbox_t, sandlock_start,
    sandlock_string_free,
};

const DEFER: u8 = 3;

fn build_policy(workdir: &Path, storage: &Path, on_exit: u8) -> *mut sandlock_sandbox_t {
    let mut b = sandlock_sandbox_builder_new();
    for p in ["/usr", "/lib", "/lib64", "/bin", "/etc", "/proc"] {
        if p == "/lib64" && !Path::new("/lib64").exists() { continue; }
        let c = CString::new(p).unwrap();
        b = unsafe { sandlock_sandbox_builder_fs_read(b, c.as_ptr()) };
    }
    let wd = CString::new(workdir.to_str().unwrap()).unwrap();
    let st = CString::new(storage.to_str().unwrap()).unwrap();
    unsafe {
        b = sandlock_sandbox_builder_fs_write(b, wd.as_ptr());
        b = sandlock_sandbox_builder_workdir(b, wd.as_ptr());
        b = sandlock_sandbox_builder_cwd(b, wd.as_ptr());
        b = sandlock_sandbox_builder_fs_storage(b, st.as_ptr());
        b = sandlock_sandbox_builder_on_exit(b, on_exit);
    }
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert_eq!(err, 0, "policy build failed");
    policy
}

fn argv(cmd: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    (owned, ptrs)
}

fn run_deferred(workdir: &Path, storage: &Path) -> *mut sandlock_ffi::sandlock_handle_t {
    let policy = build_policy(workdir, storage, DEFER);
    let (_owned, av) = argv(&["sh", "-c", "echo hi > out.txt"]);
    let h = unsafe { sandlock_create_for_run(policy, ptr::null(), av.as_ptr(), av.len() as c_uint) };
    unsafe { sandlock_sandbox_free(policy) };
    assert!(!h.is_null(), "create failed");
    assert_eq!(unsafe { sandlock_start(h) }, 0);
    let r = unsafe { sandlock_handle_wait(h) };
    assert!(!r.is_null(), "wait failed");
    assert!(unsafe { sandlock_result_success(r) });

    assert_eq!(unsafe { sandlock_result_changes_len(r) }, 1);
    let mut out = sandlock_ffi::sandlock_entry_t {
        kind: sandlock_ffi::sandlock_entry_kind_t::File, mode: 0, size: 0, has_digest: 0, digest: [0; 32],
    };
    assert_eq!(unsafe { sandlock_result_change_entry(r, 0, sandlock_ffi::SANDLOCK_CHANGE_BEFORE, &mut out) }, 1);
    assert_eq!(unsafe { sandlock_result_change_entry(r, 0, sandlock_ffi::SANDLOCK_CHANGE_AFTER, &mut out) }, 0);
    let p = unsafe { sandlock_result_change_path(r, 0) };
    assert_eq!(unsafe { CStr::from_ptr(p) }.to_str().unwrap(), "out.txt");
    unsafe { sandlock_string_free(p) };
    unsafe { sandlock_result_free(r) };
    h
}

#[test]
fn deferred_handle_commits_on_request() {
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let h = run_deferred(workdir.path(), storage.path());

    assert_eq!(unsafe { sandlock_handle_pending(h) }, 1);
    let upper = unsafe { sandlock_handle_upper_dir(h) };
    assert!(!upper.is_null());
    let upper_path = unsafe { CStr::from_ptr(upper) }.to_str().unwrap().to_string();
    unsafe { sandlock_string_free(upper) };
    assert_eq!(std::fs::read_to_string(Path::new(&upper_path).join("out.txt")).unwrap(), "hi\n");
    assert!(!workdir.path().join("out.txt").exists());

    assert_eq!(unsafe { sandlock_handle_commit(h) }, 0);
    assert_eq!(unsafe { sandlock_handle_pending(h) }, 0);
    assert!(unsafe { sandlock_handle_upper_dir(h) }.is_null());
    assert_eq!(std::fs::read_to_string(workdir.path().join("out.txt")).unwrap(), "hi\n");
    assert_ne!(unsafe { sandlock_handle_commit(h) }, 0, "nothing left to commit");
    unsafe { sandlock_handle_free(h) };
}

#[test]
fn deferred_handle_aborts_on_request() {
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let h = run_deferred(workdir.path(), storage.path());

    assert_eq!(unsafe { sandlock_handle_abort(h) }, 0);
    assert_eq!(unsafe { sandlock_handle_pending(h) }, 0);
    assert!(!workdir.path().join("out.txt").exists());
    unsafe { sandlock_handle_free(h) };
    assert!(sandlock_core::list_preserved(storage.path()).is_empty());
}

#[test]
fn freeing_a_pending_handle_preserves_the_branch() {
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let h = run_deferred(workdir.path(), storage.path());
    unsafe { sandlock_handle_free(h) };

    assert!(!workdir.path().join("out.txt").exists());
    let preserved = sandlock_core::list_preserved(storage.path());
    assert_eq!(preserved.len(), 1);
    assert_eq!(preserved[0].reason, sandlock_core::PreserveReason::Kept);
}

#[test]
fn a_committing_handle_is_never_pending() {
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let policy = build_policy(workdir.path(), storage.path(), 0);
    let (_owned, av) = argv(&["sh", "-c", "echo hi > out.txt"]);
    let h = unsafe { sandlock_create_for_run(policy, ptr::null(), av.as_ptr(), av.len() as c_uint) };
    unsafe { sandlock_sandbox_free(policy) };
    assert_eq!(unsafe { sandlock_start(h) }, 0);
    let r = unsafe { sandlock_handle_wait(h) };
    assert!(unsafe { sandlock_result_success(r) });
    assert_eq!(unsafe { sandlock_result_changes_len(r) }, 1);
    unsafe { sandlock_result_free(r) };

    assert_eq!(unsafe { sandlock_handle_pending(h) }, 0);
    assert_ne!(unsafe { sandlock_handle_abort(h) }, 0);
    assert_eq!(std::fs::read_to_string(workdir.path().join("out.txt")).unwrap(), "hi\n");
    unsafe { sandlock_handle_free(h) };
}
