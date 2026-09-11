//! The C ABI side of a change set: both sides of every change are
//! readable as plain scalars, plus a symlink target string.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::path::Path;
use std::ptr;

use sandlock_ffi::{
    sandlock_create_for_run, sandlock_entry_kind_t, sandlock_entry_t, sandlock_handle_free,
    sandlock_handle_wait,
    sandlock_result_change_entry, sandlock_result_change_kind, sandlock_result_change_path,
    sandlock_result_change_target, sandlock_result_changes_len, sandlock_result_free,
    sandlock_result_success, sandlock_sandbox_build, sandlock_sandbox_builder_cwd,
    sandlock_sandbox_builder_fs_read, sandlock_sandbox_builder_fs_storage,
    sandlock_sandbox_builder_fs_write, sandlock_sandbox_builder_new,
    sandlock_sandbox_builder_on_exit, sandlock_sandbox_builder_workdir, sandlock_sandbox_free,
    sandlock_sandbox_t, sandlock_start, sandlock_string_free, SANDLOCK_CHANGE_AFTER,
    SANDLOCK_CHANGE_BEFORE,
};

const ABORT: u8 = 1;
const BEFORE: c_int = SANDLOCK_CHANGE_BEFORE;
const AFTER: c_int = SANDLOCK_CHANGE_AFTER;
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn build_policy(workdir: &Path, storage: &Path) -> *mut sandlock_sandbox_t {
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
        b = sandlock_sandbox_builder_on_exit(b, ABORT);
    }
    let mut err: c_int = 0;
    let policy = unsafe { sandlock_sandbox_build(b, &mut err, ptr::null_mut()) };
    assert!(!policy.is_null(), "build failed: {err}");
    policy
}

fn argv(cmd: &[&str]) -> (Vec<CString>, Vec<*const c_char>) {
    let owned: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();
    let ptrs = owned.iter().map(|c| c.as_ptr()).collect();
    (owned, ptrs)
}

fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn entry(r: *const sandlock_ffi::sandlock_result_t, i: usize, side: c_int) -> Option<sandlock_entry_t> {
    let mut out = sandlock_entry_t { kind: sandlock_entry_kind_t::File, mode: 0, size: 0, has_digest: 0, digest: [0; 32] };
    match unsafe { sandlock_result_change_entry(r, i, side, &mut out) } {
        0 => Some(out),
        1 => None,
        rc => panic!("unexpected rc {rc}"),
    }
}

fn target(r: *const sandlock_ffi::sandlock_result_t, i: usize, side: c_int) -> Option<String> {
    let p = unsafe { sandlock_result_change_target(r, i, side) };
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
    unsafe { sandlock_string_free(p) };
    Some(s)
}

#[test]
fn both_sides_of_every_change_are_readable() {
    let workdir = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    std::fs::write(workdir.path().join("mod.txt"), "abc").unwrap();
    std::fs::write(workdir.path().join("gone.txt"), "abc").unwrap();
    std::os::unix::fs::symlink("a", workdir.path().join("link")).unwrap();

    let policy = build_policy(workdir.path(), storage.path());
    let (_owned, av) = argv(&[
        "sh", "-c",
        "echo new > added.txt && echo xyz > mod.txt && rm gone.txt && rm link && ln -s b link",
    ]);
    let h = unsafe { sandlock_create_for_run(policy, ptr::null(), av.as_ptr(), av.len() as c_uint) };
    unsafe { sandlock_sandbox_free(policy) };
    assert!(!h.is_null());
    assert_eq!(unsafe { sandlock_start(h) }, 0);
    let r = unsafe { sandlock_handle_wait(h) };
    assert!(unsafe { sandlock_result_success(r) });

    let n = unsafe { sandlock_result_changes_len(r) };
    let mut by_path = std::collections::BTreeMap::new();
    for i in 0..n {
        let p = unsafe { sandlock_result_change_path(r, i) };
        by_path.insert(unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string(), i);
        unsafe { sandlock_string_free(p) };
    }
    assert_eq!(by_path.keys().collect::<Vec<_>>(), vec!["added.txt", "gone.txt", "link", "mod.txt"]);

    let i = by_path["mod.txt"];
    assert_eq!(unsafe { sandlock_result_change_kind(r, i) } as u8, b'M');
    let before = entry(r, i, BEFORE).unwrap();
    let after = entry(r, i, AFTER).unwrap();
    assert_eq!(before.kind, sandlock_entry_kind_t::File);
    assert_eq!(before.size, 3);
    assert_eq!(before.has_digest, 1);
    assert_eq!(hex(&before.digest), SHA256_ABC);
    assert_eq!(after.size, 4);
    assert_ne!(after.digest, before.digest);

    let i = by_path["added.txt"];
    assert!(entry(r, i, BEFORE).is_none());
    assert_eq!(entry(r, i, AFTER).unwrap().size, 4);

    let i = by_path["gone.txt"];
    assert_eq!(hex(&entry(r, i, BEFORE).unwrap().digest), SHA256_ABC);
    assert!(entry(r, i, AFTER).is_none());

    let i = by_path["link"];
    assert_eq!(entry(r, i, BEFORE).unwrap().kind, sandlock_entry_kind_t::Symlink);
    assert_eq!(target(r, i, BEFORE).as_deref(), Some("a"));
    assert_eq!(target(r, i, AFTER).as_deref(), Some("b"));
    assert!(target(r, by_path["mod.txt"], AFTER).is_none());

    let mut out = sandlock_entry_t { kind: sandlock_entry_kind_t::File, mode: 0, size: 0, has_digest: 0, digest: [0; 32] };
    assert_eq!(unsafe { sandlock_result_change_entry(r, n, BEFORE, &mut out) }, -1);
    assert_eq!(unsafe { sandlock_result_change_entry(r, 0, 2, &mut out) }, -1);

    unsafe { sandlock_result_free(r) };
    unsafe { sandlock_handle_free(h) };
}
