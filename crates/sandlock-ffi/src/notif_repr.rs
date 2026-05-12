//! `repr(C)` snapshot of a `SeccompNotif`. The C side reads this struct
//! by value; no pointers into Rust memory live past the callback return.

use sandlock_core::SeccompNotif;

/// Stable wire-layout snapshot of a seccomp notification.
///
/// Field order, types, and padding must match `sandlock.h` exactly. The
/// size assertion in `tests/handler_smoke.rs` guards against accidental
/// drift; if a new field is added, bump the documented size and update
/// the C header in the same commit.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct sandlock_notif_data_t {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub syscall_nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl From<&SeccompNotif> for sandlock_notif_data_t {
    fn from(n: &SeccompNotif) -> Self {
        Self {
            id: n.id,
            pid: n.pid,
            flags: n.flags,
            syscall_nr: n.data.nr,
            arch: n.data.arch,
            instruction_pointer: n.data.instruction_pointer,
            args: n.data.args,
        }
    }
}
