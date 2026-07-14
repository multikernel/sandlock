//! Supervisor-side userfaultfd page server. After the restore-stub registers its
//! anonymous checkpoint regions with a userfaultfd and hands the fd to the
//! supervisor (via pidfd_getfd), this loop resolves each missing-page fault by
//! UFFDIO_COPY-ing the page from the in-memory image. Only the anonymous working
//! set flows through here; file-backed regions are kernel-paged.
//!
//! The userfaultfd MUST be created with O_NONBLOCK: poll()/epoll on a blocking
//! userfaultfd always reports POLLERR (never POLLIN), so a polling pager would
//! spin without ever reading a fault. The stub creates it O_CLOEXEC|O_NONBLOCK
//! with a plain -> UFFD_USER_MODE_ONLY fallback (hosts with
//! vm.unprivileged_userfaultfd=0 reject the plain form). USER_MODE_ONLY serves
//! only user-mode faults; full-fidelity paging of real programs (kernel-mode
//! faults from syscalls touching unfilled pages) requires
//! vm.unprivileged_userfaultfd=1 on the node.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

// userfaultfd ioctl request codes (x86_64 _IOWR(0xAA, n, struct)).
const UFFDIO_API: libc::c_ulong = 0xc018_aa3f;
const UFFDIO_REGISTER: libc::c_ulong = 0xc020_aa00;
const UFFDIO_COPY: libc::c_ulong = 0xc028_aa03;
const UFFD_API: u64 = 0xAA;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;

#[repr(C)]
struct UffdioApi { api: u64, features: u64, ioctls: u64 }
#[repr(C)]
struct UffdioRange { start: u64, len: u64 }
#[repr(C)]
struct UffdioRegister { range: UffdioRange, mode: u64, ioctls: u64 }
#[repr(C)]
struct UffdioCopy { dst: u64, src: u64, len: u64, mode: u64, copy: i64 }

// struct uffd_msg is 32 bytes; we only need the fault address at offset 16.
#[repr(C)]
struct UffdMsg { event: u8, _pad: [u8; 7], arg: [u64; 3] }

/// In-memory source for the anon working set: `(start, end, bytes)` runs.
#[derive(Clone)]
pub(crate) struct PageImage {
    pub regions: Vec<(u64, u64, Vec<u8>)>,
}

impl PageImage {
    /// The `page`-aligned slice of length `page` covering `addr`, or `None`.
    pub(crate) fn page_at(&self, addr: u64, page: usize) -> Option<&[u8]> {
        let base = addr & !((page as u64) - 1);
        for (start, end, bytes) in &self.regions {
            if base >= *start && base + page as u64 <= *end {
                let off = (base - *start) as usize;
                return Some(&bytes[off..off + page]);
            }
        }
        None
    }
}

/// Enable the uffd API and register `[start, start+len)` in missing mode.
/// Used by the pager unit test to stand in for the stub.
pub(crate) fn register_api_and_range(uffd: i32, start: u64, len: u64) -> io::Result<()> {
    let mut api = UffdioApi { api: UFFD_API, features: 0, ioctls: 0 };
    if unsafe { libc::ioctl(uffd, UFFDIO_API, &mut api) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut reg = UffdioRegister {
        range: UffdioRange { start, len },
        mode: UFFDIO_REGISTER_MODE_MISSING,
        ioctls: 0,
    };
    if unsafe { libc::ioctl(uffd, UFFDIO_REGISTER, &mut reg) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn copy_page(uffd: i32, image: &PageImage, addr: u64, page: usize) -> io::Result<()> {
    let base = addr & !((page as u64) - 1);
    let src = match image.page_at(addr, page) {
        Some(s) => s,
        None => {
            // Nothing to serve: zero-fill so the faulting thread makes progress
            // rather than hanging. (Restore images always cover their faults.)
            let zero = vec![0u8; page];
            let mut c = UffdioCopy {
                dst: base, src: zero.as_ptr() as u64, len: page as u64, mode: 0, copy: 0,
            };
            if unsafe { libc::ioctl(uffd, UFFDIO_COPY, &mut c) } < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(());
        }
    };
    let mut c = UffdioCopy {
        dst: base, src: src.as_ptr() as u64, len: page as u64, mode: 0, copy: 0,
    };
    if unsafe { libc::ioctl(uffd, UFFDIO_COPY, &mut c) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn poll_once(uffd: i32, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd { fd: uffd, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted { return Ok(false); }
        return Err(e);
    }
    Ok(n > 0 && (pfd.revents & libc::POLLIN) != 0)
}

fn handle_ready(uffd: i32, image: &PageImage) -> io::Result<bool> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let mut msg = UffdMsg { event: 0, _pad: [0; 7], arg: [0; 3] };
    let n = unsafe {
        libc::read(uffd, &mut msg as *mut _ as *mut libc::c_void,
                   std::mem::size_of::<UffdMsg>())
    };
    if n == 0 { return Ok(false); } // EOF: all handles closed
    if n < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock { return Ok(true); }
        return Err(e);
    }
    if msg.event == UFFD_EVENT_PAGEFAULT {
        // struct uffd_msg: 8-byte header (event+reserved), then the pagefault
        // arm { u64 flags; u64 address; ... }. With the 8-byte header the fault
        // address is the SECOND u64 of `arg` (byte offset 16), not the third.
        let addr = msg.arg[1];
        copy_page(uffd, image, addr, page)?;
    }
    Ok(true)
}

/// Poll/serve until the uffd reports all handles closed (EOF).
pub(crate) fn serve(uffd: i32, image: &PageImage) -> io::Result<()> {
    loop {
        if poll_once(uffd, -1)? {
            if !handle_ready(uffd, image)? { return Ok(()); }
        }
    }
}

/// Poll/serve until `stop` is set. Uses a short poll timeout so it observes the
/// flag promptly even with no faults arriving.
pub(crate) fn serve_until(uffd: i32, image: &PageImage, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        match poll_once(uffd, 20) {
            Ok(true) => { let _ = handle_ready(uffd, image); }
            Ok(false) => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_at_returns_aligned_slice_within_run() {
        let img = PageImage {
            regions: vec![(0x1000, 0x3000, {
                let mut v = vec![0u8; 0x2000];
                // second page all 0xAB
                for b in &mut v[0x1000..0x2000] { *b = 0xAB; }
                v
            })],
        };
        let page = 0x1000usize;
        // An address in the second page returns that page, all 0xAB.
        let s = img.page_at(0x2500, page).expect("covered");
        assert_eq!(s.len(), page);
        assert!(s.iter().all(|&b| b == 0xAB));
        // Out of range.
        assert!(img.page_at(0x9000, page).is_none());
    }

    #[test]
    fn serve_copies_faulted_page_into_a_registered_region() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let page = 4096usize;
        // Map an anon region we will register with uffd in THIS process.
        let len = page;
        let addr = unsafe {
            libc::mmap(std::ptr::null_mut(), len,
                       libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(addr, libc::MAP_FAILED);
        let start = addr as u64;

        // O_NONBLOCK is mandatory: poll()/epoll on a *blocking* userfaultfd always
        // returns POLLERR (never POLLIN), so the pager would spin forever. And
        // vm.unprivileged_userfaultfd=0 rejects plain userfaultfd(); UFFD_USER_MODE_ONLY
        // (0x1) is permitted unprivileged and handles user-mode faults, which is all
        // this test triggers.
        const UFFD_USER_MODE_ONLY: libc::c_int = 1;
        let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
        let uffd = {
            let plain = unsafe { libc::syscall(libc::SYS_userfaultfd, flags) } as i32;
            if plain >= 0 {
                plain
            } else {
                (unsafe {
                    libc::syscall(libc::SYS_userfaultfd, flags | UFFD_USER_MODE_ONLY)
                }) as i32
            }
        };
        assert!(uffd >= 0, "userfaultfd (tried plain then USER_MODE_ONLY)");
        register_api_and_range(uffd, start, len as u64).expect("register");

        let img = PageImage { regions: vec![(start, start + len as u64, vec![0x5Au8; len])] };
        let stop = Arc::new(AtomicBool::new(false));

        // Pager on another thread.
        let stop2 = stop.clone();
        let uffd_copy = uffd;
        let img_copy = img.clone();
        let h = std::thread::spawn(move || serve_until(uffd_copy, &img_copy, &stop2));

        // Touch the page -> fault -> pager fills with 0x5A.
        let byte = unsafe { std::ptr::read_volatile(addr as *const u8) };
        assert_eq!(byte, 0x5A, "faulted page must be filled by the pager");

        stop.store(true, Ordering::SeqCst);
        // Nudge the poll loop so it observes `stop` (write a dummy fault by
        // touching another registered page is unnecessary; serve_until uses a
        // short poll timeout).
        let _ = h.join();
        unsafe { libc::munmap(addr, len); }
    }
}
