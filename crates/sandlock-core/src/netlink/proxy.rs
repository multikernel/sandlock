//! Async responder that speaks synthesized NETLINK_ROUTE over a unix
//! `SOCK_SEQPACKET` socketpair. The child process holds one end; this
//! task owns the other and runs on the supervisor's tokio runtime —
//! same runtime as the seccomp-notify dispatcher and the HTTP ACL proxy.
//!
//! Loop:
//!   await readable on the supervisor-side fd
//!   recv one datagram (request)
//!   parse → synthesize reply datagrams → concatenate → send
//!   on EOF (child closed), exit
//!
//! Task lifetime is bounded by the supervisor's tokio runtime: when the
//! sandbox shuts down and the runtime is dropped, every in-flight
//! responder task is cancelled. No OS threads and no explicit shutdown
//! handle are needed.

use std::os::unix::io::{AsRawFd, OwnedFd};

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::netlink::{proto, synth};

const RECV_BUF: usize = 8192;

/// Spawn the responder task for a newly-created cookie fd.  The task
/// takes ownership of `fd`; the caller must not use it further.
///
/// `reply_pid` is the Linux pid of the sandboxed process, used as the
/// `nlmsg_pid` field in reply messages so glibc accepts them.
///
/// Must be called from within the supervisor's tokio runtime (all
/// seccomp-notify handlers satisfy this). The supervisor-side fd must
/// be non-blocking; see `handle_socket` for the `F_SETFL` call.
pub fn spawn_responder(fd: OwnedFd, reply_pid: u32) {
    tokio::spawn(async move {
        if let Err(e) = responder_loop(fd, reply_pid).await {
            eprintln!("sandlock netlink responder error: {e}");
        }
    });
}

async fn responder_loop(fd: OwnedFd, reply_pid: u32) -> std::io::Result<()> {
    let async_fd = AsyncFd::with_interest(fd, Interest::READABLE)?;
    let mut buf = vec![0u8; RECV_BUF];

    loop {
        let mut guard = async_fd.readable().await?;
        let raw = guard.get_inner().as_raw_fd();
        let n = match guard.try_io(|_| {
            let ret = unsafe {
                libc::recv(raw, buf.as_mut_ptr() as *mut _, buf.len(), 0)
            };
            if ret < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        }) {
            Ok(Ok(n)) => n,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        };
        if n == 0 {
            return Ok(());
        }

        let req = match proto::parse_request(&buf[..n]) {
            Some(r) => r,
            None => continue,
        };

        // Pack all reply messages for this request into a single
        // datagram. glibc's dump reader walks the recvmsg buffer
        // looking for NLMSG_DONE, so keeping everything in one send
        // is simpler and matches the common kernel behavior for
        // small dumps.
        let reply: Vec<u8> = synth::synthesize_reply(&req, reply_pid)
            .into_iter()
            .flatten()
            .collect();

        // The supervisor-side fd is non-blocking, but the kernel
        // socket buffer is large enough for any reply we produce
        // (< 64 KB for the biggest synthetic dump we'd ever make),
        // so send() never returns EAGAIN in practice. If it ever
        // does, we'd need to wait for writability too.
        let sent = unsafe {
            libc::send(
                raw,
                reply.as_ptr() as *const _,
                reply.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
}
