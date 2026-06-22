//! SCM_RIGHTS file-descriptor passing over the supervisor control socket.
//!
//! `exec` is the only control command that carries open fds (the CLI's
//! stdin/stdout/stderr, which the container shim wired to the exec stream).
//! The daemon must receive those fds with the SAME `recvmsg` that reads the
//! command bytes, because ancillary data binds to specific bytes. All other
//! commands send an empty ancillary payload, so the receive path is uniform.

use std::io;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};

/// Send `data` plus `fds` (as SCM_RIGHTS) over a blocking unix socket.
pub fn send_with_fds(
    stream: &std::os::unix::net::UnixStream,
    data: &[u8],
    fds: &[RawFd],
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let fds_bytes = std::mem::size_of_val(fds) as u32;
    let cmsg_space = if fds.is_empty() {
        0usize
    } else {
        unsafe { libc::CMSG_SPACE(fds_bytes) as usize }
    };
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fds_bytes) as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr(),
                libc::CMSG_DATA(cmsg) as *mut RawFd,
                fds.len(),
            );
        }
    }

    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive bytes plus up to `max_fds` SCM_RIGHTS fds from a raw socket fd
/// (one `recvmsg`). Returns the data and any received `OwnedFd`s.
pub fn recv_with_fds(fd: RawFd, max_fds: usize) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; 8192];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let cmsg_space =
        unsafe { libc::CMSG_SPACE((max_fds * std::mem::size_of::<RawFd>()) as u32) as usize };
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut fds = Vec::new();
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = payload / std::mem::size_of::<RawFd>();
                let data_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
                for i in 0..count {
                    fds.push(OwnedFd::from_raw_fd(*data_ptr.add(i)));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    buf.truncate(n as usize);
    Ok((buf, fds))
}

/// Tokio wrapper: await readability, then one `recv_with_fds` on the raw fd.
/// `recvmsg` returns `EAGAIN` (`WouldBlock`) if the socket was not actually
/// ready; loop until it yields data.
pub async fn recv_with_fds_async(
    stream: &tokio::net::UnixStream,
    max_fds: usize,
) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    use std::os::unix::io::AsRawFd;
    loop {
        stream.readable().await?;
        match stream.try_io(tokio::io::Interest::READABLE, || {
            recv_with_fds(stream.as_raw_fd(), max_fds)
        }) {
            Ok(res) => return Ok(res),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    /// Send a pipe's write-end across a socketpair, then prove the received fd
    /// is the SAME open file: writing through it is readable from the original
    /// read-end.
    #[test]
    fn send_and_recv_one_fd_roundtrip() {
        let (a, b) = UnixStream::pair().unwrap();

        // A pipe whose write end we will pass over the socket.
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (pipe_r, pipe_w) = (fds[0], fds[1]);

        send_with_fds(&a, b"PING", &[pipe_w]).unwrap();
        let (data, got) = recv_with_fds(b.as_raw_fd(), 3).unwrap();

        assert_eq!(&data, b"PING");
        assert_eq!(got.len(), 1);

        // Write through the RECEIVED fd, read from the original pipe read end.
        let received_w = got[0].as_raw_fd();
        assert_eq!(unsafe { libc::write(received_w, b"Z".as_ptr() as *const _, 1) }, 1);
        let mut buf = [0u8; 1];
        assert_eq!(unsafe { libc::read(pipe_r, buf.as_mut_ptr() as *mut _, 1) }, 1);
        assert_eq!(buf[0], b'Z');

        unsafe { libc::close(pipe_r); libc::close(pipe_w); }
        let _ = (a, b);
    }

    #[test]
    fn recv_without_fds_returns_empty_vec() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"hello").unwrap();
        let (data, got) = recv_with_fds(b.as_raw_fd(), 3).unwrap();
        assert_eq!(&data, b"hello");
        assert!(got.is_empty());
    }
}
