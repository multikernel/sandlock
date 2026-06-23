use std::os::unix::io::RawFd;

/// Blocking recvmsg of one message plus up to `max_fds` SCM_RIGHTS fds.
/// Returns (bytes, fds). Empty bytes means EOF/peer closed.
pub fn recv(fd: RawFd, max_fds: usize) -> std::io::Result<(Vec<u8>, Vec<RawFd>)> {
    let mut buf = vec![0u8; 65536];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
    let space = unsafe { libc::CMSG_SPACE((max_fds * 4) as u32) as usize };
    let mut cbuf = vec![0u8; space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = space as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 { return Err(std::io::Error::last_os_error()); }
    let mut fds = Vec::new();
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let p = libc::CMSG_DATA(c) as *const RawFd;
                for i in 0..(payload / 4) { fds.push(*p.add(i)); }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    buf.truncate(n as usize);
    Ok((buf, fds))
}
