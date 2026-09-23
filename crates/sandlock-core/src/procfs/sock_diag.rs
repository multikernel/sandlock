use std::collections::HashSet;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::netlink::proto::{
    nlmsg_align, NLMSG_DONE, NLMSG_ERROR, NLM_F_DUMP, NLM_F_MULTI, NLM_F_REQUEST,
};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_DUMP_INTR: u16 = 0x10;
const SEQUENCE: u32 = 1;
const UDIAG_SHOW_NAME: u32 = 1;

pub(super) struct InetRecord {
    pub cookie: u64,
    pub inode: u32,
    pub family: u8,
    pub state: u8,
    pub timer: u8,
    pub retransmits: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub local_address: [u8; 16],
    pub remote_address: [u8; 16],
    pub expires_ms: u32,
    pub rx_queue: u32,
    pub tx_queue: u32,
    pub uid: u32,
}

pub(super) struct UnixRecord {
    pub cookie: u64,
    pub inode: u32,
    pub kind: u8,
    pub state: u8,
    pub name: Vec<u8>,
}

pub(super) enum Record {
    Inet(InetRecord),
    Unix(UnixRecord),
}

impl Record {
    fn cookie(&self) -> u64 {
        match self {
            Self::Inet(record) => record.cookie,
            Self::Unix(record) => record.cookie,
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid socket diagnostic response",
    )
}

fn u16_at(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(invalid)?
            .try_into()
            .unwrap(),
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(invalid)?
            .try_into()
            .unwrap(),
    ))
}

fn cookie_at(bytes: &[u8], offset: usize) -> io::Result<u64> {
    Ok(u32_at(bytes, offset)? as u64 | ((u32_at(bytes, offset + 4)? as u64) << 32))
}

fn parse_record(bytes: &[u8], family: i32) -> io::Result<Record> {
    if bytes.first().copied() != Some(family as u8) {
        return Err(invalid());
    }
    if family == libc::AF_UNIX {
        if bytes.len() < 16 {
            return Err(invalid());
        }
        let mut name = Vec::new();
        let mut attrs = &bytes[16..];
        while !attrs.is_empty() {
            let len = u16_at(attrs, 0)? as usize;
            let kind = u16_at(attrs, 2)? & 0x3fff;
            if len < 4 || len > attrs.len() || nlmsg_align(len) > attrs.len() {
                return Err(invalid());
            }
            if kind == 0 {
                name = attrs[4..len].to_vec();
            }
            attrs = &attrs[nlmsg_align(len)..];
        }
        return Ok(Record::Unix(UnixRecord {
            cookie: cookie_at(bytes, 8)?,
            inode: u32_at(bytes, 4)?,
            kind: bytes[1],
            state: bytes[2],
            name,
        }));
    }
    if !matches!(family, libc::AF_INET | libc::AF_INET6) || bytes.len() < 72 {
        return Err(invalid());
    }
    Ok(Record::Inet(InetRecord {
        cookie: cookie_at(bytes, 44)?,
        inode: u32_at(bytes, 68)?,
        family: bytes[0],
        state: bytes[1],
        timer: bytes[2],
        retransmits: bytes[3],
        local_port: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
        remote_port: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
        local_address: bytes[8..24].try_into().unwrap(),
        remote_address: bytes[24..40].try_into().unwrap(),
        expires_ms: u32_at(bytes, 52)?,
        rx_queue: u32_at(bytes, 56)?,
        tx_queue: u32_at(bytes, 60)?,
        uid: u32_at(bytes, 64)?,
    }))
}

fn check_status(bytes: &[u8]) -> io::Result<()> {
    let status = u32_at(bytes, 0)? as i32;
    if status == 0 {
        Ok(())
    } else if (-4095..0).contains(&status) {
        Err(io::Error::from_raw_os_error(-status))
    } else {
        Err(invalid())
    }
}

fn parse_datagram(
    mut bytes: &[u8],
    family: i32,
    cookies: &HashSet<u64>,
    records: &mut Vec<Record>,
) -> io::Result<bool> {
    if bytes.is_empty() {
        return Err(invalid());
    }
    while !bytes.is_empty() {
        let len = u32_at(bytes, 0)? as usize;
        if len < 16 || len > bytes.len() || nlmsg_align(len) > bytes.len() {
            return Err(invalid());
        }
        let kind = u16_at(bytes, 4)?;
        let flags = u16_at(bytes, 6)?;
        if u32_at(bytes, 8)? != SEQUENCE {
            return Err(invalid());
        }
        if flags & NLM_F_DUMP_INTR != 0 {
            return Err(io::Error::from_raw_os_error(libc::EINTR));
        }
        let payload = &bytes[16..len];
        match kind {
            NLMSG_DONE => {
                check_status(payload)?;
                if nlmsg_align(len) != bytes.len() {
                    return Err(invalid());
                }
                return Ok(true);
            }
            NLMSG_ERROR => check_status(payload)?,
            SOCK_DIAG_BY_FAMILY if flags & NLM_F_MULTI != 0 => {
                let record = parse_record(payload, family)?;
                if cookies.contains(&record.cookie()) {
                    records.push(record);
                }
            }
            _ => return Err(invalid()),
        }
        bytes = &bytes[nlmsg_align(len)..];
    }
    Ok(false)
}

fn request(family: i32, protocol: i32) -> Vec<u8> {
    let mut payload = vec![0; if family == libc::AF_UNIX { 24 } else { 56 }];
    payload[0] = family as u8;
    payload[1] = protocol as u8;
    payload[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
    if family == libc::AF_UNIX {
        payload[12..16].copy_from_slice(&UDIAG_SHOW_NAME.to_ne_bytes());
        payload[16..24].fill(0xff);
    } else {
        payload[48..56].fill(0xff);
    }
    let mut bytes = Vec::with_capacity(16 + payload.len());
    bytes.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
    bytes.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    bytes.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    bytes.extend_from_slice(&SEQUENCE.to_ne_bytes());
    bytes.extend_from_slice(&0u32.to_ne_bytes());
    bytes.extend(payload);
    bytes
}

pub(super) fn dump(family: i32, protocol: i32, cookies: &HashSet<u64>) -> io::Result<Vec<Record>> {
    if cookies.is_empty() {
        return Ok(Vec::new());
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    let bytes = request(family, protocol);
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&kernel) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short socket diagnostic request",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buffer = vec![0u8; 65536];
    let mut records = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "socket diagnostic dump timed out",
            ));
        }
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
        msg.msg_namelen = std::mem::size_of_val(&sender) as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        let received = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || msg.msg_namelen as usize != std::mem::size_of_val(&sender)
            || sender.nl_family != libc::AF_NETLINK as u16
            || sender.nl_pid != 0
        {
            return Err(invalid());
        }
        if parse_datagram(&buffer[..received as usize], family, cookies, &mut records)? {
            return Ok(records);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_needs_no_diagnostic_support() {
        assert!(dump(libc::AF_UNSPEC, 0, &HashSet::new()).is_ok_and(|rows| rows.is_empty()));
        assert!(dump(libc::AF_UNSPEC, 0, &HashSet::from([7])).is_err());
    }

    fn message(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&1u32.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(payload);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    fn inet_payload(cookie: u64) -> Vec<u8> {
        let mut payload = vec![0; 72];
        payload[0] = libc::AF_INET as u8;
        payload[1] = 10;
        payload[4..6].copy_from_slice(&8080u16.to_be_bytes());
        payload[8..12].copy_from_slice(&[127, 0, 0, 1]);
        payload[44..48].copy_from_slice(&(cookie as u32).to_ne_bytes());
        payload[48..52].copy_from_slice(&((cookie >> 32) as u32).to_ne_bytes());
        payload[68..72].copy_from_slice(&123u32.to_ne_bytes());
        payload
    }

    #[test]
    fn colliding_inodes_are_filtered_by_full_cookie() {
        let owned = 0x1234_5678_9abc_def0;
        let foreign = 0x9999_5678_9abc_def0;
        let mut packet = message(20, 2, &inet_payload(foreign));
        packet.extend(message(20, 2, &inet_payload(owned)));
        packet.extend(message(3, 2, &0i32.to_ne_bytes()));
        let mut records = Vec::new();
        assert!(parse_datagram(
            &packet,
            libc::AF_INET,
            &HashSet::from([owned]),
            &mut records
        )
        .unwrap());
        assert_eq!(records.len(), 1);
        let Record::Inet(record) = &records[0] else {
            panic!("expected INET record")
        };
        assert_eq!(record.cookie, owned);
        assert_eq!(record.inode, 123);
        assert_eq!(record.local_port, 8080);
        assert_eq!(&record.local_address[..4], &[127, 0, 0, 1]);
    }

    #[test]
    fn malformed_or_incomplete_dumps_fail_closed() {
        let payload = inet_payload(7);
        let valid = message(20, 2, &payload);
        let mut wrong_sequence = valid.clone();
        wrong_sequence[8..12].copy_from_slice(&2u32.to_ne_bytes());
        let mut wrong_family = payload.clone();
        wrong_family[0] = libc::AF_INET6 as u8;
        for packet in [
            valid[..15].to_vec(),
            valid[..valid.len() - 1].to_vec(),
            message(20, 2, &payload[..71]),
            message(20, 2, &wrong_family),
            message(3, 0x10, &0i32.to_ne_bytes()),
            message(3, 2, &(-libc::EINTR).to_ne_bytes()),
            message(2, 0, &(-libc::EPERM).to_ne_bytes()),
            message(4, 0, &[]),
            wrong_sequence,
        ] {
            assert!(
                parse_datagram(&packet, libc::AF_INET, &HashSet::from([7]), &mut Vec::new())
                    .is_err()
            );
        }
        assert!(
            !parse_datagram(&valid, libc::AF_INET, &HashSet::from([7]), &mut Vec::new()).unwrap()
        );
    }

    #[test]
    fn unix_records_match_cookies_and_preserve_name_bytes() {
        let mut payload = vec![0; 16];
        payload[0] = libc::AF_UNIX as u8;
        payload[1] = libc::SOCK_STREAM as u8;
        payload[2] = 1;
        payload[4..8].copy_from_slice(&123u32.to_ne_bytes());
        payload[8..12].copy_from_slice(&7u32.to_ne_bytes());
        payload.extend_from_slice(&8u16.to_ne_bytes());
        payload.extend_from_slice(&0u16.to_ne_bytes());
        payload.extend_from_slice(b"\0a\0b");
        let mut records = Vec::new();
        let packet = message(20, 2, &payload);
        parse_datagram(&packet, libc::AF_UNIX, &HashSet::from([7]), &mut records).unwrap();
        let Record::Unix(record) = &records[0] else {
            panic!("expected UNIX record")
        };
        assert_eq!(record.name, b"\0a\0b");
        assert_eq!(record.inode, 123);
        records.clear();
        parse_datagram(&packet, libc::AF_UNIX, &HashSet::from([123]), &mut records).unwrap();
        assert!(records.is_empty());
        payload[16..18].copy_from_slice(&9u16.to_ne_bytes());
        assert!(parse_datagram(
            &message(20, 2, &payload),
            libc::AF_UNIX,
            &HashSet::from([7]),
            &mut records
        )
        .is_err());
    }

    #[test]
    fn kernel_dumps_match_descriptor_cookies_for_all_tables() {
        use crate::netlink::state::socket_cookie;
        use std::net::{TcpListener, UdpSocket};
        use std::os::unix::net::UnixStream;

        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp6 = TcpListener::bind("[::1]:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp6 = UdpSocket::bind("[::1]:0").unwrap();
        let (unix, _peer) = UnixStream::pair().unwrap();
        for (family, protocol, cookie) in [
            (
                libc::AF_INET,
                libc::IPPROTO_TCP,
                socket_cookie(&tcp).unwrap(),
            ),
            (
                libc::AF_INET6,
                libc::IPPROTO_TCP,
                socket_cookie(&tcp6).unwrap(),
            ),
            (
                libc::AF_INET,
                libc::IPPROTO_UDP,
                socket_cookie(&udp).unwrap(),
            ),
            (
                libc::AF_INET6,
                libc::IPPROTO_UDP,
                socket_cookie(&udp6).unwrap(),
            ),
            (libc::AF_UNIX, 0, socket_cookie(&unix).unwrap()),
        ] {
            let records = dump(family, protocol, &HashSet::from([cookie])).unwrap();
            assert_eq!(records.len(), 1, "family {family}, protocol {protocol}");
            assert_eq!(records[0].cookie(), cookie);
        }
    }

    #[test]
    fn kernel_dump_retains_owned_sockets_across_multiple_datagrams() {
        use crate::netlink::state::socket_cookie;
        use std::net::UdpSocket;

        let sockets: Vec<_> = (0..256)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let cookies: HashSet<_> = sockets.iter().map(|s| socket_cookie(s).unwrap()).collect();
        let records = dump(libc::AF_INET, libc::IPPROTO_UDP, &cookies).unwrap();
        assert_eq!(records.len(), sockets.len());
        assert_eq!(
            records.iter().map(Record::cookie).collect::<HashSet<_>>(),
            cookies
        );
    }
}
