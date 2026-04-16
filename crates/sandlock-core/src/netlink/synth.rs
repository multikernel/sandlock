use super::proto::*;

const IFI_LO_INDEX: i32 = 1;
const IFI_LO_TYPE:  u16 = 772; // ARPHRD_LOOPBACK
const IFF_UP:        u32 = 0x1;
const IFF_LOOPBACK:  u32 = 0x8;
const IFF_RUNNING:   u32 = 0x40;
const LO_FLAGS: u32 = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
const LO_MTU: u32 = 65536;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_TXQLEN: u16 = 13;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;

/// Synthesize a kernel-side reply as a sequence of datagrams.  Each Vec<u8>
/// in the returned list is one netlink datagram that should be delivered via
/// a single recvmsg call (netlink is datagram-oriented).
///
/// `reply_pid` is the Linux pid of the sandboxed process (used as the
/// `nlmsg_pid` field so glibc's pid-matching check on replies accepts them).
pub fn synthesize_reply(req: &ParsedRequest, reply_pid: u32) -> Vec<Vec<u8>> {
    match req.nlmsg_type {
        RTM_GETLINK if req.nlmsg_flags & NLM_F_DUMP != 0 =>
            build_link_dump(req.nlmsg_seq, reply_pid),
        RTM_GETADDR if req.nlmsg_flags & NLM_F_DUMP != 0 =>
            build_addr_dump(req.nlmsg_seq, reply_pid),
        _ => vec![build_error(req, -libc::EOPNOTSUPP)],
    }
}

/// Encode a single nlmsghdr + payload closure into one datagram.
fn encode_one<F: FnOnce(&mut Writer)>(
    nlmsg_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
    body: F,
) -> Vec<u8> {
    let mut w = Writer::new();
    let start = w.begin_msg(nlmsg_type, flags, seq, pid);
    body(&mut w);
    w.finish_msg(start);
    w.into_vec()
}

fn done_datagram(seq: u32, pid: u32) -> Vec<u8> {
    encode_one(NLMSG_DONE, NLM_F_MULTI, seq, pid, |w| {
        w.write_aligned(&0i32.to_ne_bytes());
    })
}

fn build_link_dump(seq: u32, pid: u32) -> Vec<Vec<u8>> {
    let link = encode_one(RTM_NEWLINK, NLM_F_MULTI, seq, pid, |w| {
        let ifi = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8, _pad: 0,
            ifi_type: IFI_LO_TYPE, ifi_index: IFI_LO_INDEX,
            ifi_flags: LO_FLAGS, ifi_change: 0,
        };
        let ifi_bytes = unsafe {
            std::slice::from_raw_parts(&ifi as *const _ as *const u8, std::mem::size_of::<IfInfoMsg>())
        };
        w.write_aligned(ifi_bytes);
        w.write_attr(IFLA_IFNAME, b"lo\0");
        w.write_attr(IFLA_MTU, &LO_MTU.to_ne_bytes());
        w.write_attr(IFLA_TXQLEN, &1000u32.to_ne_bytes());
        w.write_attr(IFLA_ADDRESS, &[0u8; 6]);
        w.write_attr(IFLA_BROADCAST, &[0u8; 6]);
    });
    vec![link, done_datagram(seq, pid)]
}

fn build_addr_dump(seq: u32, pid: u32) -> Vec<Vec<u8>> {
    let v4 = encode_one(RTM_NEWADDR, NLM_F_MULTI, seq, pid, |w| {
        let ifa = IfAddrMsg {
            ifa_family: libc::AF_INET as u8, ifa_prefixlen: 8,
            ifa_flags: 0, ifa_scope: 254,
            ifa_index: IFI_LO_INDEX as u32,
        };
        let ifa_bytes = unsafe {
            std::slice::from_raw_parts(&ifa as *const _ as *const u8, std::mem::size_of::<IfAddrMsg>())
        };
        w.write_aligned(ifa_bytes);
        w.write_attr(IFA_ADDRESS, &[127, 0, 0, 1]);
        w.write_attr(IFA_LOCAL,   &[127, 0, 0, 1]);
        w.write_attr(IFA_LABEL,   b"lo\0");
    });
    let v6 = encode_one(RTM_NEWADDR, NLM_F_MULTI, seq, pid, |w| {
        let ifa = IfAddrMsg {
            ifa_family: libc::AF_INET6 as u8, ifa_prefixlen: 128,
            ifa_flags: 0, ifa_scope: 254,
            ifa_index: IFI_LO_INDEX as u32,
        };
        let ifa_bytes = unsafe {
            std::slice::from_raw_parts(&ifa as *const _ as *const u8, std::mem::size_of::<IfAddrMsg>())
        };
        w.write_aligned(ifa_bytes);
        let mut v6addr = [0u8; 16]; v6addr[15] = 1;
        w.write_attr(IFA_ADDRESS, &v6addr);
        w.write_attr(IFA_LOCAL,   &v6addr);
    });
    vec![v4, v6, done_datagram(seq, pid)]
}

fn build_error(req: &ParsedRequest, err: i32) -> Vec<u8> {
    encode_one(NLMSG_ERROR, 0, req.nlmsg_seq, req.nlmsg_pid, |w| {
        w.write_aligned(&err.to_ne_bytes());
        let orig = NlMsgHdr {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: req.nlmsg_type,
            nlmsg_flags: req.nlmsg_flags,
            nlmsg_seq: req.nlmsg_seq,
            nlmsg_pid: req.nlmsg_pid,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(&orig as *const _ as *const u8, NLMSG_HDRLEN)
        };
        w.write_aligned(bytes);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_dump_is_two_datagrams_newlink_then_done() {
        let req = ParsedRequest {
            nlmsg_type: RTM_GETLINK, nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq: 1, nlmsg_pid: 0,
        };
        let reply = synthesize_reply(&req, 1234);
        assert_eq!(reply.len(), 2, "expected 2 datagrams (NEWLINK, DONE)");
        let t0 = u16::from_ne_bytes(reply[0][4..6].try_into().unwrap());
        assert_eq!(t0, RTM_NEWLINK);
        assert!(reply[0].windows(3).any(|w| w == b"lo\0"));
        let t1 = u16::from_ne_bytes(reply[1][4..6].try_into().unwrap());
        assert_eq!(t1, NLMSG_DONE);
    }

    #[test]
    fn addr_dump_is_three_datagrams_v4_v6_done() {
        let req = ParsedRequest {
            nlmsg_type: RTM_GETADDR, nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq: 1, nlmsg_pid: 0,
        };
        let reply = synthesize_reply(&req, 1234);
        assert_eq!(reply.len(), 3, "expected 3 datagrams (v4 addr, v6 addr, DONE)");
        assert!(reply[0].windows(4).any(|w| w == [127, 0, 0, 1]));
        let mut v6 = [0u8; 16]; v6[15] = 1;
        assert!(reply[1].windows(16).any(|w| w == v6));
        let t2 = u16::from_ne_bytes(reply[2][4..6].try_into().unwrap());
        assert_eq!(t2, NLMSG_DONE);
    }

    #[test]
    fn unknown_type_returns_eopnotsupp() {
        let req = ParsedRequest {
            nlmsg_type: 999, nlmsg_flags: NLM_F_REQUEST,
            nlmsg_seq: 7, nlmsg_pid: 0,
        };
        let reply = synthesize_reply(&req, 1234);
        assert_eq!(reply.len(), 1);
        let t = u16::from_ne_bytes(reply[0][4..6].try_into().unwrap());
        assert_eq!(t, NLMSG_ERROR);
        let err = i32::from_ne_bytes(reply[0][16..20].try_into().unwrap());
        assert_eq!(err, -libc::EOPNOTSUPP);
    }
}
