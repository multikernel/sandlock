use std::mem::size_of;

pub const NLMSG_ALIGN_TO: usize = 4;
pub const fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGN_TO - 1) & !(NLMSG_ALIGN_TO - 1)
}

pub const NLMSG_ERROR: u16 = 0x0002;
pub const NLMSG_DONE: u16 = 0x0003;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWADDR: u16 = 20;

pub const NLM_F_REQUEST: u16 = 0x001;
pub const NLM_F_MULTI:   u16 = 0x002;
pub const NLM_F_DUMP:    u16 = 0x300;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsgHdr {
    pub nlmsg_len:   u32,
    pub nlmsg_type:  u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq:   u32,
    pub nlmsg_pid:   u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfInfoMsg {
    pub ifi_family: u8,
    pub _pad:       u8,
    pub ifi_type:   u16,
    pub ifi_index:  i32,
    pub ifi_flags:  u32,
    pub ifi_change: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfAddrMsg {
    pub ifa_family:    u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags:     u8,
    pub ifa_scope:     u8,
    pub ifa_index:     u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtAttr {
    pub rta_len:  u16,
    pub rta_type: u16,
}

pub const NLMSG_HDRLEN: usize = size_of::<NlMsgHdr>();
pub const RTA_HDRLEN:   usize = size_of::<RtAttr>();

pub struct Writer { buf: Vec<u8> }

impl Writer {
    pub fn new() -> Self { Self { buf: Vec::new() } }
    pub fn into_vec(self) -> Vec<u8> { self.buf }

    pub fn write_aligned(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        let pad = nlmsg_align(bytes.len()) - bytes.len();
        self.buf.resize(self.buf.len() + pad, 0);
    }

    pub fn write_attr(&mut self, rta_type: u16, payload: &[u8]) {
        let total = RTA_HDRLEN + payload.len();
        let hdr = RtAttr { rta_len: total as u16, rta_type };
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, RTA_HDRLEN)
        };
        self.buf.extend_from_slice(hdr_bytes);
        self.buf.extend_from_slice(payload);
        let pad = nlmsg_align(total) - total;
        self.buf.resize(self.buf.len() + pad, 0);
    }

    pub fn begin_msg(&mut self, nlmsg_type: u16, flags: u16, seq: u32, pid: u32) -> usize {
        let start = self.buf.len();
        let hdr = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type, nlmsg_flags: flags, nlmsg_seq: seq, nlmsg_pid: pid,
        };
        let hdr_bytes = unsafe {
            std::slice::from_raw_parts(&hdr as *const _ as *const u8, NLMSG_HDRLEN)
        };
        self.buf.extend_from_slice(hdr_bytes);
        start
    }

    pub fn finish_msg(&mut self, start: usize) {
        let total = self.buf.len() - start;
        let len_bytes = (total as u32).to_ne_bytes();
        self.buf[start..start + 4].copy_from_slice(&len_bytes);
        let pad = nlmsg_align(total) - total;
        self.buf.resize(self.buf.len() + pad, 0);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ParsedRequest {
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

pub fn parse_request(buf: &[u8]) -> Option<ParsedRequest> {
    if buf.len() < NLMSG_HDRLEN { return None; }
    let hdr: NlMsgHdr = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
    if (hdr.nlmsg_len as usize) > buf.len() { return None; }
    Some(ParsedRequest {
        nlmsg_type: hdr.nlmsg_type,
        nlmsg_flags: hdr.nlmsg_flags,
        nlmsg_seq: hdr.nlmsg_seq,
        nlmsg_pid: hdr.nlmsg_pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_rounds_to_4() {
        assert_eq!(nlmsg_align(0), 0);
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
        assert_eq!(nlmsg_align(16), 16);
    }

    #[test]
    fn writer_msg_round_trip() {
        let mut w = Writer::new();
        let start = w.begin_msg(RTM_NEWLINK, NLM_F_MULTI, 42, 0);
        w.write_attr(3 /* IFLA_IFNAME */, b"lo\0");
        w.finish_msg(start);
        let buf = w.into_vec();
        let parsed = parse_request(&buf).unwrap();
        assert_eq!(parsed.nlmsg_type, RTM_NEWLINK);
        assert_eq!(parsed.nlmsg_seq, 42);
        let total = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert!(total >= NLMSG_HDRLEN + RTA_HDRLEN + 3);
    }

    #[test]
    fn parse_request_rejects_short_buffer() {
        assert!(parse_request(&[0u8; 4]).is_none());
    }
}
