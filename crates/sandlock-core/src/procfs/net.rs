use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use super::sock_diag::{self, Record};
use crate::netlink::{state::socket_cookie, NetlinkState};
use crate::seccomp::notif::NotifPolicy;
use crate::seccomp::state::{read_pid_start_time, ProcessIndex};
use crate::sys::syscall::{pidfd_getfd, pidfd_open};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetFile {
    Dev,
    IfInet6,
    Route,
    Ipv6Route,
    FibTrie,
    Arp,
    Tcp,
    Tcp6,
    Udp,
    Udp6,
    Unix,
    Sockstat,
    Sockstat6,
}

pub(crate) const FILES: &[(&str, NetFile)] = &[
    ("dev", NetFile::Dev),
    ("if_inet6", NetFile::IfInet6),
    ("route", NetFile::Route),
    ("ipv6_route", NetFile::Ipv6Route),
    ("fib_trie", NetFile::FibTrie),
    ("arp", NetFile::Arp),
    ("tcp", NetFile::Tcp),
    ("tcp6", NetFile::Tcp6),
    ("udp", NetFile::Udp),
    ("udp6", NetFile::Udp6),
    ("unix", NetFile::Unix),
    ("sockstat", NetFile::Sockstat),
    ("sockstat6", NetFile::Sockstat6),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetEntry {
    Outside,
    Directory,
    File(NetFile),
    Missing,
}

pub(crate) fn lookup(path: &str) -> NetEntry {
    if path == "/proc/net" || path == "/proc/net/" {
        return NetEntry::Directory;
    }
    let Some(name) = path.strip_prefix("/proc/net/") else {
        return NetEntry::Outside;
    };
    FILES
        .iter()
        .find_map(|&(entry, file)| (entry == name).then_some(NetEntry::File(file)))
        .unwrap_or(NetEntry::Missing)
}

struct SocketSnapshot {
    sockets: HashMap<u64, OwnedFd>,
}

impl SocketSnapshot {
    fn collect(processes: &ProcessIndex, netlink: &NetlinkState) -> Self {
        let mut sockets = HashMap::new();
        for pid in processes.pids_snapshot() {
            let Some(key) = processes.key_for(pid) else {
                continue;
            };
            if read_pid_start_time(pid) != Some(key.start_time) {
                continue;
            }
            let Some(tgid) = processes.tgid_of(pid) else {
                continue;
            };
            let Ok(pidfd) = pidfd_open(tgid as u32, 0) else {
                continue;
            };
            let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            let mut task_sockets = HashMap::new();
            for entry in entries.flatten() {
                let Some(fd) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<i32>().ok())
                else {
                    continue;
                };
                let Ok(socket) = pidfd_getfd(&pidfd, fd, 0) else {
                    continue;
                };
                let Some(cookie) = socket_cookie(&socket) else {
                    continue;
                };
                if netlink.contains_cookie(cookie) {
                    continue;
                }
                task_sockets.entry(cookie).or_insert(socket);
            }
            if processes.key_for(pid) == Some(key)
                && read_pid_start_time(pid) == Some(key.start_time)
            {
                sockets.extend(task_sockets);
            }
        }
        Self { sockets }
    }

    fn cookies(&self) -> HashSet<u64> {
        self.sockets.keys().copied().collect()
    }

    fn raw_count(&self, domain: i32) -> usize {
        self.sockets
            .values()
            .filter(|fd| {
                socket_option(fd, libc::SO_DOMAIN) == Some(domain)
                    && socket_option(fd, libc::SO_TYPE) == Some(libc::SOCK_RAW)
            })
            .count()
    }

    fn count(&self, domain: i32, protocol: i32) -> usize {
        self.sockets
            .values()
            .filter(|fd| {
                socket_option(fd, libc::SO_DOMAIN) == Some(domain)
                    && socket_option(fd, libc::SO_PROTOCOL) == Some(protocol)
            })
            .count()
    }
}

fn socket_option(fd: &OwnedFd, option: i32) -> Option<i32> {
    let mut value = 0i32;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut i32).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(value)
}

const INET_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
const UNIX_HEADER: &str = "Num       RefCount Protocol Flags    Type St Inode Path\n";

fn render_inet(
    records: &[Record],
    ports: &HashMap<u16, u16>,
    remap: bool,
    protocol: i32,
) -> String {
    use std::fmt::Write;

    let mut output = String::from(INET_HEADER);
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    for (index, record) in records
        .iter()
        .filter_map(|record| match record {
            Record::Inet(record) => Some(record),
            _ => None,
        })
        .enumerate()
    {
        let address = |bytes: &[u8; 16]| -> String {
            let len = if record.family == libc::AF_INET as u8 {
                4
            } else {
                16
            };
            bytes[..len]
                .chunks_exact(4)
                .map(|word| format!("{:08X}", u32::from_ne_bytes(word.try_into().unwrap())))
                .collect()
        };
        let local_port = if remap {
            ports
                .get(&record.local_port)
                .copied()
                .unwrap_or(record.local_port)
        } else {
            record.local_port
        };
        let tx_queue = if record.state == 10 {
            0
        } else {
            record.tx_queue
        };
        let expires = record.expires_ms as u64 * ticks / 1000;
        let (retransmits, probes) = if matches!(record.timer, 2 | 4) {
            (0, record.retransmits)
        } else {
            (record.retransmits, 0)
        };
        // Keep procfs columns present even when diagnostics cannot supply their counters.
        let counters = if protocol == libc::IPPROTO_TCP {
            "0 0 0 0 0"
        } else {
            "0"
        };
        writeln!(output,
            "{index}: {}:{local_port:04X} {}:{:04X} {:02X} {tx_queue:08X}:{:08X} {:02X}:{expires:08X} {retransmits:08X} {} {probes} {} 0 0000000000000000 {counters}",
            address(&record.local_address), address(&record.remote_address), record.remote_port,
            record.state, record.rx_queue, record.timer, record.uid, record.inode,
        ).unwrap();
    }
    output
}

fn render_unix(records: &[Record], map_path: impl Fn(&str) -> Option<String>) -> String {
    use std::fmt::Write;

    let mut output = String::from(UNIX_HEADER);
    for record in records {
        let Record::Unix(record) = record else {
            continue;
        };
        let name = if record.name.first() == Some(&0) {
            record
                .name
                .iter()
                .map(|byte| if *byte == 0 { b'@' } else { *byte })
                .collect::<Vec<_>>()
        } else {
            record
                .name
                .split(|byte| *byte == 0)
                .next()
                .unwrap_or_default()
                .to_vec()
        };
        let Ok(path) = std::str::from_utf8(&name) else {
            continue;
        };
        if path.contains(['\n', '\r']) {
            continue;
        }
        let path = if path.is_empty() {
            String::new()
        } else {
            let Some(path) = map_path(path) else {
                continue;
            };
            path
        };
        let flags = if record.state == 10 { 0x10000 } else { 0 };
        let state = if record.state == 1 { 3 } else { 1 };
        write!(
            output,
            "0000000000000000: 00000000 00000000 {flags:08X} {:04X} {state:02X} {}",
            record.kind, record.inode
        )
        .unwrap();
        if !path.is_empty() {
            output.push(' ');
            output.push_str(&path);
        }
        output.push('\n');
    }
    output
}

fn visible_unix_path(
    path: &str,
    root: Option<&Path>,
    mounts: &[(std::path::PathBuf, std::path::PathBuf)],
) -> Option<String> {
    let host = Path::new(path);
    if host
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return None;
    }
    let Some(root) = root else {
        return Some(path.into());
    };
    let mapped = crate::chroot::resolve::host_to_virtual(root, mounts, host)?;
    let (virtual_base, source) = std::iter::once((Path::new("/"), root))
        .chain(mounts.iter().map(|(v, h)| (v.as_path(), h.as_path())))
        .filter(|(v, _)| mapped.starts_with(v))
        .max_by_key(|(v, _)| v.as_os_str().len())?;
    let resolved = source.join(mapped.strip_prefix(virtual_base).ok()?);
    (resolved == host)
        .then(|| mapped.to_str().map(str::to_owned))
        .flatten()
}

fn generate_proc_net_dev() -> Vec<u8> {
    concat!(
        "Inter-|   Receive                                                |  Transmit\n",
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
        "    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n",
    ).as_bytes().to_vec()
}

fn generate_proc_net_if_inet6() -> Vec<u8> {
    b"00000000000000000000000000000001 01 80 10 80       lo\n".to_vec()
}

pub(crate) fn render(
    file: NetFile,
    processes: &ProcessIndex,
    port_map: &HashMap<u16, u16>,
    netlink: &NetlinkState,
    policy: &NotifPolicy,
) -> io::Result<Vec<u8>> {
    let topology = match file {
        NetFile::Dev => return Ok(generate_proc_net_dev()),
        NetFile::IfInet6 => return Ok(generate_proc_net_if_inet6()),
        NetFile::Route => Some("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\nlo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n"),
        NetFile::Ipv6Route => Some("00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 80200001 lo\n"),
        NetFile::FibTrie => Some("Main:\n  +-- 127.0.0.0/8 1 0 0\n     |-- 127.0.0.1\n        /32 host LOCAL\nLocal:\n  +-- 127.0.0.0/8 1 0 0\n     |-- 127.0.0.1\n        /32 host LOCAL\n"),
        NetFile::Arp => Some("IP address       HW type     Flags       HW address            Mask     Device\n"),
        _ => None,
    };
    if let Some(text) = topology {
        return Ok(text.as_bytes().to_vec());
    }
    let snapshot = SocketSnapshot::collect(processes, netlink);
    let cookies = snapshot.cookies();
    let text = match file {
        NetFile::Tcp | NetFile::Tcp6 | NetFile::Udp | NetFile::Udp6 => {
            let family = if matches!(file, NetFile::Tcp6 | NetFile::Udp6) {
                libc::AF_INET6
            } else {
                libc::AF_INET
            };
            let protocol = if matches!(file, NetFile::Tcp | NetFile::Tcp6) {
                libc::IPPROTO_TCP
            } else {
                libc::IPPROTO_UDP
            };
            let records = sock_diag::dump(family, protocol, &cookies)?;
            render_inet(&records, port_map, policy.port_remap, protocol)
        }
        NetFile::Unix => {
            let records = sock_diag::dump(libc::AF_UNIX, 0, &cookies)?;
            render_unix(&records, |path| {
                if path.starts_with('@') { return Some(path.into()); }
                if policy.cow_enabled || !path.starts_with('/') { return None; }
                visible_unix_path(path, policy.chroot_root.as_deref(), &policy.chroot_mounts)
            })
        }
        NetFile::Sockstat => format!(
            "sockets: used {}\nTCP: inuse {} orphan 0 tw 0 alloc {} mem 0\nUDP: inuse {} mem 0\nUDPLITE: inuse {}\nRAW: inuse {}\nFRAG: inuse 0 memory 0\n",
            snapshot.sockets.len(), snapshot.count(libc::AF_INET, libc::IPPROTO_TCP),
            snapshot.count(libc::AF_INET, libc::IPPROTO_TCP) + snapshot.count(libc::AF_INET6, libc::IPPROTO_TCP),
            snapshot.count(libc::AF_INET, libc::IPPROTO_UDP), snapshot.count(libc::AF_INET, libc::IPPROTO_UDPLITE), snapshot.raw_count(libc::AF_INET),
        ),
        NetFile::Sockstat6 => format!(
            "TCP6: inuse {}\nUDP6: inuse {}\nUDPLITE6: inuse {}\nRAW6: inuse {}\nFRAG6: inuse 0 memory 0\n",
            snapshot.count(libc::AF_INET6, libc::IPPROTO_TCP), snapshot.count(libc::AF_INET6, libc::IPPROTO_UDP),
            snapshot.count(libc::AF_INET6, libc::IPPROTO_UDPLITE), snapshot.raw_count(libc::AF_INET6),
        ),
        _ => unreachable!(),
    };
    Ok(text.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_closed_at_component_boundaries() {
        assert_eq!(lookup("/proc/net"), NetEntry::Directory);
        assert_eq!(lookup("/proc/network"), NetEntry::Outside);
        assert_eq!(lookup("/proc/net/tcp/extra"), NetEntry::Missing);
        assert_eq!(lookup("/proc/net/future"), NetEntry::Missing);
        for &(name, file) in FILES {
            assert_eq!(lookup(&format!("/proc/net/{name}")), NetEntry::File(file));
        }
    }

    fn inet_record(family: i32) -> Record {
        use super::super::sock_diag::InetRecord;
        let mut local_address = [0; 16];
        local_address[..4].copy_from_slice(&0x0100007fu32.to_ne_bytes());
        Record::Inet(InetRecord {
            cookie: 7,
            inode: 123,
            family: family as u8,
            state: 1,
            timer: 0,
            retransmits: 0,
            local_port: 50000,
            remote_port: 50000,
            local_address,
            remote_address: local_address,
            expires_ms: 0,
            rx_queue: 16,
            tx_queue: 32,
            uid: 1000,
        })
    }

    #[test]
    fn inet_rows_only_translate_local_port() {
        let records = [inet_record(libc::AF_INET)];
        let ports = HashMap::from([(50000, 8080)]);
        let output = render_inet(&records, &ports, true, libc::IPPROTO_TCP);
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("0: 0100007F:1F90 0100007F:C350 01 00000020:00000010"));
        assert!(output.contains("1000 0 123 0 0000000000000000"));
        assert!(render_inet(&records, &ports, false, libc::IPPROTO_TCP)
            .contains("0100007F:C350 0100007F:C350"));
        assert_eq!(
            render_inet(&[], &ports, false, libc::IPPROTO_TCP),
            INET_HEADER
        );
    }

    #[test]
    fn ipv6_rows_keep_all_address_words_and_listener_queue_semantics() {
        let mut record = inet_record(libc::AF_INET6);
        let Record::Inet(info) = &mut record else {
            unreachable!()
        };
        info.local_address[12..16].copy_from_slice(&0x12345678u32.to_ne_bytes());
        info.state = 10;
        let output = render_inet(
            &[record],
            &HashMap::from([(50000, 53)]),
            true,
            libc::IPPROTO_TCP,
        );
        assert!(output.contains("0100007F000000000000000012345678:0035"));
        assert!(output.contains("0A 00000000:00000010"));
    }

    #[test]
    fn inet_rows_preserve_protocol_column_counts() {
        for (protocol, fields) in [(libc::IPPROTO_TCP, 17), (libc::IPPROTO_UDP, 13)] {
            let output = render_inet(
                &[inet_record(libc::AF_INET)],
                &HashMap::new(),
                false,
                protocol,
            );
            assert_eq!(
                output.lines().nth(1).unwrap().split_whitespace().count(),
                fields
            );
        }
    }

    #[test]
    fn inet_probe_counts_are_not_reported_as_retransmissions() {
        for (timer, retransmits, probes) in [
            (1, "00000003", "0"),
            (2, "00000000", "3"),
            (4, "00000000", "3"),
        ] {
            let mut record = inet_record(libc::AF_INET);
            let Record::Inet(info) = &mut record else {
                unreachable!()
            };
            info.timer = timer;
            info.retransmits = 3;
            let output = render_inet(&[record], &HashMap::new(), false, libc::IPPROTO_TCP);
            let fields: Vec<_> = output.lines().nth(1).unwrap().split_whitespace().collect();
            assert_eq!(fields[6], retransmits);
            assert_eq!(fields[8], probes);
        }
    }

    #[test]
    fn unix_path_mapping_rejects_shadowed_root_paths() {
        let root = Some(Path::new("/rootfs"));
        let mounts = vec![("/run".into(), "/host/run".into())];
        assert_eq!(
            visible_unix_path("/host/run/a", root, &mounts),
            Some("/run/a".into())
        );
        assert_eq!(visible_unix_path("/rootfs/run/hidden", root, &mounts), None);
        assert_eq!(visible_unix_path("/elsewhere/a", root, &mounts), None);
        assert_eq!(visible_unix_path("/rootfs/../secret", root, &mounts), None);
    }

    fn unix_record(inode: u32, name: &[u8], state: u8) -> Record {
        Record::Unix(super::super::sock_diag::UnixRecord {
            cookie: inode as u64 + 1000,
            inode,
            kind: libc::SOCK_STREAM as u8,
            state,
            name: name.to_vec(),
        })
    }

    #[test]
    fn unix_unrepresentable_names_cannot_inject_rows() {
        let records = [
            unix_record(42, b"\0visible", 1),
            unix_record(43, b"\0\xff", 1),
            unix_record(44, b"\0name\nforged row", 1),
        ];
        let output = render_unix(&records, |p| Some(p.into()));
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("42 @visible"));
    }

    #[test]
    fn unix_unnamed_and_abstract_sockets_survive() {
        let records = [
            unix_record(42, b"", 1),
            unix_record(43, b"\0sandbox name\0tail", 1),
        ];
        let output = render_unix(&records, |p| Some(p.into()));
        assert_eq!(output.lines().count(), 3);
        assert!(output.contains("43 @sandbox name@tail\n"));
        assert!(output.contains("03 42\n"));
    }

    #[test]
    fn unix_rows_hide_unmapped_paths_and_render_listener_flags() {
        let records = [
            unix_record(123, b"/rootfs/run/a socket\0", 10),
            unix_record(456, b"/host/secret\0", 10),
        ];
        let output = render_unix(&records, |path| {
            path.strip_prefix("/rootfs").map(str::to_owned)
        });
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("00010000 0001 01 123 /run/a socket"));
        assert!(!output.contains("rootfs"));
        assert!(!output.contains("secret"));
    }
}
