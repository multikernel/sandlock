use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use crate::netlink::{state::socket_cookie, NetlinkState};
use crate::seccomp::notif::{dup_fd_from_pid, NotifPolicy};
use crate::seccomp::state::{read_pid_start_time, ProcessIndex};

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
                let Ok(socket) = dup_fd_from_pid(pid as u32, fd) else {
                    continue;
                };
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(socket.as_raw_fd(), &mut stat) } != 0
                    || stat.st_mode & libc::S_IFMT != libc::S_IFSOCK
                {
                    continue;
                }
                let Some(cookie) = socket_cookie(&socket) else {
                    continue;
                };
                if netlink.contains_cookie(cookie) {
                    continue;
                }
                task_sockets.entry(stat.st_ino).or_insert(socket);
            }
            // Keep descriptors pinned so a closed socket's inode cannot be reused by a host row.
            if processes.key_for(pid) == Some(key)
                && read_pid_start_time(pid) == Some(key.start_time)
            {
                sockets.extend(task_sockets);
            }
        }
        Self { sockets }
    }

    fn inodes(&self) -> HashSet<u64> {
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

fn filter_inet(
    input: &str,
    inodes: &HashSet<u64>,
    ports: &HashMap<u16, u16>,
    remap: bool,
) -> String {
    let mut output = String::from(INET_HEADER);
    let mut index = 0;
    for row in input.lines().skip(1) {
        let mut fields: Vec<String> = row.split_whitespace().map(str::to_owned).collect();
        if fields.len() < 10 {
            continue;
        }
        if !fields[9]
            .parse::<u64>()
            .ok()
            .is_some_and(|i| i != 0 && inodes.contains(&i))
        {
            continue;
        }
        let Some((address, port)) = fields[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port, 16) else {
            continue;
        };
        if remap {
            fields[1] = format!(
                "{}:{:04X}",
                address,
                ports.get(&port).copied().unwrap_or(port)
            );
        }
        fields[0] = format!("{index}:");
        if fields.len() > 11 {
            fields[11] = "0000000000000000".into();
        }
        output.push_str(&fields.join(" "));
        output.push('\n');
        index += 1;
    }
    output
}

fn filter_unix(
    input: &[u8],
    inodes: &HashSet<u64>,
    map_path: impl Fn(&str) -> Option<String>,
) -> String {
    let mut output = String::from(UNIX_HEADER);
    for row in input.split(|byte| *byte == b'\n').skip(1) {
        let Ok(row) = std::str::from_utf8(row) else {
            continue;
        };
        let mut rest = row;
        let mut fields = Vec::new();
        for _ in 0..7 {
            rest = rest.trim_start();
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            fields.push(&rest[..end]);
            rest = &rest[end..];
        }
        if !fields[6]
            .parse::<u64>()
            .ok()
            .is_some_and(|i| i != 0 && inodes.contains(&i))
        {
            continue;
        }
        let path = rest.trim_start();
        let path = if path.is_empty() {
            String::new()
        } else {
            let Some(path) = map_path(path) else {
                continue;
            };
            path
        };
        fields[0] = "0000000000000000:";
        output.push_str(&fields.join(" "));
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
    let inodes = snapshot.inodes();
    let text = match file {
        NetFile::Tcp | NetFile::Tcp6 | NetFile::Udp | NetFile::Udp6 => {
            let name = FILES.iter().find(|(_, entry)| *entry == file).unwrap().0;
            let input = std::fs::read_to_string(format!("/proc/net/{name}"))?;
            filter_inet(&input, &inodes, port_map, policy.port_remap)
        }
        NetFile::Unix => {
            let input = std::fs::read("/proc/net/unix")?;
            filter_unix(&input, &inodes, |path| {
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

    #[test]
    fn inet_rows_require_owned_inode_and_only_translate_local_port() {
        let input = "header\n 8: 0100007F:C350 0100007F:C350 01 0:0 00:0 0 1000 0 123 1 00000000\n 9: 0100007F:C350 00000000:0000 0A 0:0 00:0 0 1000 0 999 1 00000000\n 10: 0100007F:C350 00000000:0000 06 0:0 00:0 0 1000 0 0 1 00000000\nmalformed\n";
        let owned = HashSet::from([123]);
        let ports = HashMap::from([(50000, 8080)]);
        let output = filter_inet(input, &owned, &ports, true);
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("0: 0100007F:1F90 0100007F:C350"));
        assert!(!output.contains("999"));
        assert!(filter_inet(input, &owned, &ports, false).contains("0100007F:C350 0100007F:C350"));
    }

    #[test]
    fn ipv6_udp_rows_keep_endpoints_and_drop_unverifiable_rows() {
        let input = "header\n 30: 00000000000000000000000001000000:C350 00000000000000000000000000000000:0000 07 0:0 00:0 0 1000 0 42 2 0000000012345678 0\n 31: 00000000000000000000000001000000:C350 00000000000000000000000000000000:0000 07 0:0 00:0 0 1000 0 invalid\n";
        let output = filter_inet(
            input,
            &HashSet::from([42]),
            &HashMap::from([(50000, 53)]),
            true,
        );
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("00000000000000000000000001000000:0035"));
        assert!(!output.contains("12345678"));
        assert_eq!(
            filter_inet(input, &HashSet::new(), &HashMap::new(), false),
            INET_HEADER
        );
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

    #[test]
    fn unix_binary_names_do_not_hide_representable_owned_sockets() {
        let input = b"header\n00000000: 00000002 00000000 00000000 0001 03 42 @visible\n00000000: 00000002 00000000 00000000 0001 03 43 @\xff\n00000000: 00000002 00000000 00000000 0001 03 999 @\xfe\n";
        let output = filter_unix(input, &HashSet::from([42, 43]), |p| Some(p.into()));
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("42 @visible"));
    }

    #[test]
    fn unix_unnamed_and_abstract_sockets_survive() {
        let input = "header\n00000000: 00000002 00000000 00000000 0001 03 42\n00000000: 00000002 00000000 00000000 0001 03 43 @sandbox name\n";
        let output = filter_unix(input.as_bytes(), &HashSet::from([42, 43]), |p| {
            Some(p.into())
        });
        assert_eq!(output.lines().count(), 3);
        assert!(output.contains("43 @sandbox name\n"));
        assert!(output.contains("03 42\n"));
    }

    #[test]
    fn unix_rows_hide_foreign_inodes_and_unmapped_paths() {
        let input = "header\n0000000000001234: 00000002 00000000 00010000 0001 01 123 /rootfs/run/a socket\n0000000000005678: 00000002 00000000 00010000 0001 01 456 /host/secret\n0000000000009876: 00000002 00000000 00010000 0001 01 999 @foreign\n";
        let output = filter_unix(input.as_bytes(), &HashSet::from([123, 456]), |path| {
            path.strip_prefix("/rootfs").map(str::to_owned)
        });
        assert_eq!(output.lines().count(), 2);
        assert!(output.contains("123 /run/a socket"));
        assert!(!output.contains("rootfs"));
        assert!(!output.contains("secret"));
        assert!(!output.contains("1234:"));
    }
}
