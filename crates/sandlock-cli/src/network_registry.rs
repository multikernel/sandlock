// Network registry — shared state in /dev/shm for cross-sandbox port discovery.
//
// Each sandbox with a hostname registers its port mappings in a single JSON
// file. `sandlock network` reads this file to display all active sandboxes.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkEntry {
    pub pid: i32,
    pub ports: HashMap<u16, u16>,
    /// Allowed hostnames (from `net_allow_hosts`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,
    /// Virtual `/etc/hosts` content injected into the sandbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_etc_hosts: Option<String>,
}

pub type Registry = HashMap<String, NetworkEntry>;

fn registry_dir() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/dev/shm/sandlock-{}", uid))
}

fn registry_path() -> PathBuf {
    registry_dir().join("network.json")
}

/// Open the registry file with an exclusive flock, creating it if needed.
fn open_locked() -> io::Result<fs::File> {
    fs::create_dir_all(registry_dir())?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(registry_path())?;
    // Exclusive lock — blocks until available
    let ret = unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn read_registry(file: &mut fs::File) -> Registry {
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok();
    serde_json::from_str(&buf).unwrap_or_default()
}

fn write_registry(file: &mut fs::File, registry: &Registry) -> io::Result<()> {
    file.set_len(0)?;
    file.seek(std::io::SeekFrom::Start(0))?;
    serde_json::to_writer_pretty(file, registry)?;
    Ok(())
}

/// Register a sandbox's network state. Returns an error if the hostname is
/// already claimed by a live process.
pub fn register(
    hostname: &str,
    pid: i32,
    ports: HashMap<u16, u16>,
    allowed_hosts: Vec<String>,
    virtual_etc_hosts: Option<String>,
) -> io::Result<()> {
    let mut file = open_locked()?;
    let mut reg = read_registry(&mut file);
    // Check for hostname conflict with a live process
    if let Some(existing) = reg.get(hostname) {
        if unsafe { libc::kill(existing.pid, 0) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("hostname '{}' already claimed by PID {}", hostname, existing.pid),
            ));
        }
    }
    reg.insert(hostname.to_string(), NetworkEntry {
        pid,
        ports,
        allowed_hosts,
        virtual_etc_hosts,
    });
    write_registry(&mut file, &reg)
}

/// Update port mappings for an already-registered hostname.
pub fn update_ports(hostname: &str, ports: HashMap<u16, u16>) -> io::Result<()> {
    let mut file = open_locked()?;
    let mut reg = read_registry(&mut file);
    if let Some(entry) = reg.get_mut(hostname) {
        entry.ports = ports;
        write_registry(&mut file, &reg)?;
    }
    Ok(())
}

/// Remove a sandbox's entry from the registry.
pub fn unregister(hostname: &str) -> io::Result<()> {
    let mut file = open_locked()?;
    let mut reg = read_registry(&mut file);
    reg.remove(hostname);
    write_registry(&mut file, &reg)
}

/// Generate the next available sandbox name (sandbox-1, sandbox-2, ...).
pub fn next_name() -> String {
    let max_n = match open_locked() {
        Ok(mut file) => {
            let reg = read_registry(&mut file);
            reg.keys()
                .filter_map(|k| {
                    k.strip_prefix("sandbox-")
                        .and_then(|s| s.parse::<u64>().ok())
                })
                .max()
                .unwrap_or(0)
        }
        Err(_) => 0,
    };
    format!("sandbox-{}", max_n + 1)
}

/// Read all entries, pruning dead PIDs.
pub fn list() -> io::Result<Registry> {
    let mut file = match open_locked() {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Registry::new()),
        Err(e) => return Err(e),
    };
    let mut reg = read_registry(&mut file);
    let before = reg.len();
    reg.retain(|_, entry| unsafe { libc::kill(entry.pid, 0) } == 0);
    if reg.len() != before {
        let _ = write_registry(&mut file, &reg);
    }
    Ok(reg)
}
