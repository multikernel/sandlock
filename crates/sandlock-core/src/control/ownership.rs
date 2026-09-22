use std::io;

const HEADER: usize = 4;
const SIGNATURE: [u16; 3] = [0x534c, 0x434f, 1];
const NAME_BYTES: usize = 64;
const TOKEN_WORDS: usize = 9;
const SLOT_SIZE: usize = 2 + TOKEN_WORDS + NAME_BYTES;
const SLOTS: usize = 256;
const SEMAPHORES: usize = HEADER + SLOTS * SLOT_SIZE;

#[derive(Clone, Copy, Debug)]
struct Registry(i32);

#[derive(Debug)]
pub(crate) struct Claim {
    registry: Registry,
    slot: usize,
    owner: i32,
    pub entry: Entry,
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub name: String,
    pub token: String,
    pub supervisor: i32,
}

#[repr(C)]
union SemArg {
    value: libc::c_int,
    array: *mut libc::c_ushort,
    stat: *mut libc::semid_ds,
}

fn checked(result: i32) -> io::Result<i32> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "incompatible sandlock control registry",
    )
}

impl Registry {
    fn open(create: bool) -> io::Result<Option<Self>> {
        let uid = unsafe { libc::getuid() };
        let key = (uid ^ 0x534c4301).max(1) as libc::key_t;
        let flags = 0o600 | if create { libc::IPC_CREAT } else { 0 };
        let id = unsafe { libc::semget(key, SEMAPHORES as i32, flags) };
        if id < 0 && !create && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        let registry = Self(checked(id)?);
        let mut stat: libc::semid_ds = unsafe { std::mem::zeroed() };
        checked(unsafe { libc::semctl(id, 0, libc::IPC_STAT, SemArg { stat: &mut stat }) })?;
        if stat.sem_perm.uid != uid
            || stat.sem_perm.cuid != uid
            || stat.sem_perm.mode & 0o777 != 0o600
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "control registry owned by another user or has unsafe permissions",
            ));
        }
        if stat.sem_nsems as usize != SEMAPHORES {
            return Err(invalid());
        }
        let values = registry.values()?;
        if values[1..HEADER] != SIGNATURE && values[1..].iter().any(|&v| v != 0) {
            return Err(invalid());
        }
        let _lock = registry.lock()?;
        let values = registry.values()?;
        if values[1..HEADER] == [0; 3] && values[HEADER..].iter().all(|&v| v == 0) {
            let mut ops: Vec<_> = SIGNATURE
                .iter()
                .enumerate()
                .map(|(i, &value)| libc::sembuf {
                    sem_num: (i + 1) as u16,
                    sem_op: value as i16,
                    sem_flg: libc::IPC_NOWAIT as i16,
                })
                .collect();
            checked(unsafe { libc::semop(id, ops.as_mut_ptr(), ops.len()) })?;
        } else if values[1..HEADER] != SIGNATURE {
            return Err(invalid());
        }
        Ok(Some(registry))
    }

    fn values(self) -> io::Result<Vec<u16>> {
        let mut values = vec![0; SEMAPHORES];
        checked(unsafe {
            libc::semctl(
                self.0,
                0,
                libc::GETALL,
                SemArg {
                    array: values.as_mut_ptr(),
                },
            )
        })?;
        Ok(values)
    }

    fn lock(self) -> io::Result<Transaction> {
        let mut ops = [
            libc::sembuf {
                sem_num: 0,
                sem_op: 0,
                sem_flg: 0,
            },
            libc::sembuf {
                sem_num: 0,
                sem_op: 1,
                sem_flg: libc::SEM_UNDO as i16,
            },
        ];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let timeout = libc::timespec {
                tv_sec: remaining.as_secs() as _,
                tv_nsec: remaining.subsec_nanos() as _,
            };
            let result = unsafe {
                libc::syscall(
                    libc::SYS_semtimedop,
                    self.0,
                    ops.as_mut_ptr(),
                    ops.len(),
                    &timeout,
                )
            } as i32;
            match checked(result) {
                Ok(_) => {
                    return Ok(Transaction {
                        registry: self,
                        owner: unsafe { libc::getpid() },
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted && !remaining.is_zero() => {
                    continue
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn adjust(self, index: usize, delta: i16) -> io::Result<()> {
        let mut op = libc::sembuf {
            sem_num: index as u16,
            sem_op: delta,
            sem_flg: (libc::SEM_UNDO | libc::IPC_NOWAIT) as i16,
        };
        checked(unsafe { libc::semop(self.0, &mut op, 1) }).map(|_| ())
    }

    fn entries(self, values: &[u16]) -> io::Result<Vec<Entry>> {
        let mut entries = Vec::new();
        for slot in 0..SLOTS {
            let start = HEADER + slot * SLOT_SIZE;
            let data = &values[start..start + SLOT_SIZE];
            if data[0] == 0 {
                continue;
            }
            let len = data[1] as usize;
            if data[0] != 1 || len == 0 || len > NAME_BYTES {
                return Err(invalid());
            }
            let bytes = data[2 + TOKEN_WORDS..2 + TOKEN_WORDS + len]
                .iter()
                .map(|&v| u8::try_from(v).map_err(|_| invalid()))
                .collect::<io::Result<Vec<_>>>()?;
            let name = String::from_utf8(bytes).map_err(|_| invalid())?;
            let supervisor = checked(unsafe { libc::semctl(self.0, start as i32, libc::GETPID) })?;
            if supervisor <= 0 {
                continue;
            }
            let token = data[2..2 + TOKEN_WORDS]
                .iter()
                .map(|v| format!("{v:04x}"))
                .collect();
            entries.push(Entry {
                name,
                token,
                supervisor,
            });
        }
        Ok(entries)
    }

    fn claim(self, name: &str) -> io::Result<Claim> {
        if name.is_empty() || name.len() > NAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control name must contain 1 to 64 bytes",
            ));
        }
        let mut nonce = uuid::Uuid::new_v4().as_u128();
        let mut token = [0u16; TOKEN_WORDS];
        for word in &mut token {
            *word = (nonce & 0x7fff) as u16;
            nonce >>= 15;
        }
        let _lock = self.lock()?;
        let values = self.values()?;
        if self
            .entries(&values)?
            .iter()
            .any(|entry| entry.name == name)
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "sandbox name is already claimed",
            ));
        }
        let slot = (0..SLOTS)
            .find(|&slot| values[HEADER + slot * SLOT_SIZE] == 0)
            .ok_or_else(|| {
                io::Error::other("control registry is full (256 live sandboxes per user)")
            })?;
        let start = HEADER + slot * SLOT_SIZE;
        let mut metadata = [0u16; SLOT_SIZE - 1];
        metadata[0] = name.len() as u16;
        metadata[1..1 + TOKEN_WORDS].copy_from_slice(&token);
        for (dst, &byte) in metadata[1 + TOKEN_WORDS..].iter_mut().zip(name.as_bytes()) {
            *dst = byte as u16;
        }
        // SETALL would erase the undo adjustments of every live owner.
        for (offset, &value) in metadata.iter().enumerate() {
            checked(unsafe {
                libc::semctl(
                    self.0,
                    (start + 1 + offset) as i32,
                    libc::SETVAL,
                    SemArg {
                        value: value as i32,
                    },
                )
            })?;
        }
        self.adjust(start, 1)?;
        let owner = unsafe { libc::getpid() };
        let entry = Entry {
            name: name.into(),
            token: token.iter().map(|v| format!("{v:04x}")).collect(),
            supervisor: owner,
        };
        Ok(Claim {
            registry: self,
            slot,
            owner,
            entry,
        })
    }
}

struct Transaction {
    registry: Registry,
    owner: i32,
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if unsafe { libc::getpid() } == self.owner {
            let _ = self.registry.adjust(0, -1);
        }
    }
}

impl Claim {
    pub(crate) fn new(name: &str) -> io::Result<Self> {
        Registry::open(true)?.ok_or_else(invalid)?.claim(name)
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        // A host may drop inherited Rust objects after fork; it owns no undo adjustment.
        if unsafe { libc::getpid() } == self.owner {
            let _ = self.registry.adjust(HEADER + self.slot * SLOT_SIZE, -1);
        }
    }
}

pub(crate) fn list() -> io::Result<Vec<Entry>> {
    let Some(registry) = Registry::open(false)? else {
        return Ok(Vec::new());
    };
    let _lock = registry.lock()?;
    registry.entries(&registry.values()?)
}

pub(crate) fn lookup(name: &str) -> io::Result<Entry> {
    list()?
        .into_iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no sandbox named '{name}'"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::process::{Child, Command, Stdio};

    struct TestRegistry(Registry);

    impl TestRegistry {
        fn new() -> Self {
            let id = checked(unsafe { libc::semget(libc::IPC_PRIVATE, SEMAPHORES as i32, 0o600) })
                .unwrap();
            Self(Registry(id))
        }
    }

    impl Drop for TestRegistry {
        fn drop(&mut self) {
            unsafe {
                libc::semctl(self.0 .0, 0, libc::IPC_RMID);
            }
        }
    }

    struct Helper(Child, Option<i32>);

    impl Helper {
        fn start(registry: Registry, mode: &str) -> Self {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "control::ownership::tests::process_helper",
                    "--nocapture",
                ])
                .env("SANDLOCK_TEST_SEMID", registry.0.to_string())
                .env("SANDLOCK_TEST_SEM_MODE", mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            let mut lingering = None;
            loop {
                line.clear();
                assert!(
                    output.read_line(&mut line).unwrap() != 0,
                    "helper exited before ready"
                );
                if let Some(pid) = line.trim().strip_prefix("CHILD:") {
                    lingering = Some(pid.parse().unwrap());
                }
                if line.trim() == "READY" {
                    break;
                }
            }
            Self(child, lingering)
        }
    }

    impl Drop for Helper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn process_helper() {
        let Ok(id) = std::env::var("SANDLOCK_TEST_SEMID") else {
            return;
        };
        let registry = Registry(id.parse().unwrap());
        let mode = std::env::var("SANDLOCK_TEST_SEM_MODE").unwrap();
        let _claim;
        let _lock;
        if mode == "claim" {
            _claim = Some(registry.claim("crash-owner").unwrap());
            _lock = None;
        } else {
            _claim = None;
            _lock = Some(registry.lock().unwrap());
            // Simulate a publisher dying after one metadata write, before its claim.
            checked(unsafe {
                libc::semctl(
                    registry.0,
                    (HEADER + 1) as i32,
                    libc::SETVAL,
                    SemArg { value: 61 },
                )
            })
            .unwrap();
        }
        if mode == "claim" {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                unsafe {
                    let mut byte = 0u8;
                    libc::read(0, (&mut byte as *mut u8).cast(), 1);
                    libc::_exit(0);
                }
            }
            writeln!(std::io::stdout(), "CHILD:{pid}").unwrap();
        }
        std::io::stdout().write_all(b"READY\n").unwrap();
        std::io::stdout().flush().unwrap();
        let mut byte = [0];
        let _ = std::io::Read::read(&mut std::io::stdin(), &mut byte);
    }

    #[test]
    fn claims_are_exclusive_and_reuse_changes_the_instance() {
        let registry = TestRegistry::new();
        let claim = registry.0.claim("名字").unwrap();
        assert_eq!(
            registry.0.claim("名字").unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        let old_token = claim.entry.token.clone();
        drop(claim);
        let next = registry.0.claim("名字").unwrap();
        assert_ne!(next.entry.token, old_token);
        assert_eq!(
            registry.0.entries(&registry.0.values().unwrap()).unwrap()[0].name,
            "名字"
        );
    }

    #[test]
    fn killed_owner_releases_claim_and_preserves_other_owners() {
        let registry = TestRegistry::new();
        let ours = registry.0.claim("survivor").unwrap();
        let mut helper = Helper::start(registry.0, "claim");
        let _lingering_child_stdin = helper.0.stdin.take();
        assert_eq!(
            registry.0.claim("crash-owner").unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        let entries = registry.0.entries(&registry.0.values().unwrap()).unwrap();
        assert_eq!(
            entries
                .iter()
                .find(|e| e.name == "crash-owner")
                .unwrap()
                .supervisor,
            helper.0.id() as i32
        );
        helper.0.kill().unwrap();
        helper.0.wait().unwrap();
        assert_eq!(unsafe { libc::kill(helper.1.unwrap(), 0) }, 0);
        let _reused = registry.0.claim("crash-owner").unwrap();
        assert_eq!(
            registry.0.claim("survivor").unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        drop(ours);
    }

    #[test]
    fn killed_publisher_releases_transaction_and_partial_record() {
        let registry = TestRegistry::new();
        let mut helper = Helper::start(registry.0, "partial");
        helper.0.kill().unwrap();
        helper.0.wait().unwrap();
        let _claim = registry.0.claim("recovered").unwrap();
        let entries = registry.0.entries(&registry.0.values().unwrap()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "recovered");
    }

    #[test]
    fn dropping_an_inherited_claim_cannot_release_the_parent() {
        let registry = TestRegistry::new();
        let claim = registry.0.claim("parent").unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            drop(claim);
            unsafe {
                libc::_exit(0);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        assert_eq!(
            registry.0.claim("parent").unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
    }

    #[test]
    fn a_full_table_reports_exhaustion_and_reuses_released_slots() {
        let registry = TestRegistry::new();
        let mut claims = Vec::new();
        for i in 0..SLOTS {
            claims.push(registry.0.claim(&format!("slot-{i}")).unwrap());
        }
        assert!(registry
            .0
            .claim("overflow")
            .unwrap_err()
            .to_string()
            .contains("full"));
        claims.pop();
        let _replacement = registry.0.claim("replacement").unwrap();
    }
}
