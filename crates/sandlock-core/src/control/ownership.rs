use std::io;

const HEADER: usize = 4;
const SIGNATURE: [u16; 3] = [0x534c, 0x434f, 5];
const NAME_BYTES: usize = 64;
const SLOTS: usize = 4096;
const SEMAPHORES: usize = HEADER + 2 * SLOTS;
const METADATA_HEADER: usize = 32;
const METADATA_BYTES: usize = METADATA_HEADER + SLOTS * std::mem::size_of::<Record>();
const BUCKETS: usize = 65_536;
const DIRECTORY_WORDS: usize = 5 + BUCKETS;
const DIRECTORY_BYTES: usize = DIRECTORY_WORDS * 8;

#[derive(Clone, Copy, Debug)]
struct Registry(i32, i32, i32);

#[repr(C)]
#[derive(Clone, Copy)]
struct Record {
    name: [u8; NAME_BYTES],
    token: [u8; 16],
    len: u8,
    next: u64,
}

struct Mapping(*mut Record);

impl Mapping {
    fn attach(id: i32, readonly: bool) -> io::Result<Self> {
        Self::attach_bytes(id, readonly, METADATA_BYTES)
    }

    fn attach_bytes(id: i32, readonly: bool, bytes: usize) -> io::Result<Self> {
        let _fork_guard = super::live();
        let address = unsafe {
            libc::shmat(
                id,
                std::ptr::null(),
                if readonly { libc::SHM_RDONLY } else { 0 },
            )
        };
        if address == (-1isize) as *mut libc::c_void {
            return Err(io::Error::last_os_error());
        }
        // In-process sandbox entrypoints must not inherit another thread's attachment.
        if unsafe { libc::madvise(address, bytes, libc::MADV_DONTFORK) } != 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::shmdt(address);
            }
            return Err(error);
        }
        Ok(Self(address.cast()))
    }

    fn read(&self, slot: usize) -> Record {
        assert!(slot < SLOTS);
        unsafe {
            self.0
                .cast::<u8>()
                .add(METADATA_HEADER)
                .cast::<Record>()
                .add(slot)
                .read_volatile()
        }
    }

    fn write(&mut self, slot: usize, record: Record) {
        assert!(slot < SLOTS);
        unsafe {
            self.0
                .cast::<u8>()
                .add(METADATA_HEADER)
                .cast::<Record>()
                .add(slot)
                .write_volatile(record);
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            libc::shmdt(self.0.cast());
        }
    }
}

#[derive(Debug)]
pub(crate) struct Claim {
    registry: Registry,
    slot: usize,
    owner: i32,
    token: [u8; 16],
    pub entry: Entry,
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub name: String,
    pub token: String,
    pub supervisor: i32,
    pub child: Option<i32>,
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

fn validate_permissions(perm: &libc::ipc_perm) -> io::Result<()> {
    let uid = unsafe { libc::getuid() };
    if perm.uid != uid || perm.cuid != uid || perm.mode & 0o777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control registry owned by another user or has unsafe permissions",
        ));
    }
    Ok(())
}

fn open_semaphores(key: libc::key_t, count: usize, create: bool) -> io::Result<i32> {
    let id = checked(unsafe {
        libc::semget(
            key,
            count as i32,
            0o600 | if create { libc::IPC_CREAT } else { 0 },
        )
    })?;
    let mut stat: libc::semid_ds = unsafe { std::mem::zeroed() };
    checked(unsafe { libc::semctl(id, 0, libc::IPC_STAT, SemArg { stat: &mut stat }) })?;
    validate_permissions(&stat.sem_perm)?;
    if stat.sem_nsems as usize != count {
        return Err(invalid());
    }
    Ok(id)
}

fn values(id: i32, count: usize) -> io::Result<Vec<u16>> {
    let mut values = vec![0; count];
    checked(unsafe {
        libc::semctl(
            id,
            0,
            libc::GETALL,
            SemArg {
                array: values.as_mut_ptr(),
            },
        )
    })?;
    Ok(values)
}

fn open_memory(key: libc::key_t, bytes: usize, create: bool) -> io::Result<i32> {
    let id = checked(unsafe {
        libc::shmget(key, bytes, 0o600 | if create { libc::IPC_CREAT } else { 0 })
    })?;
    let mut stat: libc::shmid_ds = unsafe { std::mem::zeroed() };
    checked(unsafe { libc::shmctl(id, libc::IPC_STAT, &mut stat) })?;
    validate_permissions(&stat.shm_perm)?;
    if stat.shm_segsz != bytes {
        return Err(invalid());
    }
    Ok(id)
}

fn initialize_signature(id: i32, count: usize) -> io::Result<()> {
    let snapshot = values(id, count)?;
    if snapshot[1..HEADER] == SIGNATURE {
        return Ok(());
    }
    if snapshot[1..].iter().any(|&v| v != 0) {
        return Err(invalid());
    }
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
    Ok(())
}

struct Directory(Mapping);
impl Directory {
    fn word(&self, index: usize) -> u64 {
        assert!(index < DIRECTORY_WORDS);
        unsafe { self.0 .0.cast::<u64>().add(index).read_volatile() }
    }
    fn put(&self, index: usize, value: u64) {
        assert!(index < DIRECTORY_WORDS);
        unsafe {
            self.0 .0.cast::<u64>().add(index).write_volatile(value);
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
    fn salt(&self) -> [u64; 2] {
        [self.word(0), self.word(1)]
    }
    fn recover(&self) -> io::Result<()> {
        let pending = self.word(3);
        if pending == 0 {
            return Ok(());
        }
        let cursor = self.word(2);
        let bucket = usize::try_from(self.word(4)).map_err(|_| invalid())?;
        if bucket >= BUCKETS
            || (pending != cursor && pending != cursor.checked_add(1).ok_or_else(invalid)?)
        {
            return Err(invalid());
        }
        if self.word(5 + bucket) == pending {
            self.put(2, pending);
        } else if pending <= cursor {
            return Err(invalid());
        }
        self.put(3, 0);
        Ok(())
    }
}

fn hash_name(name: &[u8]) -> u64 {
    name.iter().fold(0xcbf29ce484222325u64, |h, &byte| {
        (h ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    })
}

fn segment_key(salt: [u64; 2], segment: u64) -> libc::key_t {
    let mut value = segment.wrapping_add(salt[0]) ^ salt[1];
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    ((value ^ (value >> 31)) as u32).max(1) as libc::key_t
}

#[derive(Clone, Copy)]
struct Catalog {
    lock: i32,
    metadata: i32,
}
impl Catalog {
    fn open(create: bool) -> io::Result<Option<Self>> {
        let key = (unsafe { libc::getuid() } ^ 0x534c4305).max(1) as libc::key_t;
        let lock = match open_semaphores(key, HEADER, create) {
            Ok(id) => id,
            Err(e) if !create && e.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(e) => return Err(e),
        };
        let _lock = Registry(lock, -1, lock).lock()?;
        let signature = values(lock, HEADER)?;
        let initialize = signature[1..] == [0; 3];
        if !initialize && signature[1..] != SIGNATURE {
            return Err(invalid());
        }
        if initialize && !create {
            return Ok(None);
        }
        let metadata = open_memory(key, DIRECTORY_BYTES, create && initialize)?;
        let catalog = Self { lock, metadata };
        let directory = catalog.directory()?;
        if initialize {
            let salt = uuid::Uuid::new_v4().as_u128();
            directory.put(0, salt as u64);
            directory.put(1, (salt >> 64) as u64);
            initialize_signature(lock, HEADER)?;
        }
        directory.recover()?;
        Ok(Some(catalog))
    }

    fn directory(self) -> io::Result<Directory> {
        Ok(Directory(Mapping::attach_bytes(
            self.metadata,
            false,
            DIRECTORY_BYTES,
        )?))
    }

    fn segment(self, directory: &Directory, ordinal: u64, create: bool) -> io::Result<Registry> {
        Registry::open_segment(directory.salt(), ordinal, self.lock, create)
    }

    fn claim(self, name: &str) -> io::Result<Claim> {
        if name.is_empty() || name.len() > NAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control name must contain 1 to 64 bytes",
            ));
        }
        let _lock = Registry(self.lock, -1, self.lock).lock()?;
        let directory = self.directory()?;
        directory.recover()?;
        let bucket = hash_name(name.as_bytes()) as usize % BUCKETS;
        let mut reference = directory.word(5 + bucket);
        let mut available = None;
        let mut traversed = 0;
        while reference != 0 {
            if reference > directory.word(2) || traversed >= directory.word(2) {
                return Err(invalid());
            }
            traversed += 1;
            let registry = self.segment(&directory, (reference - 1) / SLOTS as u64, false)?;
            let slot = ((reference - 1) % SLOTS as u64) as usize;
            let mapping = Mapping::attach(registry.1, true)?;
            let record = mapping.read(slot);
            let owner =
                checked(unsafe { libc::semctl(registry.0, (HEADER + slot) as i32, libc::GETVAL) })?;
            if owner == 0 {
                available.get_or_insert(reference);
            } else {
                if owner != 1 || record.len == 0 || record.len as usize > NAME_BYTES {
                    return Err(invalid());
                }
                if &record.name[..record.len as usize] == name.as_bytes() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "sandbox name is already claimed",
                    ));
                }
            }
            reference = record.next;
        }
        let fresh = available.is_none();
        let reference = available.unwrap_or(directory.word(2).checked_add(1).ok_or_else(invalid)?);
        let registry = self.segment(&directory, (reference - 1) / SLOTS as u64, fresh)?;
        let slot = ((reference - 1) % SLOTS as u64) as usize;
        let mut mapping = Mapping::attach(registry.1, false)?;
        let next = if fresh {
            directory.word(5 + bucket)
        } else {
            mapping.read(slot).next
        };
        if fresh {
            directory.put(4, bucket as u64);
            directory.put(3, reference);
        }
        let token = *uuid::Uuid::new_v4().as_bytes();
        let mut record = Record {
            name: [0; NAME_BYTES],
            token,
            len: name.len() as u8,
            next,
        };
        record.name[..name.len()].copy_from_slice(name.as_bytes());
        mapping.write(slot, record);
        checked(unsafe {
            libc::semctl(
                registry.0,
                (HEADER + SLOTS + slot) as i32,
                libc::SETVAL,
                SemArg { value: 0 },
            )
        })?;
        if fresh {
            directory.put(5 + bucket, reference);
            directory.put(2, reference);
            directory.put(3, 0);
        }
        registry.adjust(HEADER + slot, 1)?;
        let owner = unsafe { libc::getpid() };
        Ok(Claim {
            registry,
            slot,
            owner,
            token,
            entry: Entry {
                name: name.into(),
                token: uuid::Uuid::from_bytes(token).simple().to_string(),
                supervisor: owner,
                child: None,
            },
        })
    }

    fn lookup(self, name: &str) -> io::Result<Option<Entry>> {
        let _lock = Registry(self.lock, -1, self.lock).lock()?;
        let directory = self.directory()?;
        directory.recover()?;
        let bucket = hash_name(name.as_bytes()) as usize % BUCKETS;
        let mut reference = directory.word(5 + bucket);
        let mut traversed = 0;
        while reference != 0 {
            if reference > directory.word(2) || traversed >= directory.word(2) {
                return Err(invalid());
            }
            traversed += 1;
            let registry = self.segment(&directory, (reference - 1) / SLOTS as u64, false)?;
            let slot = ((reference - 1) % SLOTS as u64) as usize;
            let record = Mapping::attach(registry.1, true)?.read(slot);
            if record.len as usize > NAME_BYTES {
                return Err(invalid());
            }
            if &record.name[..record.len as usize] == name.as_bytes() {
                let owner = checked(unsafe {
                    libc::semctl(registry.0, (HEADER + slot) as i32, libc::GETVAL)
                })? as u16;
                let child = checked(unsafe {
                    libc::semctl(registry.0, (HEADER + SLOTS + slot) as i32, libc::GETVAL)
                })? as u16;
                if let Some(entry) = registry.entry(slot, record, owner, child)? {
                    return Ok(Some(entry));
                }
            }
            reference = record.next;
        }
        Ok(None)
    }

    fn list(self) -> io::Result<Vec<Entry>> {
        let _lock = Registry(self.lock, -1, self.lock).lock()?;
        let directory = self.directory()?;
        directory.recover()?;
        let mut entries = Vec::new();
        for ordinal in 0..directory.word(2).div_ceil(SLOTS as u64) {
            let registry = self.segment(&directory, ordinal, false)?;
            entries.extend(registry.entries(&registry.values()?)?);
        }
        Ok(entries)
    }
}

impl Registry {
    fn open_segment(salt: [u64; 2], segment: u64, lock: i32, create: bool) -> io::Result<Self> {
        let key = segment_key(salt, segment);
        let metadata = open_memory(key, METADATA_BYTES, create)?;
        let header = Directory(Mapping::attach(metadata, false)?);
        let expected = [salt[0], salt[1], segment, 0x534c_434f_0000_0005];
        if header.word(3) == 0 && create {
            for (i, &value) in expected.iter().enumerate() {
                if header.word(i) != 0 && header.word(i) != value {
                    return Err(invalid());
                }
            }
            for (i, &value) in expected.iter().enumerate() {
                header.put(i, value);
            }
        } else if (0..4).any(|i| header.word(i) != expected[i]) {
            return Err(invalid());
        }
        let sem = open_semaphores(key, SEMAPHORES, create)?;
        initialize_signature(sem, SEMAPHORES)?;
        Ok(Self(sem, metadata, lock))
    }

    fn values(self) -> io::Result<Vec<u16>> {
        values(self.0, SEMAPHORES)
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
                    self.2,
                    ops.as_mut_ptr(),
                    ops.len(),
                    &timeout,
                )
            } as i32;
            match checked(result) {
                Ok(_) => {
                    return Ok(Transaction {
                        registry: Registry(self.2, -1, self.2),
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

    fn entry(
        self,
        slot: usize,
        record: Record,
        owner: u16,
        child: u16,
    ) -> io::Result<Option<Entry>> {
        if owner == 0 {
            return Ok(None);
        }
        if owner != 1 || record.len == 0 || record.len as usize > NAME_BYTES {
            return Err(invalid());
        }
        let supervisor =
            checked(unsafe { libc::semctl(self.0, (HEADER + slot) as i32, libc::GETPID) })?;
        if supervisor <= 0 {
            return Ok(None);
        }
        let child = match child {
            0 => None,
            1 => {
                let pid = checked(unsafe {
                    libc::semctl(self.0, (HEADER + SLOTS + slot) as i32, libc::GETPID)
                })?;
                (pid > 0).then_some(pid)
            }
            _ => return Err(invalid()),
        };
        Ok(Some(Entry {
            name: String::from_utf8(record.name[..record.len as usize].to_vec())
                .map_err(|_| invalid())?,
            token: uuid::Uuid::from_bytes(record.token).simple().to_string(),
            supervisor,
            child,
        }))
    }

    fn entries(self, owners: &[u16]) -> io::Result<Vec<Entry>> {
        let metadata = Mapping::attach(self.1, true)?;
        let mut entries = Vec::new();
        for slot in 0..SLOTS {
            if owners[HEADER + slot] == 0 {
                continue;
            }
            if let Some(entry) = self.entry(
                slot,
                metadata.read(slot),
                owners[HEADER + slot],
                owners[HEADER + SLOTS + slot],
            )? {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    #[cfg(test)]
    fn claim(self, name: &str) -> io::Result<Claim> {
        if name.is_empty() || name.len() > NAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control name must contain 1 to 64 bytes",
            ));
        }
        let token = *uuid::Uuid::new_v4().as_bytes();
        let _lock = self.lock()?;
        let owners = self.values()?;
        let mut metadata = Mapping::attach(self.1, false)?;
        let mut available = None;
        for slot in 0..SLOTS {
            if owners[HEADER + slot] == 0 {
                available.get_or_insert(slot);
                continue;
            }
            let record = metadata.read(slot);
            if owners[HEADER + slot] != 1 || record.len == 0 || record.len as usize > NAME_BYTES {
                return Err(invalid());
            }
            if &record.name[..record.len as usize] == name.as_bytes() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "sandbox name is already claimed",
                ));
            }
        }
        let slot = available.ok_or_else(|| {
            io::Error::other(format!(
                "control registry is full ({SLOTS} live sandboxes per user)"
            ))
        })?;
        let mut record = Record {
            name: [0; NAME_BYTES],
            token,
            len: name.len() as u8,
            next: 0,
        };
        record.name[..name.len()].copy_from_slice(name.as_bytes());
        metadata.write(slot, record);
        checked(unsafe {
            libc::semctl(
                self.0,
                (HEADER + SLOTS + slot) as i32,
                libc::SETVAL,
                SemArg { value: 0 },
            )
        })?;
        self.adjust(HEADER + slot, 1)?;
        let owner = unsafe { libc::getpid() };
        let entry = Entry {
            name: name.into(),
            token: uuid::Uuid::from_bytes(token).simple().to_string(),
            supervisor: owner,
            child: None,
        };
        Ok(Claim {
            registry: self,
            slot,
            owner,
            token,
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

#[derive(Clone, Copy)]
pub(crate) struct ChildPublisher {
    registry: Registry,
    slot: usize,
    token: [u8; 16],
}
impl ChildPublisher {
    pub(crate) fn publish(self) -> bool {
        self.try_publish().is_ok()
    }

    fn try_publish(self) -> io::Result<()> {
        let _lock = self.registry.lock()?;
        let metadata = Mapping::attach(self.registry.1, true)?;
        // Serialize the generation check with slot reuse without touching its owner stamp.
        if metadata.read(self.slot).token != self.token {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        let mut ops = [
            libc::sembuf {
                sem_num: (HEADER + SLOTS + self.slot) as u16,
                sem_op: 0,
                sem_flg: libc::IPC_NOWAIT as i16,
            },
            libc::sembuf {
                sem_num: (HEADER + SLOTS + self.slot) as u16,
                sem_op: 1,
                sem_flg: libc::IPC_NOWAIT as i16,
            },
        ];
        loop {
            match checked(unsafe { libc::semop(self.registry.0, ops.as_mut_ptr(), ops.len()) }) {
                Ok(_) => return Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl Claim {
    pub(crate) fn child_publisher(&self) -> ChildPublisher {
        ChildPublisher {
            registry: self.registry,
            slot: self.slot,
            token: self.token,
        }
    }
    pub(crate) fn new(name: &str) -> io::Result<Self> {
        Catalog::open(true)?.ok_or_else(invalid)?.claim(name)
    }
}
impl Drop for Claim {
    fn drop(&mut self) {
        // A host may drop inherited Rust objects after fork; it owns no undo adjustment.
        if unsafe { libc::getpid() } == self.owner {
            let _ = self.registry.adjust(HEADER + self.slot, -1);
        }
    }
}

pub(crate) fn list() -> io::Result<Vec<Entry>> {
    let Some(catalog) = Catalog::open(false)? else {
        return Ok(Vec::new());
    };
    catalog.list()
}

pub(crate) fn lookup(name: &str) -> io::Result<Entry> {
    let not_found = || {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no sandbox named '{name}'"),
        )
    };
    Catalog::open(false)?
        .ok_or_else(not_found)?
        .lookup(name)?
        .ok_or_else(not_found)
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
            let metadata =
                checked(unsafe { libc::shmget(libc::IPC_PRIVATE, METADATA_BYTES, 0o600) }).unwrap();
            Self(Registry(id, metadata, id))
        }
    }

    impl Drop for TestRegistry {
        fn drop(&mut self) {
            unsafe {
                libc::semctl(self.0 .0, 0, libc::IPC_RMID);
                libc::shmctl(self.0 .1, libc::IPC_RMID, std::ptr::null_mut());
            }
        }
    }

    struct TestCatalog(Catalog);
    impl TestCatalog {
        fn new() -> Self {
            let lock = open_semaphores(libc::IPC_PRIVATE, HEADER, true).unwrap();
            let metadata = open_memory(libc::IPC_PRIVATE, DIRECTORY_BYTES, true).unwrap();
            let catalog = Catalog { lock, metadata };
            let directory = catalog.directory().unwrap();
            let salt = uuid::Uuid::new_v4().as_u128();
            directory.put(0, salt as u64);
            directory.put(1, (salt >> 64) as u64);
            initialize_signature(lock, HEADER).unwrap();
            Self(catalog)
        }
    }
    impl Drop for TestCatalog {
        fn drop(&mut self) {
            let directory = self.0.directory().unwrap();
            for ordinal in 0..=directory.word(2).max(directory.word(3)) / SLOTS as u64 {
                let key = segment_key(directory.salt(), ordinal);
                unsafe {
                    let sem = libc::semget(key, 0, 0o600);
                    if sem >= 0 {
                        libc::semctl(sem, 0, libc::IPC_RMID);
                    }
                    let memory = libc::shmget(key, 0, 0o600);
                    if memory >= 0 {
                        libc::shmctl(memory, libc::IPC_RMID, std::ptr::null_mut());
                    }
                }
            }
            unsafe {
                libc::semctl(self.0.lock, 0, libc::IPC_RMID);
                libc::shmctl(self.0.metadata, libc::IPC_RMID, std::ptr::null_mut());
            }
        }
    }

    #[test]
    fn catalog_grows_past_31000_and_reuses_indexed_reservations() {
        let catalog = TestCatalog::new();
        let mut claims = Vec::new();
        for i in 0..40_000 {
            claims.push(catalog.0.claim(&format!("dense-{i}")).unwrap());
        }
        assert_eq!(catalog.0.list().unwrap().len(), 40_000);
        for i in [0, 4095, 4096, 30_999, 31_000, 39_999] {
            let entry = catalog.0.lookup(&format!("dense-{i}")).unwrap().unwrap();
            assert_eq!(entry.token, claims[i].entry.token);
        }
        assert_eq!(
            catalog.0.claim("dense-39999").unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        let allocated = catalog.0.directory().unwrap().word(2);
        let old = claims.pop().unwrap().entry.token.clone();
        let replacement = catalog.0.claim("dense-39999").unwrap();
        assert_ne!(replacement.entry.token, old);
        assert_eq!(catalog.0.directory().unwrap().word(2), allocated);
    }

    #[test]
    fn indexed_bucket_checks_duplicates_past_an_inactive_head() {
        let catalog = TestCatalog::new();
        let first = "first";
        let bucket = hash_name(first.as_bytes()) as usize % BUCKETS;
        let second = (0..)
            .map(|i| format!("collision-{i}"))
            .find(|name| hash_name(name.as_bytes()) as usize % BUCKETS == bucket)
            .unwrap();
        let _first = catalog.0.claim(first).unwrap();
        let second_claim = catalog.0.claim(&second).unwrap();
        drop(second_claim);
        assert_eq!(
            catalog.0.claim(first).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        assert!(catalog.0.lookup(first).unwrap().is_some());
        let _reused = catalog.0.claim(&second).unwrap();
        assert_eq!(catalog.0.list().unwrap().len(), 2);
    }

    #[test]
    fn killed_index_publisher_recovers_each_publication_stage() {
        for stage in [
            "index-before-head",
            "index-after-head",
            "index-after-cursor",
        ] {
            let catalog = TestCatalog::new();
            let mut helper = Helper::start(
                Registry(catalog.0.lock, catalog.0.metadata, catalog.0.lock),
                stage,
            );
            helper.0.kill().unwrap();
            helper.0.wait().unwrap();
            assert!(catalog.0.list().unwrap().is_empty());
            let _claim = catalog.0.claim("interrupted").unwrap();
            assert!(catalog.0.lookup("interrupted").unwrap().is_some());
            assert_eq!(catalog.0.directory().unwrap().word(2), 1);
        }
    }

    #[test]
    fn segment_identity_mismatch_preserves_existing_objects() {
        let catalog = TestCatalog::new();
        let claim = catalog.0.claim("owner").unwrap();
        let header = Directory(Mapping::attach(claim.registry.1, false).unwrap());
        let salt = header.word(0);
        header.put(0, salt ^ 1);
        assert_eq!(
            catalog.0.lookup("owner").unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            unsafe { libc::semctl(claim.registry.0, (HEADER + claim.slot) as i32, libc::GETVAL) },
            1
        );
        header.put(0, salt);
        assert!(catalog.0.lookup("owner").unwrap().is_some());
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
                .env(
                    "SANDLOCK_TEST_SEMID",
                    format!("{},{},{}", registry.0, registry.1, registry.2),
                )
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
        let ids: Vec<i32> = id.split(',').map(|v| v.parse().unwrap()).collect();
        let registry = Registry(ids[0], ids[1], ids[2]);
        let mode = std::env::var("SANDLOCK_TEST_SEM_MODE").unwrap();
        if mode.starts_with("index-") {
            let catalog = Catalog {
                lock: registry.0,
                metadata: registry.1,
            };
            let _lock = registry.lock().unwrap();
            let directory = catalog.directory().unwrap();
            let segment = catalog.segment(&directory, 0, true).unwrap();
            let bucket = hash_name(b"interrupted") as usize % BUCKETS;
            directory.put(4, bucket as u64);
            directory.put(3, 1);
            let mut record = Record {
                name: [0; NAME_BYTES],
                token: [0; 16],
                len: 11,
                next: 0,
            };
            record.name[..11].copy_from_slice(b"interrupted");
            Mapping::attach(segment.1, false).unwrap().write(0, record);
            if mode != "index-before-head" {
                directory.put(5 + bucket, 1);
            }
            if mode == "index-after-cursor" {
                directory.put(2, 1);
            }
            std::io::stdout().write_all(b"READY\n").unwrap();
            std::io::stdout().flush().unwrap();
            let mut byte = [0];
            let _ = std::io::Read::read(&mut std::io::stdin(), &mut byte);
            return;
        }
        let _claim;
        let _lock;
        if mode == "claim" {
            _claim = Some(registry.claim("crash-owner").unwrap());
            _lock = None;
        } else {
            _claim = None;
            _lock = Some(registry.lock().unwrap());
            let mut metadata = Mapping::attach(registry.1, false).unwrap();
            metadata.write(
                0,
                Record {
                    name: [0; NAME_BYTES],
                    token: [0; 16],
                    len: 61,
                    next: 0,
                },
            );
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
    fn child_publication_cannot_touch_a_reused_slot_or_its_owner_stamp() {
        let registry = TestRegistry::new();
        let first = registry.0.claim("first").unwrap();
        let stale = first.child_publisher();
        drop(first);
        let replacement = registry.0.claim("replacement").unwrap();
        assert!(!stale.publish());
        let publisher = replacement.child_publisher();
        let child = super::super::fork_without_control_fds();
        assert!(child >= 0);
        if child == 0 {
            let published = publisher.publish();
            unsafe {
                libc::_exit(if published { 0 } else { 1 });
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0);
        let entry = registry
            .0
            .entries(&registry.0.values().unwrap())
            .unwrap()
            .remove(0);
        assert_eq!(entry.supervisor, unsafe { libc::getpid() });
        assert_eq!(entry.child, Some(child));
        assert!(
            !publisher.publish(),
            "a second publisher must not replace the child stamp"
        );
    }

    #[test]
    fn metadata_mapping_is_not_inherited_by_a_sandbox_child() {
        let registry = TestRegistry::new();
        let mapping = Mapping::attach(registry.0 .1, false).unwrap();
        let pid = super::super::fork_without_control_fds();
        assert!(pid >= 0);
        if pid == 0 {
            let mut residency = 0u8;
            let result = unsafe { libc::mincore(mapping.0.cast(), 1, &mut residency) };
            let absent =
                result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOMEM);
            unsafe {
                libc::_exit(if absent { 0 } else { 1 });
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
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
