use thiserror::Error;

/// Root error type for all sandlock operations.
#[derive(Debug, Error)]
pub enum SandlockError {
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("process error: {0}")]
    Runtime(#[from] SandboxRuntimeError),

    #[error("memory protection error: {0}")]
    MemoryProtect(String),

    #[error("handler error: {0}")]
    Handler(#[from] crate::seccomp::dispatch::HandlerError),
}

/// Errors from sandbox configuration validation and building.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("invalid sandbox: {0}")]
    Invalid(String),

    #[error("max_cpu must be 1-100, got {0}")]
    InvalidCpuPercent(u8),

    #[error("confine() only accepts Landlock filesystem policy; unsupported fields: {0}")]
    UnsupportedForConfine(String),

    #[error("chroot path {path} does not exist or is inaccessible: {source}")]
    ChrootNotFound {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Errors from the sandbox process runtime (fork, confinement, child, etc.).
#[derive(Debug, Error)]
pub enum SandboxRuntimeError {
    #[error("fork failed: {0}")]
    Fork(#[source] std::io::Error),

    #[error("confinement failed: {0}")]
    Confinement(#[from] ConfinementError),

    #[error("child process error: {0}")]
    Child(String),

    #[error("branch error: {0}")]
    Branch(#[from] BranchError),

    #[error("sandbox not running")]
    NotRunning,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum ConfinementError {
    #[error("landlock unavailable: {0}")]
    LandlockUnavailable(String),

    /// A `Protection` in `ProtectionState::Strict` is unavailable
    /// because the host kernel's Landlock ABI is below the
    /// protection's `min_abi()`. Build (or `confine`) refuses to
    /// proceed; the caller can resolve by setting that protection to
    /// `Degradable` or `Disabled`, or by running on a kernel that
    /// supports it.
    #[error("required protection {protection:?} is not available: host Landlock ABI is v{host_abi}, requires v{required_abi}")]
    ProtectionUnavailable {
        protection: crate::protection::Protection,
        required_abi: u32,
        host_abi: u32,
    },

    #[error("landlock error: {0}")]
    Landlock(String),

    #[error("seccomp error: {0}")]
    Seccomp(#[from] SeccompError),
}

#[derive(Debug, Error)]
pub enum SeccompError {
    #[error("seccomp filter installation failed: {0}")]
    FilterInstall(String),

    #[error("notification error: {0}")]
    Notif(#[from] NotifError),
}

#[derive(Debug, Error)]
pub enum NotifError {
    #[error("notification supervisor error: {0}")]
    Supervisor(String),

    #[error("child memory read failed: {0}")]
    ChildMemoryRead(#[source] std::io::Error),

    #[error("notification ioctl failed: {0}")]
    Ioctl(#[source] std::io::Error),
}

#[derive(Debug, Error)]
pub enum BranchError {
    #[error("branch operation failed: {0}")]
    Operation(String),

    #[error("branch conflict: {0}")]
    Conflict(String),

    #[error("disk quota exceeded")]
    QuotaExceeded,

    #[error("file already exists")]
    Exists,
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, SandlockError>;
