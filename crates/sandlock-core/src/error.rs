use thiserror::Error;

/// Root error type for all sandlock operations.
#[derive(Debug, Error)]
pub enum SandlockError {
    #[error("policy error: {0}")]
    Policy(#[from] PolicyError),

    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("memory protection error: {0}")]
    MemoryProtect(String),

    #[error("handler error: {0}")]
    Handler(#[from] crate::seccomp::dispatch::HandlerError),
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid policy: {0}")]
    Invalid(String),

    #[error("fs_isolation requires workdir to be set")]
    FsIsolationRequiresWorkdir,

    #[error("max_cpu must be 1-100, got {0}")]
    InvalidCpuPercent(u8),

    #[error("confine() only accepts Landlock filesystem policy; unsupported fields: {0}")]
    UnsupportedForConfine(String),
}

#[derive(Debug, Error)]
pub enum SandboxError {
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

    #[error("landlock ABI v{required} required (kernel has v{actual}): {feature}")]
    InsufficientAbi {
        required: u32,
        actual: u32,
        feature: String,
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
