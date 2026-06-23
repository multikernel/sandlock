//! Sandlock OCI runtime shim library.
//!
//! Provides OCI spec parsing, policy translation, and state management
//! for use by the sandlock-oci binary and integration tests.
//!
//! ## Key types
//!
//! - [`OciPolicy`] — in-memory representation of the translated OCI config
//! - [`SandboxState`] — on-disk lifecycle state for a sandbox
//! - [`SupervisorCmd`] / [`SupervisorReply`] — IPC messages for the supervisor

pub mod fdpass;
pub mod init;
pub mod policy;
pub mod spec;
pub mod state;
pub mod supervisor;

pub use policy::OciPolicy;
pub use state::{SandboxState, ExitInfo, Status};
pub use supervisor::{SupervisorCmd, SupervisorReply, SUPERVISOR_SOCKET};