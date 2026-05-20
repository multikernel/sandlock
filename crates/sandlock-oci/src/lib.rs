//! Sandlock OCI runtime shim library.
//!
//! Provides OCI spec parsing, policy translation, and state management
//! for use by the sandlock-oci binary and integration tests.
//!
//! ## Key types
//!
//! - [`OciPolicy`] — in-memory representation of the translated OCI config
//! - [`ContainerState`] — on-disk lifecycle state for a container
//! - [`SupervisorCmd`] / [`SupervisorReply`] — IPC messages for the supervisor

pub mod policy;
pub mod spec;
pub mod state;
pub mod supervisor;

pub use policy::OciPolicy;
pub use state::{ContainerState, ExitInfo, Status};
pub use supervisor::{SupervisorCmd, SupervisorReply, SUPERVISOR_SOCKET};