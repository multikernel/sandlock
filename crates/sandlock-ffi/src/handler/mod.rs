//! FFI surface for the sandlock `Handler` trait. See `docs/extension-handlers.md`.
//!
//! Split across three submodules for clarity:
//!   * [`abi`]     — public ABI types, setters, and accessor entry points.
//!   * [`adapter`] — `FfiHandler` adapter implementing `Handler`.
//!   * [`run`]     — `sandlock_run_with_handlers` entry points and helpers.

pub mod abi;
pub mod adapter;
pub mod run;

// Re-export every symbol that was at `sandlock_ffi::handler::FOO` before
// the split so external tests and downstream consumers do not break.
pub use abi::*;
pub use adapter::FfiHandler;
pub use run::{sandlock_run_interactive_with_handlers, sandlock_run_with_handlers};
