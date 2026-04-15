//! NETLINK_ROUTE virtualization for sandboxed processes.
//!
//! Presents a synthetic network view (one loopback interface) without
//! exposing real host netlink.  See `state.rs` for the fd registry and
//! `handlers.rs` for seccomp-notify integration.

pub mod handlers;
pub mod proto;
pub mod proxy;
pub mod state;
pub mod synth;

pub use state::NetlinkState;
