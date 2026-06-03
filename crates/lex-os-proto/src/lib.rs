//! Wire protocol between the lex-os supervisor (host) and the agent binary
//! running inside the microVM (guest).
//!
//! ## Design
//!
//! The protocol is intentionally minimal: one newline-terminated JSON line
//! per step in each direction. The supervisor sends an `AgentViewMsg` (the
//! agent's observable state); the guest responds with an `AgentActionMsg`.
//! Synchronous, one outstanding message at a time — no multiplexing needed.
//!
//! ```text
//! Host (supervisor)          Guest (agent binary)
//! ─────────────────          ────────────────────
//! send AgentViewMsg    →     recv AgentViewMsg
//!                            reason (call Ollama)
//! recv AgentActionMsg  ←     send AgentActionMsg
//! mediate action
//! (repeat)
//! ```
//!
//! The `Transport` trait abstracts the byte channel so the same `VsockAgent`
//! and guest binary can be driven by an in-process pair in tests or a real
//! `AF_VSOCK` socket on a KVM host.

pub mod msg;
pub mod transport;

pub use msg::{AgentActionMsg, AgentViewMsg};
pub use transport::{simulated_pair, SimulatedTransport, Transport};

/// Host-side Firecracker vsock channel (plain Unix sockets, std only).
#[cfg(unix)]
pub mod fc_host;

/// The vsock port the supervisor listens on and the guest connects to.
/// Guest CID is assigned by the hypervisor; host CID is always 2.
pub const VSOCK_PORT: u32 = 7234;
/// Host CID in every Firecracker guest.
pub const HOST_CID: u32 = 2;

/// Real `AF_VSOCK` transport — Linux only.
/// Gate behind `--features vsock` so the crate compiles on macOS during
/// development and only pulls in `libc` on KVM hosts.
#[cfg(all(feature = "vsock", target_os = "linux"))]
pub mod vsock;
