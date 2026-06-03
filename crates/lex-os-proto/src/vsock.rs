//! Real `AF_VSOCK` transport — Linux only, requires `--features vsock`.
//!
//! The supervisor calls `VsockListener::bind(VSOCK_PORT)` before provisioning
//! the VM, then `accept()` once the guest boots and connects. The guest calls
//! `VsockStream::connect(HOST_CID, VSOCK_PORT)`.
//!
//! Both sides wrap their stream in `StreamTransport` / `StreamGuestTransport`.
//!
//! ## TODO (implement on the KVM host)
//! - `VsockListener::bind` — `socket(AF_VSOCK, SOCK_STREAM, 0)` + `bind` + `listen`
//! - `VsockListener::accept` — `accept` + wrap fd in `File` → `BufReader`/`BufWriter`
//! - `VsockStream::connect` — `socket` + `connect` with `sockaddr_vm { cid, port }`
//! - Add `libc` to `[dependencies]` in Cargo.toml when implementing

use std::io::BufReader;
use std::net::TcpStream;

use crate::transport::{StreamGuestTransport, StreamTransport};
use crate::{HOST_CID, VSOCK_PORT};

/// Host-side vsock listener. Call `bind()` before provisioning the VM so the
/// socket exists when the guest boots and tries to connect.
pub struct VsockListener {
    _port: u32,
}

impl VsockListener {
    /// Bind to the given vsock port on the host (CID = VMADDR_CID_HOST = 2).
    pub fn bind(port: u32) -> anyhow::Result<Self> {
        // TODO: libc::socket(AF_VSOCK, SOCK_STREAM, 0) + bind + listen
        let _ = port;
        anyhow::bail!("vsock not yet implemented — build on the KVM host")
    }

    /// Block until the guest connects. Returns a `StreamTransport` wrapping
    /// the accepted vsock fd.
    pub fn accept(
        &self,
    ) -> anyhow::Result<StreamTransport<BufReader<std::fs::File>, std::fs::File>> {
        // TODO: libc::accept → wrap raw fd
        anyhow::bail!("vsock not yet implemented — build on the KVM host")
    }
}

/// Guest-side vsock connection. Call `connect()` after the guest binary starts.
pub struct VsockStream;

impl VsockStream {
    /// Connect to the host supervisor. `cid` is usually `HOST_CID` (2).
    pub fn connect(
        cid: u32,
        port: u32,
    ) -> anyhow::Result<StreamGuestTransport<BufReader<std::fs::File>, std::fs::File>> {
        // TODO: libc::socket(AF_VSOCK, SOCK_STREAM, 0) + connect with sockaddr_vm
        let _ = (cid, port);
        anyhow::bail!("vsock not yet implemented — build on the KVM host")
    }
}

/// Convenience: host binds on `VSOCK_PORT`.
pub fn host_listener() -> anyhow::Result<VsockListener> {
    VsockListener::bind(VSOCK_PORT)
}

/// Convenience: guest connects to `HOST_CID:VSOCK_PORT`.
pub fn guest_connect(
) -> anyhow::Result<StreamGuestTransport<BufReader<std::fs::File>, std::fs::File>> {
    VsockStream::connect(HOST_CID, VSOCK_PORT)
}
