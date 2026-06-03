//! Host side of the Firecracker vsock channel — plain Unix sockets, std only.
//!
//! With Firecracker's UDS-backed vsock and a *guest-initiated* connection, the
//! guest's `AF_VSOCK` connect to `(2, PORT)` makes Firecracker connect to the
//! host Unix socket at `${uds_path}_${PORT}`. So the host just needs to be
//! listening there before the guest boots — no `AF_VSOCK`, no `libc`.

use std::io::BufReader;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use crate::transport::StreamTransport;
use crate::VSOCK_PORT;

/// A bound Unix listener at `${uds_path}_${port}`, ready for Firecracker to
/// connect to when the guest opens its vsock channel.
pub struct FcVsockHost {
    listener: UnixListener,
    path: std::path::PathBuf,
}

impl FcVsockHost {
    /// Bind the host socket Firecracker will connect to for guest port `port`.
    /// Call this *before* `InstanceStart` so the socket exists when the guest
    /// connects during boot.
    pub fn bind(uds_path: &Path, port: u32) -> anyhow::Result<Self> {
        let path = std::path::PathBuf::from(format!("{}_{}", uds_path.display(), port));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)
            .map_err(|e| anyhow::anyhow!("bind {}: {e}", path.display()))?;
        Ok(Self { listener, path })
    }

    /// Bind on the conventional [`VSOCK_PORT`].
    pub fn bind_default(uds_path: &Path) -> anyhow::Result<Self> {
        Self::bind(uds_path, VSOCK_PORT)
    }

    /// Block until the guest connects, returning a host-side [`StreamTransport`].
    pub fn accept(&self) -> anyhow::Result<StreamTransport<BufReader<UnixStream>, UnixStream>> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|e| anyhow::anyhow!("accept: {e}"))?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(StreamTransport::new(reader, stream))
    }
}

impl Drop for FcVsockHost {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
