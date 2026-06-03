//! Real `AF_VSOCK` transport for the **guest** side — Linux only, requires
//! `--features vsock` (pulls in `libc`).
//!
//! Firecracker's vsock is host-UDS-backed and *guest-initiated* here: the guest
//! opens an `AF_VSOCK` socket to `(HOST_CID=2, VSOCK_PORT)`; Firecracker then
//! connects to the host's Unix socket at `${uds_path}_${VSOCK_PORT}`. So only
//! the guest needs `AF_VSOCK`/`libc`; the host side is a plain `UnixListener`
//! (see [`crate::fc_host`]) and needs no special privileges or crates.

use std::fs::File;
use std::io::BufReader;
use std::os::unix::io::FromRawFd;
use std::time::{Duration, Instant};

use crate::transport::StreamGuestTransport;
use crate::{HOST_CID, VSOCK_PORT};

/// Connect the guest to the host supervisor over vsock, retrying for a few
/// seconds while the host listener / firecracker device come up during boot.
pub fn guest_connect() -> anyhow::Result<StreamGuestTransport<BufReader<File>, File>> {
    connect_retry(HOST_CID, VSOCK_PORT, Duration::from_secs(15))
}

fn connect_retry(
    cid: u32,
    port: u32,
    timeout: Duration,
) -> anyhow::Result<StreamGuestTransport<BufReader<File>, File>> {
    let deadline = Instant::now() + timeout;
    let mut last_err = None;
    while Instant::now() < deadline {
        match connect_once(cid, port) {
            Ok(t) => return Ok(t),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("vsock connect timed out")))
}

fn connect_once(
    cid: u32,
    port: u32,
) -> anyhow::Result<StreamGuestTransport<BufReader<File>, File>> {
    // SAFETY: standard socket(2)/connect(2) FFI; we own the fd and wrap it in a
    // `File` that closes it on drop. `sockaddr_vm` is zeroed then populated.
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!("socket(AF_VSOCK): {e}"));
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;
        let ret = libc::connect(
            fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(anyhow::anyhow!("connect(vsock {cid}:{port}): {e}"));
        }
        let file = File::from_raw_fd(fd);
        let reader = BufReader::new(file.try_clone()?);
        Ok(StreamGuestTransport::new(reader, file))
    }
}
