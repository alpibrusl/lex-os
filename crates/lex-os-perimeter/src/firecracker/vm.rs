//! Firecracker child-process lifecycle (spawn + wait-for-socket + SIGKILL).

// Some items are wired into provision()/destroy() in a later task (#14);
// allow dead_code until then.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use super::api::ApiError;

#[derive(Debug, thiserror::Error)]
pub(super) enum VmError {
    #[error("spawn firecracker: {0}")]
    Spawn(std::io::Error),
    #[error("firecracker binary not found on PATH")]
    MissingBinary,
    #[error("api: {0}")]
    Api(#[from] ApiError),
}

pub(super) struct FirecrackerVm {
    pub(super) sock: PathBuf,
    pub(super) child: Child,
}

impl FirecrackerVm {
    pub(super) fn spawn(sock: PathBuf) -> Result<Self, VmError> {
        if Command::new("firecracker")
            .arg("--version")
            .output()
            .is_err()
        {
            return Err(VmError::MissingBinary);
        }
        let argv = build_firecracker_argv(&sock);
        let child = Command::new("firecracker")
            .args(&argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(VmError::Spawn)?;
        Ok(Self { sock, child })
    }

    pub(super) fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(super) fn build_firecracker_argv(sock: &Path) -> Vec<String> {
    vec!["--api-sock".to_string(), sock.display().to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_firecracker_argv_uses_the_api_sock() {
        let argv = build_firecracker_argv(&PathBuf::from("/tmp/fc.sock"));
        assert_eq!(
            argv,
            vec!["--api-sock".to_string(), "/tmp/fc.sock".to_string()]
        );
    }
}
