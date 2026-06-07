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
    /// Spawn firecracker directly (unjailed, as the current user — root in the
    /// demos). `sock` is both what we pass `--api-sock` and where the host
    /// connects.
    pub(super) fn spawn(sock: PathBuf) -> Result<Self, VmError> {
        let argv = build_firecracker_argv(&sock);
        Self::spawn_program("firecracker", argv, sock)
    }

    /// Spawn via an arbitrary launcher (the jailer) with a pre-built argv.
    /// `host_sock` is where the *host* reaches the API socket (under the jail
    /// chroot it differs from the in-jail `--api-sock` path inside `argv`).
    pub(super) fn spawn_jailed(
        jailer_bin: &str,
        argv: Vec<String>,
        host_sock: PathBuf,
    ) -> Result<Self, VmError> {
        Self::spawn_program(jailer_bin, argv, host_sock)
    }

    fn spawn_program(program: &str, argv: Vec<String>, sock: PathBuf) -> Result<Self, VmError> {
        if Command::new(program).arg("--version").output().is_err() {
            return Err(VmError::MissingBinary);
        }
        // Inherit stdout/stderr so the guest serial console (ttyS0 → firecracker
        // stdout) streams live to the operator — that's where the Wall-2 egress
        // probes from init-attack.sh appear. (Folding the console into the audit
        // log is a follow-up; for now it must at least be visible.)
        let child = Command::new(program)
            .args(&argv)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(VmError::Spawn)?;
        Ok(Self { sock, child })
    }

    pub(super) fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for FirecrackerVm {
    /// Defense-in-depth: if the handle is dropped without an explicit
    /// `kill()` (e.g. a partial provision, or a panic between spawn and being
    /// stored), reap the child so we never orphan a firecracker process.
    fn drop(&mut self) {
        self.kill();
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
