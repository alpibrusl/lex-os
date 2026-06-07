//! Jailer integration: run firecracker chrooted and privilege-dropped.
//!
//! Without the jailer, the perimeter spawns `firecracker` directly as root — a
//! VM escape would land in a root context on the host, the opposite of "sealed
//! at the edge". `jailer` wraps firecracker in a per-VM chroot, drops to a
//! non-root `uid:gid`, and sets up a cgroup before exec'ing firecracker.
//!
//! The cost is a two-world path layout: things firecracker names (kernel,
//! rootfs, API socket, vsock UDS) are *inside* the chroot, while the host
//! supervisor — which stays root — addresses the same files at their
//! host-visible location under the jail root. [`Layout`] (in the parent module)
//! holds both halves; this module owns the jailer-specific path math and argv.

use std::path::{Path, PathBuf};

/// How to launch firecracker under the jailer.
#[derive(Debug, Clone)]
pub struct JailConfig {
    /// Non-root uid firecracker is dropped to.
    pub uid: u32,
    /// Group firecracker runs as — must be the `kvm` group so `/dev/kvm`
    /// (mode 660 root:kvm) is reachable from inside the jail.
    pub gid: u32,
    /// Directory under which jailer builds `firecracker/<id>/root/`.
    pub chroot_base: PathBuf,
    /// Per-VM identifier; also the chroot subdirectory name. Kept stable across
    /// reprovisions so the host vsock path doesn't move under the supervisor.
    pub id: String,
    /// The jailer binary (on PATH or an absolute path).
    pub jailer_bin: String,
}

/// The per-VM jail directory jailer owns: `<base>/firecracker/<id>`. Removing
/// this tree on teardown clears the chroot, the staged assets, and the sockets.
pub(super) fn chroot_id_dir(cfg: &JailConfig) -> PathBuf {
    cfg.chroot_base.join("firecracker").join(&cfg.id)
}

/// The chroot root jailer builds for this VM: `<base>/firecracker/<id>/root`.
/// Everything firecracker references by an in-jail absolute path resolves to
/// this directory on the host.
pub(super) fn chroot_root(cfg: &JailConfig) -> PathBuf {
    chroot_id_dir(cfg).join("root")
}

/// Best-effort guess of the cgroup-v2 directory jailer creates for this VM
/// (`<cgroup2-mount>/<exec-file-name>/<id>`). Removed on teardown so a
/// reprovision with the same id doesn't trip over a leftover cgroup.
pub(super) fn cgroup_v2_dir(cfg: &JailConfig) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
        .join("firecracker")
        .join(&cfg.id)
}

/// Build the jailer argv. Everything after `--` is firecracker's own args;
/// `api_sock_in_jail` is the socket path *as firecracker sees it* (relative to
/// the chroot root, e.g. `/fc.sock`).
pub(super) fn build_jailer_argv(
    cfg: &JailConfig,
    exec_file: &Path,
    api_sock_in_jail: &str,
) -> Vec<String> {
    vec![
        "--id".into(),
        cfg.id.clone(),
        "--exec-file".into(),
        exec_file.display().to_string(),
        "--uid".into(),
        cfg.uid.to_string(),
        "--gid".into(),
        cfg.gid.to_string(),
        "--chroot-base-dir".into(),
        cfg.chroot_base.display().to_string(),
        "--cgroup-version".into(),
        "2".into(),
        // Firecracker's own args follow.
        "--".into(),
        "--api-sock".into(),
        api_sock_in_jail.into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> JailConfig {
        JailConfig {
            uid: 1002,
            gid: 107,
            chroot_base: PathBuf::from("/srv/jail"),
            id: "lexbox".into(),
            jailer_bin: "jailer".into(),
        }
    }

    #[test]
    fn chroot_root_follows_jailer_layout() {
        assert_eq!(
            chroot_root(&cfg()),
            PathBuf::from("/srv/jail/firecracker/lexbox/root")
        );
    }

    #[test]
    fn jailer_argv_drops_privs_and_chroots_then_passes_fc_args() {
        let argv = build_jailer_argv(&cfg(), Path::new("/usr/local/bin/firecracker"), "/fc.sock");
        // Identity + isolation flags jailer needs.
        for pair in [
            ("--id", "lexbox"),
            ("--exec-file", "/usr/local/bin/firecracker"),
            ("--uid", "1002"),
            ("--gid", "107"),
            ("--chroot-base-dir", "/srv/jail"),
            ("--cgroup-version", "2"),
        ] {
            let i = argv.iter().position(|a| a == pair.0).expect(pair.0);
            assert_eq!(argv[i + 1], pair.1, "value after {}", pair.0);
        }
        // Firecracker args come strictly after the `--` separator.
        let sep = argv.iter().position(|a| a == "--").expect("-- separator");
        let sock = argv.iter().position(|a| a == "--api-sock").unwrap();
        assert!(sock > sep, "--api-sock must follow the -- separator");
        assert_eq!(argv[sock + 1], "/fc.sock");
    }
}
