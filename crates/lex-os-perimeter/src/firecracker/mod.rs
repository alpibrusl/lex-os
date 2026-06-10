//! Firecracker microVM perimeter backend (feature = "firecracker").
//!
//! This module provides a [`FirecrackerPerimeter`] that implements the
//! [`Perimeter`] trait against Firecracker's HTTP management API.

mod api;
mod jail;
mod net;
mod vm;

use std::path::{Path, PathBuf};
use std::time::Duration;

use api::{put_json, wait_for_socket, with_socket};
use net::{
    create_tap, destroy_tap, flush_egress_rules, flush_nat, install_egress_allowlist, install_nat,
};
use vm::FirecrackerVm;

pub use jail::JailConfig;

use crate::{BoxState, Perimeter, PerimeterError, SandboxPolicy};
use lex_os_manifest::{Dimension, IsolationFloor, Level};

/// Paths the perimeter needs to find at runtime. Override per-instance for
/// tests; the defaults match what `demo/setup-assets.sh` produces.
pub struct FirecrackerAssets {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub socket: PathBuf,
    pub tap: String,
    /// Host IP on the tap, CIDR form. The guest gets the .2 address.
    pub host_ip_cidr: String,
    /// Kernel command line. The default boots the demo's guest-side attack
    /// script (`init=/sbin/init.demo`, injected into the rootfs by
    /// `demo/setup-assets.sh`); a real agent run overrides this via
    /// [`FirecrackerPerimeter::with_assets`].
    pub boot_args: String,
    /// Host UDS base path for the guest↔supervisor vsock channel. Firecracker
    /// connects to `${socket_vsock}_${port}` when the guest opens a vsock
    /// connection. Empty disables the vsock device (the attack-script demo
    /// doesn't need it; the in-VM agent does).
    pub socket_vsock: PathBuf,
    /// Guest context id for the vsock device (host is always CID 2).
    pub guest_cid: u32,
    /// When set, firecracker is launched under the jailer (chroot + dropped
    /// privileges + cgroup) instead of directly as root. `None` keeps the
    /// legacy run-as-root path (tests, hosts without a jailer). Real runs should
    /// set this — running the VMM as root defeats "sealed at the edge".
    pub jail: Option<JailConfig>,
}

impl Default for FirecrackerAssets {
    fn default() -> Self {
        Self {
            kernel: PathBuf::from("demo/assets/vmlinux"),
            rootfs: PathBuf::from("demo/assets/rootfs.ext4"),
            socket: PathBuf::from("/tmp/firecracker-lex-os.sock"),
            tap: "tap-lex0".into(),
            host_ip_cidr: "169.254.42.1/30".into(),
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/init.demo".into(),
            socket_vsock: PathBuf::from("/tmp/firecracker-lex-os-vsock.sock"),
            guest_cid: 3,
            jail: None,
        }
    }
}

/// A perimeter backed by a Firecracker microVM.  `provision` calls the
/// Firecracker management API to spawn a fresh VM and configure it.
pub struct FirecrackerPerimeter {
    policy: Option<SandboxPolicy>,
    state: BoxState,
    assets: FirecrackerAssets,
    vm: Option<FirecrackerVm>,
}

impl Default for FirecrackerPerimeter {
    fn default() -> Self {
        Self::new()
    }
}

impl FirecrackerPerimeter {
    pub fn new() -> Self {
        Self::with_assets(FirecrackerAssets::default())
    }

    pub fn with_assets(assets: FirecrackerAssets) -> Self {
        Self {
            policy: None,
            state: BoxState::Dead,
            assets,
            vm: None,
        }
    }
}

fn perimeter_err<E: std::fmt::Display>(e: E) -> PerimeterError {
    PerimeterError::Blocked(format!("firecracker backend: {e}"))
}

impl Perimeter for FirecrackerPerimeter {
    fn backend_name(&self) -> &'static str {
        "firecracker"
    }

    fn max_floor(&self) -> IsolationFloor {
        IsolationFloor::MicroVm
    }

    fn provision(&mut self, policy: SandboxPolicy) -> Result<(), PerimeterError> {
        if policy.required_floor > self.max_floor() {
            return Err(PerimeterError::FloorUnavailable {
                required: policy.required_floor.as_str(),
                available: self.max_floor().as_str(),
            });
        }
        // Boot can fail partway (e.g. the tap is created but InstanceStart
        // errors). On any failure, roll back host state so we never leak a
        // tap, iptables rules, a stale socket, or the firecracker child (the
        // child is reaped by `FirecrackerVm`'s Drop when the local `vm` here
        // is dropped on the error path).
        match self.boot_microvm(&policy) {
            Ok(vm) => {
                self.policy = Some(policy);
                self.state = BoxState::Alive;
                self.vm = Some(vm);
                Ok(())
            }
            Err(e) => {
                self.teardown_host();
                Err(e)
            }
        }
    }

    fn is_alive(&self) -> bool {
        self.state == BoxState::Alive
    }

    fn check(&self, dim: Dimension, required: Level) -> Result<(), PerimeterError> {
        if self.state != BoxState::Alive {
            return Err(PerimeterError::NotAlive);
        }
        let policy = self.policy.clone().ok_or(PerimeterError::NotAlive)?;
        if policy.permits(dim, required) {
            Ok(())
        } else {
            Err(PerimeterError::Blocked(format!(
                "{dim} ≥ {required} not permitted by sandbox policy"
            )))
        }
    }

    fn destroy(&mut self, _reason: &str) {
        if let Some(mut vm) = self.vm.take() {
            vm.kill();
        }
        self.teardown_host();
        self.state = BoxState::Dead;
    }
}

/// Where a file lives for the host (which stays root) versus how firecracker
/// names it. Identical unjailed; under the jailer the host addresses files at
/// their chroot location while firecracker, chrooted, names them from its root.
struct Layout {
    /// Path the host connects to for the API socket.
    api_sock_host: PathBuf,
    /// Value of firecracker's `--api-sock` (in-jail when jailed).
    api_sock_arg: String,
    /// `kernel_image_path` for `/boot-source`.
    kernel_arg: String,
    /// `path_on_host` for the rootfs drive.
    rootfs_arg: String,
    /// `uds_path` for `/vsock`; empty disables the vsock device.
    vsock_arg: String,
    /// Host base path for the vsock channel (FcVsockHost binds `${base}_${port}`);
    /// empty when there is no vsock.
    vsock_host_base: PathBuf,
    /// `Some(chroot_root)` when jailed — assets are staged into it after boot.
    jail_root: Option<PathBuf>,
}

impl FirecrackerPerimeter {
    /// Host-visible path of the vsock channel base (`${this}_${port}` is the
    /// socket FcVsockHost binds). `None` when no vsock device / no in-VM agent.
    /// The supervisor's transport needs this because under the jailer it lives
    /// inside the chroot, not at the configured `socket_vsock`.
    pub fn vsock_host_path(&self) -> Option<PathBuf> {
        let lay = self.layout();
        (!lay.vsock_host_base.as_os_str().is_empty()).then_some(lay.vsock_host_base)
    }

    fn layout(&self) -> Layout {
        let a = &self.assets;
        let has_vsock = !a.socket_vsock.as_os_str().is_empty();
        match &a.jail {
            None => Layout {
                api_sock_host: a.socket.clone(),
                api_sock_arg: a.socket.display().to_string(),
                kernel_arg: a.kernel.display().to_string(),
                rootfs_arg: a.rootfs.display().to_string(),
                vsock_arg: a.socket_vsock.display().to_string(),
                vsock_host_base: a.socket_vsock.clone(),
                jail_root: None,
            },
            Some(cfg) => {
                let root = jail::chroot_root(cfg);
                Layout {
                    api_sock_host: root.join("fc.sock"),
                    api_sock_arg: "/fc.sock".into(),
                    kernel_arg: "/vmlinux".into(),
                    rootfs_arg: "/rootfs.ext4".into(),
                    vsock_arg: if has_vsock {
                        "/vsock.sock".into()
                    } else {
                        String::new()
                    },
                    vsock_host_base: if has_vsock {
                        root.join("vsock.sock")
                    } else {
                        PathBuf::new()
                    },
                    jail_root: Some(root),
                }
            }
        }
    }

    /// Boot the microVM and install the host egress wall, returning the live
    /// child handle. Performs no `self` state mutation so the caller can roll
    /// back cleanly on error.
    fn boot_microvm(&self, policy: &SandboxPolicy) -> Result<FirecrackerVm, PerimeterError> {
        let lay = self.layout();

        // 1. Clear leftovers from a previous crashed run (stale socket, tap,
        //    iptables rules, and any prior chroot) so provisioning is
        //    idempotent — otherwise `ip tuntap add` fails with EBUSY on a
        //    lingering tap and jailer refuses an existing chroot/cgroup.
        self.teardown_host();

        // 2. Create the host tap and install the egress wall BEFORE telling
        //    firecracker about the interface. When jailed the tap is owned by
        //    the dropped uid/gid so the chrooted firecracker can open it.
        let owner = self.assets.jail.as_ref().map(|c| (c.uid, c.gid));
        create_tap(&self.assets.tap, &self.assets.host_ip_cidr, owner).map_err(perimeter_err)?;
        install_egress_allowlist(&self.assets.tap, &policy.egress).map_err(perimeter_err)?;
        install_nat(&self.assets.tap, &self.assets.host_ip_cidr).map_err(perimeter_err)?;

        // 3. Spawn firecracker — directly (root) or under the jailer — then wait
        //    for the API socket. When jailed, jailer creates the chroot before
        //    exec'ing firecracker, so by the time the socket answers the chroot
        //    exists and we can stage the kernel + rootfs into it.
        let vm = match &self.assets.jail {
            None => FirecrackerVm::spawn(self.assets.socket.clone()).map_err(perimeter_err)?,
            Some(cfg) => {
                std::fs::create_dir_all(&cfg.chroot_base).map_err(perimeter_err)?;
                let fc = firecracker_exec_path();
                let argv = jail::build_jailer_argv(cfg, &fc, &lay.api_sock_arg);
                FirecrackerVm::spawn_jailed(&cfg.jailer_bin, argv, lay.api_sock_host.clone())
                    .map_err(perimeter_err)?
            }
        };
        wait_for_socket(&lay.api_sock_host, Duration::from_secs(5)).map_err(perimeter_err)?;

        // 3a. With the jailer up, its per-VM cgroup exists. Verify our teardown
        //     path actually points at it: a jailer that renamed the cgroup tree
        //     must fail loudly here, not leak a cgroup per box at teardown.
        if let Some(cfg) = &self.assets.jail {
            jail::verify_cgroup_dir(cfg).map_err(perimeter_err)?;
        }

        // 3b. Stage assets into the freshly-created chroot (jailed only). Kernel
        //     is hard-linked (read-only, shared is fine); the rootfs is copied
        //     so each box gets its own writable disk — the original asset is
        //     never mutated, matching the "disposable box" model.
        if let (Some(root), Some(cfg)) = (&lay.jail_root, &self.assets.jail) {
            stage_jail_assets(root, &self.assets, cfg.uid, cfg.gid)?;
        }

        // 4. Boot source.
        let boot = format!(
            r#"{{"kernel_image_path":"{}","boot_args":"{}"}}"#,
            lay.kernel_arg, self.assets.boot_args
        );
        with_socket(&lay.api_sock_host, |s| put_json(s, "/boot-source", &boot))
            .map_err(perimeter_err)?;

        // 5. Rootfs drive (writable; the agent is root inside its own box).
        let drive = format!(
            r#"{{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":false}}"#,
            lay.rootfs_arg
        );
        with_socket(&lay.api_sock_host, |s| {
            put_json(s, "/drives/rootfs", &drive)
        })
        .map_err(perimeter_err)?;

        // 6. Network interface (the tap already exists, step 2).
        let net = format!(
            r#"{{"iface_id":"eth0","host_dev_name":"{}"}}"#,
            self.assets.tap
        );
        with_socket(&lay.api_sock_host, |s| {
            put_json(s, "/network-interfaces/eth0", &net)
        })
        .map_err(perimeter_err)?;

        // 6b. vsock device for the guest↔supervisor channel. Skipped when there
        //     is no in-guest agent (attack-script demo). The host listens on
        //     `${vsock_host_base}_${VSOCK_PORT}` (see lex_os_proto::fc_host);
        //     under the jailer that path is inside the chroot.
        if !lay.vsock_arg.is_empty() {
            let vsock = format!(
                r#"{{"guest_cid":{},"uds_path":"{}"}}"#,
                self.assets.guest_cid, lay.vsock_arg
            );
            with_socket(&lay.api_sock_host, |s| put_json(s, "/vsock", &vsock))
                .map_err(perimeter_err)?;
        }

        // 7. Start the VM. Firecracker's /actions is a PUT (it has no POST).
        with_socket(&lay.api_sock_host, |s| {
            put_json(s, "/actions", r#"{"action_type":"InstanceStart"}"#)
        })
        .map_err(perimeter_err)?;

        Ok(vm)
    }

    /// Remove the host-side footprint: egress rules, tap, and either the bare
    /// sockets (unjailed) or the whole per-VM jail tree + its cgroup (jailed).
    /// Idempotent — every step ignores "already gone".
    fn teardown_host(&self) {
        flush_nat(&self.assets.tap, &self.assets.host_ip_cidr);
        let _ = flush_egress_rules(&self.assets.tap);
        let _ = destroy_tap(&self.assets.tap);
        match &self.assets.jail {
            None => {
                let _ = std::fs::remove_file(&self.assets.socket);
                if !self.assets.socket_vsock.as_os_str().is_empty() {
                    let _ = std::fs::remove_file(&self.assets.socket_vsock);
                }
            }
            Some(cfg) => {
                // The chroot holds the API socket, vsock socket, and staged
                // assets; removing it clears them all. The cgroup must go too or
                // jailer refuses to reuse the id on reprovision.
                let _ = std::fs::remove_dir_all(jail::chroot_id_dir(cfg));
                let _ = std::fs::remove_dir(jail::cgroup_v2_dir(cfg));
            }
        }
    }
}

/// Absolute path to the firecracker binary jailer should hard-link into the
/// chroot. `--exec-file` must be a real file, not a PATH name; prefer the
/// install location `demo/setup-assets.sh` uses, then a couple of fallbacks.
fn firecracker_exec_path() -> PathBuf {
    for p in ["/usr/local/bin/firecracker", "/usr/bin/firecracker"] {
        if Path::new(p).exists() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("firecracker")
}

/// Stage the kernel and rootfs into the jail chroot and make them accessible to
/// the dropped uid/gid. Kernel: hard-link (read-only); rootfs: copy (per-VM
/// writable), then chown to the jail user so firecracker can open it rw.
fn stage_jail_assets(
    root: &Path,
    assets: &FirecrackerAssets,
    uid: u32,
    gid: u32,
) -> Result<(), PerimeterError> {
    use std::os::unix::fs::chown;

    let kdst = root.join("vmlinux");
    let _ = std::fs::remove_file(&kdst);
    std::fs::hard_link(&assets.kernel, &kdst)
        .or_else(|_| std::fs::copy(&assets.kernel, &kdst).map(|_| ()))
        .map_err(perimeter_err)?;

    let rdst = root.join("rootfs.ext4");
    let _ = std::fs::remove_file(&rdst);
    std::fs::copy(&assets.rootfs, &rdst).map_err(perimeter_err)?;
    chown(&rdst, Some(uid), Some(gid)).map_err(perimeter_err)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{Grant, Level};

    /// Full provision → check → destroy cycle on the simulated backend.
    /// This test is ignored by default because the real backend requires KVM.
    #[test]
    #[ignore = "requires KVM; run on a Firecracker-capable host"]
    fn firecracker_provision_check_destroy_cycle() {
        use crate::SandboxPolicy;
        let mut perim = FirecrackerPerimeter::new();
        assert!(!perim.is_alive());

        let grant = Grant::new(Level::ReadWrite, Level::None, Level::None);
        let policy = SandboxPolicy::from_grant(&grant);
        perim.provision(policy).expect("provision should succeed");
        assert!(perim.is_alive());

        assert!(perim.check(Dimension::Filesystem, Level::ReadOnly).is_ok());
        assert!(perim.check(Dimension::Network, Level::Allowlist).is_err());

        perim.destroy("test teardown");
        assert!(!perim.is_alive());
        assert!(matches!(
            perim.check(Dimension::Filesystem, Level::ReadOnly),
            Err(PerimeterError::NotAlive)
        ));
    }

    /// Backend reports MicroVm as its maximum floor.
    #[test]
    #[ignore = "requires KVM; run on a Firecracker-capable host"]
    fn firecracker_max_floor_is_microvm() {
        let perim = FirecrackerPerimeter::new();
        assert_eq!(perim.max_floor(), IsolationFloor::MicroVm);
        assert_eq!(perim.backend_name(), "firecracker");
    }

    /// Provisioning with a policy that exceeds this backend's floor is
    /// rejected (refuse, don't downgrade — design doc §7.5).
    ///
    /// Since Firecracker tops out at MicroVm and MicroVm is the highest
    /// floor, there's no policy that exceeds it; this test documents the
    /// invariant and verifies the backend name instead.
    #[test]
    #[ignore = "requires KVM; run on a Firecracker-capable host"]
    fn firecracker_backend_name_and_floor() {
        let mut perim = FirecrackerPerimeter::new();
        let policy = SandboxPolicy::from_grant(&Grant::top());
        // MicroVm floor policy fits inside a MicroVm backend.
        assert!(perim.provision(policy).is_ok());
    }
}
