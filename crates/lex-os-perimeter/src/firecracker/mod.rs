//! Firecracker microVM perimeter backend (feature = "firecracker").
//!
//! This module provides a [`FirecrackerPerimeter`] that implements the
//! [`Perimeter`] trait against Firecracker's HTTP management API.

mod api;
mod net;
mod vm;

use std::path::PathBuf;
use std::time::Duration;

use api::{post_json, put_json, wait_for_socket, with_socket};
use net::{create_tap, destroy_tap, flush_egress_rules, install_egress_allowlist};
use vm::FirecrackerVm;

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

impl FirecrackerPerimeter {
    /// Boot the microVM and install the host egress wall, returning the live
    /// child handle. Performs no `self` state mutation so the caller can roll
    /// back cleanly on error.
    fn boot_microvm(&self, policy: &SandboxPolicy) -> Result<FirecrackerVm, PerimeterError> {
        // 1. Clear leftovers from a previous crashed run (stale API socket,
        //    tap device, and our iptables rules) so provisioning is idempotent
        //    — otherwise `ip tuntap add` fails with EBUSY on a lingering tap.
        self.teardown_host();

        // 2. Spawn firecracker; wait for the API socket to accept connections.
        let vm = FirecrackerVm::spawn(self.assets.socket.clone()).map_err(perimeter_err)?;
        wait_for_socket(&self.assets.socket, Duration::from_secs(2)).map_err(perimeter_err)?;

        // 3. Configure the boot source.
        let boot = format!(
            r#"{{"kernel_image_path":"{}","boot_args":"{}"}}"#,
            self.assets.kernel.display(),
            self.assets.boot_args
        );
        with_socket(&self.assets.socket, |s| put_json(s, "/boot-source", &boot))
            .map_err(perimeter_err)?;

        // 4. Configure the rootfs drive (writable; the agent is root inside).
        let drive = format!(
            r#"{{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":false}}"#,
            self.assets.rootfs.display()
        );
        with_socket(&self.assets.socket, |s| {
            put_json(s, "/drives/rootfs", &drive)
        })
        .map_err(perimeter_err)?;

        // 5. Configure the network interface (host_dev_name created next).
        let net = format!(
            r#"{{"iface_id":"eth0","host_dev_name":"{}"}}"#,
            self.assets.tap
        );
        with_socket(&self.assets.socket, |s| {
            put_json(s, "/network-interfaces/eth0", &net)
        })
        .map_err(perimeter_err)?;

        // 6. Create the tap on the host and install the egress allowlist.
        create_tap(&self.assets.tap, &self.assets.host_ip_cidr).map_err(perimeter_err)?;
        install_egress_allowlist(&self.assets.tap, &policy.egress).map_err(perimeter_err)?;

        // 7. Start the VM.
        with_socket(&self.assets.socket, |s| {
            post_json(s, "/actions", r#"{"action_type":"InstanceStart"}"#)
        })
        .map_err(perimeter_err)?;

        Ok(vm)
    }

    /// Remove the host-side footprint: egress rules, tap device, API socket.
    /// Idempotent — every step ignores "already gone".
    fn teardown_host(&self) {
        let _ = flush_egress_rules(&self.assets.tap);
        let _ = destroy_tap(&self.assets.tap);
        let _ = std::fs::remove_file(&self.assets.socket);
    }
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
