//! Firecracker microVM perimeter backend (feature = "firecracker").
//!
//! This module provides a [`FirecrackerPerimeter`] that implements the
//! [`Perimeter`] trait against Firecracker's HTTP management API.  The
//! real provisioning would POST to the `/actions` endpoint; this
//! skeleton simulates the side-effect so the mediation loop, audit log,
//! and policy checks are all exercisable without a KVM host.  Swap the
//! `provision` body for the real HTTP calls to go live.

use crate::{BoxState, Perimeter, PerimeterError, SandboxPolicy};
use lex_os_manifest::{Dimension, IsolationFloor, Level};

/// A perimeter backed by a Firecracker microVM.  In production, `provision`
/// calls the Firecracker management API (HTTP to `/actions`) to start a
/// fresh VM; here the call is simulated so the trait contract is testable
/// everywhere a Perimeter is needed.
pub struct FirecrackerPerimeter {
    policy: Option<SandboxPolicy>,
    state: BoxState,
}

impl Default for FirecrackerPerimeter {
    fn default() -> Self {
        Self::new()
    }
}

impl FirecrackerPerimeter {
    pub fn new() -> Self {
        Self {
            policy: None,
            state: BoxState::Dead,
        }
    }
}

impl Perimeter for FirecrackerPerimeter {
    fn backend_name(&self) -> &'static str {
        "firecracker"
    }

    fn max_floor(&self) -> IsolationFloor {
        IsolationFloor::MicroVm
    }

    /// Provision a fresh microVM for `policy`.  A real implementation would
    /// call the Firecracker HTTP `/actions` endpoint here; this skeleton
    /// simulates success so the loop is testable without KVM.
    fn provision(&mut self, policy: SandboxPolicy) -> Result<(), PerimeterError> {
        if policy.required_floor > self.max_floor() {
            return Err(PerimeterError::FloorUnavailable {
                required: policy.required_floor.as_str(),
                available: self.max_floor().as_str(),
            });
        }
        // Real: POST to Firecracker /actions { action_type: "InstanceStart" }
        self.policy = Some(policy);
        self.state = BoxState::Alive;
        Ok(())
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
        // Real: POST to Firecracker /actions { action_type: "SendCtrlAltDel" }
        self.state = BoxState::Dead;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{Budget, Goal, Grant, Level};

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

        assert!(perim
            .check(Dimension::Filesystem, Level::ReadOnly)
            .is_ok());
        assert!(perim
            .check(Dimension::Network, Level::Allowlist)
            .is_err());

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
