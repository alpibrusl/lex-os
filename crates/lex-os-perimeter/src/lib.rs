//! The box's edge (design doc §3, §8): the minimal, hard-enforced
//! capability boundary.
//!
//! Two ideas live here:
//!
//! 1. **One grant → an OS policy.** [`SandboxPolicy::from_grant`] turns
//!    a [`Grant`] into the concrete kernel-level posture — which network
//!    egress is permitted, whether the filesystem is writable, whether
//!    arbitrary executables may be spawned. This is the second of the
//!    "two enforcement layers": the Lex type check catches an agent
//!    *calling* a command it shouldn't; the perimeter catches an agent
//!    that ignores Lex and runs arbitrary binaries.
//!
//! 2. **Pluggable backends.** A [`Perimeter`] is whatever actually
//!    enforces the policy. The strength required depends on the grant:
//!    namespaces (bubblewrap) suffice for `exec: none`; `exec: full`
//!    demands a microVM. Real backends (Firecracker/gVisor/bubblewrap)
//!    are Rust + Linux and live behind this trait; this crate ships a
//!    [`SimulatedPerimeter`] that enforces the policy in-process so the
//!    mediation loop is testable everywhere.

use lex_os_manifest::{Dimension, Grant, IsolationFloor, Level, Manifest};
use serde::{Deserialize, Serialize};

#[cfg(feature = "firecracker")]
mod firecracker;
#[cfg(feature = "firecracker")]
pub use firecracker::FirecrackerPerimeter;

/// Network posture derived from the network trust level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetEgress {
    /// No egress at all — the syscalls resolve to nothing (design doc
    /// §5.1: ungranted effects are physically absent).
    Denied,
    /// Loopback only.
    Loopback,
    /// Restricted to an allowlist (the allowlist itself is carried in
    /// the effect args / resolver, not modelled here).
    Allowlist,
    /// Unrestricted egress.
    Open,
}

/// The concrete enforcement posture for a box. Every field is *derived*
/// from the grant, never set independently — that is what keeps the
/// declaration and the enforcement in lockstep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// May the box read its filesystem at all?
    pub fs_readable: bool,
    /// May the box write its filesystem?
    pub fs_writable: bool,
    pub net_egress: NetEgress,
    /// May the box spawn arbitrary executables (the `exec`/`proc`
    /// authority)? When false, subprocess-spawning syscalls are blocked.
    pub exec_allowed: bool,
    /// The minimum isolation backend strength this policy needs.
    pub required_floor: IsolationFloor,
    /// The egress allowlist: host or `host:port` entries that the box
    /// may reach when `net_egress == Allowlist`. Empty unless populated
    /// via [`SandboxPolicy::from_manifest`].
    pub egress: Vec<String>,
}

impl SandboxPolicy {
    /// The single source of truth mapping a grant to an OS posture.
    /// Produces an empty egress list — use [`from_manifest`] to carry the
    /// allowlist from a full manifest.
    pub fn from_grant(grant: &Grant) -> Self {
        let net_egress = match grant.network {
            Level::None => NetEgress::Denied,
            Level::Loopback | Level::ReadOnly | Level::Sandboxed => NetEgress::Loopback,
            Level::Allowlist | Level::ReadWrite => NetEgress::Allowlist,
            Level::Full => NetEgress::Open,
        };
        SandboxPolicy {
            fs_readable: grant.filesystem.rank() >= Level::ReadOnly.rank(),
            fs_writable: grant.filesystem.rank() >= Level::ReadWrite.rank(),
            net_egress,
            exec_allowed: grant.exec != Level::None,
            required_floor: IsolationFloor::implied_by(grant),
            egress: Vec::new(),
        }
    }

    /// Build a policy from a full manifest, carrying the egress allowlist.
    pub fn from_manifest(manifest: &Manifest) -> Self {
        let mut policy = Self::from_grant(&manifest.grant);
        policy.egress = manifest.egress.clone();
        policy
    }

    /// Does the policy permit outbound connections to `host`?
    ///
    /// - `Open`: always yes.
    /// - `Allowlist`: yes if any entry in `self.egress` matches via
    ///   [`lex_types::trust::host_matches`].
    /// - Otherwise: no.
    pub fn permits_host(&self, host: &str) -> bool {
        match self.net_egress {
            NetEgress::Open => true,
            NetEgress::Allowlist => self
                .egress
                .iter()
                .any(|allow| lex_types::trust::host_matches(allow, host)),
            _ => false,
        }
    }

    /// Does the policy permit an operation that needs `required` on
    /// `dim`? Used as the perimeter-side mirror of the type check — the
    /// kernel boundary answering the same question Lex answered
    /// statically.
    pub fn permits(&self, dim: Dimension, required: Level) -> bool {
        match dim {
            Dimension::Filesystem => match required {
                Level::None => true,
                Level::ReadOnly => self.fs_readable,
                _ => self.fs_writable,
            },
            Dimension::Network => {
                !matches!(self.net_egress, NetEgress::Denied) || required == Level::None
            }
            Dimension::Exec => self.exec_allowed || required == Level::None,
        }
    }
}

/// The live state of a provisioned box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxState {
    /// Running and answering liveness checks.
    Alive,
    /// Wedged or self-destructed — fails liveness, awaits reprovision.
    Dead,
}

#[derive(Debug, thiserror::Error)]
pub enum PerimeterError {
    /// The environment cannot provide the isolation floor the policy
    /// requires. *Refuse, don't downgrade* (design doc §7.5): we error
    /// rather than silently running on a weaker boundary.
    #[error(
        "isolation floor `{required}` is not available in this environment (have `{available}`)"
    )]
    FloorUnavailable {
        required: &'static str,
        available: &'static str,
    },
    #[error("the box is not alive")]
    NotAlive,
    #[error("operation blocked by perimeter: {0}")]
    Blocked(String),
}

/// A handle to a provisioned, policy-enforcing box.
pub trait Perimeter {
    /// A human-readable name for the backend (for logs/audit).
    fn backend_name(&self) -> &'static str;

    /// The strongest isolation floor this backend can enforce.
    fn max_floor(&self) -> IsolationFloor;

    /// Provision (or reprovision) a fresh box enforcing `policy`. Fails
    /// if the backend can't reach the policy's required floor.
    fn provision(&mut self, policy: SandboxPolicy) -> Result<(), PerimeterError>;

    /// Liveness check (design doc §5.3 — default is *stop*, not
    /// *continue*). The supervisor reprovisions when this reports dead.
    fn is_alive(&self) -> bool;

    /// Ask the perimeter to authorise an effect at the kernel boundary.
    /// This is the wall that holds even if the agent bypasses Lex.
    fn check(&self, dim: Dimension, required: Level) -> Result<(), PerimeterError>;

    /// Simulate the box destroying itself (allowed and even useful, as
    /// long as the box is isolated — design doc §4).
    fn destroy(&mut self, reason: &str);
}

/// An in-process perimeter that enforces the derived [`SandboxPolicy`]
/// without a real kernel boundary. It is *not* a security boundary — it
/// exists so the mediation loop, budgets, audit log and reprovision loop
/// are exercised end-to-end in any environment. A real deployment swaps
/// in a Firecracker/gVisor/bubblewrap backend with the same trait.
#[derive(Debug)]
pub struct SimulatedPerimeter {
    policy: Option<SandboxPolicy>,
    state: BoxState,
    /// The strongest floor this simulator claims to provide. Set to
    /// `MicroVm` so the simulator can stand in for any floor in tests;
    /// real backends report their true ceiling.
    ceiling: IsolationFloor,
}

impl Default for SimulatedPerimeter {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulatedPerimeter {
    pub fn new() -> Self {
        Self {
            policy: None,
            state: BoxState::Dead,
            ceiling: IsolationFloor::MicroVm,
        }
    }

    /// Construct a simulator that pretends to only reach `ceiling`,
    /// useful for testing the *refuse, don't downgrade* path.
    pub fn with_ceiling(ceiling: IsolationFloor) -> Self {
        Self {
            policy: None,
            state: BoxState::Dead,
            ceiling,
        }
    }

    pub fn state(&self) -> BoxState {
        self.state
    }

    pub fn policy(&self) -> Option<SandboxPolicy> {
        self.policy.clone()
    }
}

impl Perimeter for SimulatedPerimeter {
    fn backend_name(&self) -> &'static str {
        "simulated"
    }

    fn max_floor(&self) -> IsolationFloor {
        self.ceiling
    }

    fn provision(&mut self, policy: SandboxPolicy) -> Result<(), PerimeterError> {
        if policy.required_floor > self.ceiling {
            return Err(PerimeterError::FloorUnavailable {
                required: policy.required_floor.as_str(),
                available: self.ceiling.as_str(),
            });
        }
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
        self.state = BoxState::Dead;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_grant_yields_no_egress_no_exec() {
        let grant = Grant::new(Level::ReadWrite, Level::None, Level::None);
        let p = SandboxPolicy::from_grant(&grant);
        assert!(p.fs_readable);
        assert!(p.fs_writable);
        assert_eq!(p.net_egress, NetEgress::Denied);
        assert!(!p.exec_allowed);
        assert_eq!(p.required_floor, IsolationFloor::Namespace);
    }

    #[test]
    fn top_grant_is_open_and_demands_microvm() {
        let p = SandboxPolicy::from_grant(&Grant::top());
        assert_eq!(p.net_egress, NetEgress::Open);
        assert!(p.exec_allowed);
        assert_eq!(p.required_floor, IsolationFloor::MicroVm);
    }

    #[test]
    fn policy_permits_mirrors_grant() {
        let p = SandboxPolicy::from_grant(&Grant::new(Level::ReadOnly, Level::None, Level::None));
        assert!(p.permits(Dimension::Filesystem, Level::ReadOnly));
        assert!(!p.permits(Dimension::Filesystem, Level::ReadWrite));
        assert!(!p.permits(Dimension::Network, Level::Allowlist));
        assert!(!p.permits(Dimension::Exec, Level::Sandboxed));
        // None is always permitted.
        assert!(p.permits(Dimension::Network, Level::None));
    }

    #[test]
    fn provision_and_check_on_simulated() {
        let grant = Grant::new(Level::ReadOnly, Level::None, Level::None);
        let mut perim = SimulatedPerimeter::new();
        assert!(!perim.is_alive());
        perim.provision(SandboxPolicy::from_grant(&grant)).unwrap();
        assert!(perim.is_alive());
        assert!(perim.check(Dimension::Filesystem, Level::ReadOnly).is_ok());
        assert!(perim.check(Dimension::Network, Level::Allowlist).is_err());
    }

    #[test]
    fn refuse_dont_downgrade_when_floor_unavailable() {
        // A namespace-only backend cannot host a microVM-floor policy.
        let mut perim = SimulatedPerimeter::with_ceiling(IsolationFloor::Namespace);
        let policy = SandboxPolicy::from_grant(&Grant::top());
        let err = perim.provision(policy).unwrap_err();
        assert!(matches!(err, PerimeterError::FloorUnavailable { .. }));
        assert!(!perim.is_alive());
    }

    #[test]
    fn destroyed_box_fails_liveness_and_checks() {
        let mut perim = SimulatedPerimeter::new();
        perim
            .provision(SandboxPolicy::from_grant(&Grant::top()))
            .unwrap();
        perim.destroy("agent ran rm -rf /");
        assert!(!perim.is_alive());
        assert!(matches!(
            perim.check(Dimension::Filesystem, Level::ReadOnly),
            Err(PerimeterError::NotAlive)
        ));
    }

    #[test]
    fn from_manifest_carries_egress_and_permits_host() {
        use lex_os_manifest::{Budget, Goal};
        let manifest = Manifest::new(
            Goal::new("test"),
            Grant::new(Level::ReadWrite, Level::Allowlist, Level::None),
            Budget::research_default(),
        )
        .with_egress(vec!["results.demo.internal:443".into()]);
        let policy = SandboxPolicy::from_manifest(&manifest);
        assert_eq!(policy.net_egress, NetEgress::Allowlist);
        assert_eq!(policy.egress, vec!["results.demo.internal:443"]);
        // The allowlisted host is permitted.
        assert!(policy.permits_host("results.demo.internal"));
        // A host not in the list is refused.
        assert!(!policy.permits_host("evil.com"));
    }
}
