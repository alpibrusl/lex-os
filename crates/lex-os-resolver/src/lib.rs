//! The resolver (design doc §7.3): negotiate a manifest against the
//! real environment, and **fail loudly** when the environment can't
//! satisfy it.
//!
//! This is deliberately imperative Rust, not Lex — it is inherently
//! effectful environment-probing (which isolation backends are
//! installed, what the kernel supports), "the opposite of what Lex is
//! good at" (design doc §7, "Where Lex does NOT help"). Its single
//! safety-relevant rule is *refuse, don't downgrade*: if the manifest
//! needs a microVM and only namespaces are available, it returns an
//! error rather than quietly running on a weaker boundary.

use lex_os_manifest::{IsolationFloor, Manifest, ManifestError};
use lex_os_perimeter::SandboxPolicy;
use serde::{Deserialize, Serialize};

/// Which isolation backends the environment can offer, highest floor a
/// backend can reach. In a real deployment these are probed (does
/// `firecracker` exist and can we open `/dev/kvm`? is the
/// `runsc`/gVisor binary present? is `bwrap` installed and are user
/// namespaces enabled?). Here it is a declared capability so callers
/// can describe the host honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// The strongest isolation floor this host can actually enforce.
    pub max_floor: IsolationFloor,
    /// Whether outbound network is physically reachable from the host.
    /// (A `network: none` grant is fine regardless; a grant that needs
    /// egress on a host with no network is a resolve failure.)
    pub network_available: bool,
}

impl Environment {
    /// A host that can run the strongest boundary — the assumption a
    /// production supervisor host should meet.
    pub fn full() -> Self {
        Self {
            max_floor: IsolationFloor::MicroVm,
            network_available: true,
        }
    }

    /// A constrained host: namespaces only, no network. Useful to
    /// demonstrate the refuse-don't-downgrade path.
    pub fn namespaces_only_offline() -> Self {
        Self {
            max_floor: IsolationFloor::Namespace,
            network_available: false,
        }
    }
}

/// The outcome of resolving a manifest against an environment: the
/// concrete policy to enforce and the backend floor to enforce it with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPlan {
    pub policy: SandboxPolicy,
    /// The isolation floor the box will actually run at (≥ the manifest
    /// floor, ≤ the environment ceiling).
    pub floor: IsolationFloor,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(
        "environment cannot satisfy manifest: needs isolation floor `{needed}` but host tops out at `{available}` — refusing to downgrade"
    )]
    InsufficientIsolation {
        needed: &'static str,
        available: &'static str,
    },
    #[error(
        "manifest grants network egress but the host has no network — refusing to run a half-satisfied grant"
    )]
    NetworkUnavailable,
}

/// Negotiate `manifest` against `env`. On success the returned plan is
/// guaranteed runnable on this host *exactly* as specified; on failure
/// the caller must fix the manifest or the host, never weaken silently.
pub fn resolve(manifest: &Manifest, env: &Environment) -> Result<ResolvedPlan, ResolveError> {
    // The manifest must first be internally consistent.
    manifest.validate()?;

    let policy = SandboxPolicy::from_grant(&manifest.grant);

    // The floor we must run at is the stronger of what the manifest
    // demands and what the grant implies (they agree after validate,
    // but be explicit).
    let needed = manifest.isolation_floor.max(policy.required_floor);

    if needed > env.max_floor {
        return Err(ResolveError::InsufficientIsolation {
            needed: needed.as_str(),
            available: env.max_floor.as_str(),
        });
    }

    // If the grant asks for egress, the host must actually have a
    // network. Refuse rather than run a grant we can't honour.
    let wants_egress = !matches!(policy.net_egress, lex_os_perimeter::NetEgress::Denied);
    if wants_egress && !env.network_available {
        return Err(ResolveError::NetworkUnavailable);
    }

    Ok(ResolvedPlan {
        policy,
        floor: needed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{Budget, Goal, Grant, Level};

    fn manifest(grant: Grant) -> Manifest {
        Manifest::new(Goal::new("t"), grant, Budget::research_default())
    }

    #[test]
    fn analyze_manifest_resolves_on_namespace_host() {
        // fs read/write, no net, no exec -> namespace floor is enough,
        // no network needed.
        let m = manifest(Grant::new(Level::ReadWrite, Level::None, Level::None));
        let env = Environment::namespaces_only_offline();
        let plan = resolve(&m, &env).unwrap();
        assert_eq!(plan.floor, IsolationFloor::Namespace);
    }

    #[test]
    fn sudo_manifest_refused_on_namespace_host() {
        let m = manifest(Grant::top());
        let env = Environment::namespaces_only_offline();
        let err = resolve(&m, &env).unwrap_err();
        assert!(matches!(err, ResolveError::InsufficientIsolation { .. }));
    }

    #[test]
    fn sudo_manifest_resolves_on_full_host() {
        let m = manifest(Grant::top());
        let plan = resolve(&m, &Environment::full()).unwrap();
        assert_eq!(plan.floor, IsolationFloor::MicroVm);
    }

    #[test]
    fn egress_grant_refused_without_network() {
        // Needs network, exec none so floor is fine on namespace host,
        // but no network -> refuse.
        let m = manifest(Grant::new(Level::ReadOnly, Level::Full, Level::None));
        let env = Environment::namespaces_only_offline();
        let err = resolve(&m, &env).unwrap_err();
        assert!(matches!(err, ResolveError::NetworkUnavailable));
    }
}
