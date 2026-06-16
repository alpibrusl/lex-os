//! The trust manifest: the owner's whole safety declaration.
//!
//! An owner dispatches an agent by handing it a [`Manifest`] — a goal,
//! a capability [`Grant`], and hard [`Budget`]s. Once dispatched no
//! human watches, so this manifest *is* the safety boundary (design doc
//! §9). Everything the runtime enforces is derived from it.
//!
//! The capability grant is the trust lattice from `lex-types`: the same
//! declaration that the Lex type checker uses to reject a program that
//! calls an un-granted effect is the one the supervisor turns into an OS
//! sandbox policy. One declaration, two enforcement layers (design doc
//! §7). This crate re-exports it so downstream crates have a single
//! source of truth.

pub use lex_types::trust::{Dimension, Grant, GrantId, Level, TrustError};

mod actuation;
pub use actuation::{Actuation, ActuatorArm, ActuatorGripper, Range};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What the agent is asked to accomplish. Free text plus an optional
/// machine-checkable done-signal the agent emits when it believes the
/// goal is met (the supervisor still owns the decision to stop).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Goal {
    pub description: String,
    /// A token the agent reports to claim completion. The supervisor
    /// treats reaching it as *a* terminal condition, never the only one
    /// — budget exhaustion and kill always win.
    #[serde(default)]
    pub done_signal: Option<String>,
}

impl Goal {
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            done_signal: None,
        }
    }

    pub fn with_done_signal(mut self, signal: impl Into<String>) -> Self {
        self.done_signal = Some(signal.into());
        self
    }
}

/// The reversibility class of a command's *effect*, sorted by blast
/// radius (design doc §6). This is a structural property of the
/// command, not something the agent asserts about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Reversibility {
    /// Read, query, draft. Free, always logged.
    ReversibleCheap,
    /// Send email, write a file, spend ≤ €X. Allowed within budget and
    /// policy; prominently logged; the grant remains revocable.
    IrreversibleBounded,
    /// Delete data, large payment, unbounded third-party effect. In a
    /// human-in-the-loop system this is gated by approval. In the
    /// no-human system there is no approval step, so it must be absent
    /// from the grant or bounded so tightly the worst case is
    /// acceptable. There is no backstop behind the grant.
    IrreversibleConsequential,
}

impl Reversibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Reversibility::ReversibleCheap => "reversible-cheap",
            Reversibility::IrreversibleBounded => "irreversible-bounded",
            Reversibility::IrreversibleConsequential => "irreversible-consequential",
        }
    }
}

/// Hard, externally-enforced resource bounds (design doc §5.2). Must be
/// external because a stuck or misaligned agent will not honour its own
/// limits. On exhaustion the box halts regardless of goal state.
///
/// Money is integer cents to keep budgets exact (no float drift).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Wall-clock ceiling in seconds.
    pub wall_clock_secs: u64,
    /// Maximum number of mediated commands the agent may issue.
    pub max_commands: u64,
    /// Maximum spend, in cents.
    pub max_money_cents: u64,
    /// Maximum external API calls (a network-egress sub-budget).
    pub max_api_calls: u64,
}

impl Budget {
    /// A conservative default for a low-trust research agent.
    pub fn research_default() -> Self {
        Self {
            wall_clock_secs: 300,
            max_commands: 100,
            max_money_cents: 0,
            max_api_calls: 50,
        }
    }
}

/// The minimum isolation strength the owner requires. The resolver maps
/// this (together with the grant) to a concrete backend, and *refuses*
/// rather than downgrades if the environment can't reach the floor
/// (design doc §8 isolation-floor note).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IsolationFloor {
    /// Namespace isolation (bubblewrap). Adequate only for low-trust
    /// `exec: none` research agents.
    Namespace,
    /// A user-space kernel boundary (gVisor).
    Gvisor,
    /// A hardware-virtualised boundary (Firecracker microVM). Required
    /// for the `sudo` / `exec: full` / no-human case.
    MicroVm,
}

impl IsolationFloor {
    pub fn as_str(self) -> &'static str {
        match self {
            IsolationFloor::Namespace => "namespace",
            IsolationFloor::Gvisor => "gvisor",
            IsolationFloor::MicroVm => "microvm",
        }
    }

    /// The floor a grant *implies* on its own, before the owner raises
    /// it. Any authority to execute arbitrary binaries (`exec` above
    /// `None`) demands at least a kernel boundary; full exec demands a
    /// microVM. This encodes the design doc's rule that what a
    /// high-privilege grant *resolves to* is what changes, not the
    /// manifest.
    pub fn implied_by(grant: &Grant) -> IsolationFloor {
        match grant.exec {
            Level::None => IsolationFloor::Namespace,
            Level::Full => IsolationFloor::MicroVm,
            _ => IsolationFloor::Gvisor,
        }
    }
}

/// The complete dispatch: goal + grant + budgets + isolation floor.
/// Content-addressable so the supervisor can hold it in tamper-proof
/// external storage and reprovision an identical box from it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub goal: Goal,
    pub grant: Grant,
    pub budget: Budget,
    pub isolation_floor: IsolationFloor,
    /// Network egress allowlist: the only hosts the box may reach, as
    /// `host` or `host:port` entries (a leading `*.` wildcard matches
    /// subdomains). Empty means no egress unless `grant.network` is
    /// `full`. This is the data behind the demo grant
    /// `network: none EXCEPT results.demo.internal:443`, and is what both
    /// the static type-check (via `Grant::permits_effects_with_allowlist`)
    /// and the perimeter firewall are derived from.
    #[serde(default)]
    pub egress: Vec<String>,
    /// The robot half of the grant. `None` for ordinary agent boxes; when
    /// present, the supervisor mediates each skill's arguments against it.
    #[serde(default)]
    pub actuation: Option<Actuation>,
}

/// Content address of a [`Manifest`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManifestId(pub String);

impl ManifestId {
    pub fn short(&self) -> &str {
        &self.0[..self.0.len().min(12)]
    }
}

impl std::fmt::Display for ManifestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "manifest:{}", self.short())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest is not internally consistent: {0}")]
    Inconsistent(String),
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error("failed to (de)serialize manifest: {0}")]
    Serde(#[from] serde_json::Error),
    #[error(
        "egress widening: child manifest adds host `{host}` not present in the parent's egress allowlist (a child may only narrow)"
    )]
    EgressWidens { host: String },
    #[error("budget widening on {field}: child requests {requested} > parent {parent}")]
    BudgetWidens {
        field: &'static str,
        parent: u64,
        requested: u64,
    },
}

impl Manifest {
    pub fn new(goal: Goal, grant: Grant, budget: Budget) -> Self {
        let isolation_floor = IsolationFloor::implied_by(&grant);
        Self {
            goal,
            grant,
            budget,
            isolation_floor,
            egress: Vec::new(),
            actuation: None,
        }
    }

    /// Set the network egress allowlist (host or `host:port` entries).
    pub fn with_egress(mut self, hosts: Vec<String>) -> Self {
        self.egress = hosts;
        self
    }

    /// Validate that `child` is a well-formed narrowing of `self` across
    /// **every** dimension the agent could try to widen (design doc §7
    /// Attempt 3): the grant (via the trust lattice), the egress
    /// allowlist (child ⊆ parent), and every budget ceiling
    /// (child ≤ parent). Returns the first widening as a structured
    /// error so the supervisor can log a `[BLOCKED:narrowing]` reason.
    pub fn validate_narrowing(parent: &Manifest, child: &Manifest) -> Result<(), ManifestError> {
        // Grant: child must be ≤ parent on the trust lattice.
        Grant::narrow(&parent.grant, &child.grant)?;
        // Egress: every child host must already be allowed by the parent.
        for host in &child.egress {
            let bare = host.split(':').next().unwrap_or(host);
            let covered = parent
                .egress
                .iter()
                .any(|p| lex_types::trust::host_matches(p, bare));
            if !covered {
                return Err(ManifestError::EgressWidens { host: host.clone() });
            }
        }
        // Budgets: no ceiling may exceed the parent's.
        let checks: [(&'static str, u64, u64); 4] = [
            (
                "wall_clock_secs",
                parent.budget.wall_clock_secs,
                child.budget.wall_clock_secs,
            ),
            (
                "max_commands",
                parent.budget.max_commands,
                child.budget.max_commands,
            ),
            (
                "max_money_cents",
                parent.budget.max_money_cents,
                child.budget.max_money_cents,
            ),
            (
                "max_api_calls",
                parent.budget.max_api_calls,
                child.budget.max_api_calls,
            ),
        ];
        for (field, p, c) in checks {
            if c > p {
                return Err(ManifestError::BudgetWidens {
                    field,
                    parent: p,
                    requested: c,
                });
            }
        }
        Ok(())
    }

    /// Build a manifest while raising the isolation floor to the owner's
    /// explicit minimum if it exceeds what the grant implies. The floor
    /// can be raised, never lowered below what the grant demands.
    pub fn with_floor(mut self, floor: IsolationFloor) -> Self {
        self.isolation_floor = self.isolation_floor.max(floor);
        self
    }

    /// Validate the manifest is internally consistent before dispatch.
    /// The key invariant: the chosen isolation floor must be strong
    /// enough for the grant. A `network: none, exec: full` agent on a
    /// mere namespace floor is exactly the misconfiguration this catches.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let implied = IsolationFloor::implied_by(&self.grant);
        if self.isolation_floor < implied {
            return Err(ManifestError::Inconsistent(format!(
                "grant {} implies an isolation floor of `{}` but manifest declares `{}`",
                self.grant,
                implied.as_str(),
                self.isolation_floor.as_str(),
            )));
        }
        Ok(())
    }

    /// Derive a child manifest that *narrows* this one's grant. Widening
    /// any dimension is rejected (design doc §7.1 narrowing invariant).
    /// Budgets are clamped to be no larger than the parent's, and the
    /// isolation floor is re-derived (never weaker than the child grant
    /// needs, never weaker than the parent's floor).
    pub fn narrow_to(
        &self,
        child_grant: Grant,
        child_budget: Budget,
    ) -> Result<Manifest, ManifestError> {
        let grant = Grant::narrow(&self.grant, &child_grant)?;
        let budget = Budget {
            wall_clock_secs: child_budget
                .wall_clock_secs
                .min(self.budget.wall_clock_secs),
            max_commands: child_budget.max_commands.min(self.budget.max_commands),
            max_money_cents: child_budget
                .max_money_cents
                .min(self.budget.max_money_cents),
            max_api_calls: child_budget.max_api_calls.min(self.budget.max_api_calls),
        };
        let isolation_floor = IsolationFloor::implied_by(&grant).max(self.isolation_floor);
        Ok(Manifest {
            goal: self.goal.clone(),
            grant,
            budget,
            isolation_floor,
            // The child inherits the parent's egress; narrowing can drop
            // hosts but never add them, so inheriting is always safe.
            egress: self.egress.clone(),
            actuation: self.actuation.clone(),
        })
    }

    /// Content address of the manifest — a stable SHA-256 over its
    /// canonical JSON. Reproducible across processes; this is the handle
    /// the supervisor stores externally and reprovisions from.
    pub fn content_id(&self) -> ManifestId {
        let canonical = self.canonical_json();
        let mut hasher = Sha256::new();
        hasher.update(b"lex.os.manifest.v1");
        hasher.update(canonical.as_bytes());
        ManifestId(hex::encode(hasher.finalize()))
    }

    /// Canonical JSON used for hashing and external storage. Field order
    /// is fixed by the struct definition and serde, so this is stable.
    pub fn canonical_json(&self) -> String {
        // Build the value explicitly so ordering is deterministic and
        // independent of serde's struct field emission quirks.
        let mut egress = self.egress.clone();
        egress.sort();
        let v = serde_json::json!({
            "goal": self.goal.description,
            "done_signal": self.goal.done_signal,
            "grant": {
                "filesystem": self.grant.filesystem.rank(),
                "network": self.grant.network.rank(),
                "exec": self.grant.exec.rank(),
            },
            "budget": {
                "wall_clock_secs": self.budget.wall_clock_secs,
                "max_commands": self.budget.max_commands,
                "max_money_cents": self.budget.max_money_cents,
                "max_api_calls": self.budget.max_api_calls,
            },
            "isolation_floor": self.isolation_floor.as_str(),
            "egress": egress,
            "actuation": self.actuation,
        });
        serde_json::to_string(&v).expect("manifest json is always serializable")
    }

    /// Serialize to pretty JSON for external storage / inspection.
    pub fn to_json(&self) -> Result<String, ManifestError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(s: &str) -> Result<Manifest, ManifestError> {
        Ok(serde_json::from_str(s)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_manifest() -> Manifest {
        // "analyze data -> report": filesystem read only, no network, no
        // exec. The classic narrowest grant from design doc §5.1.
        Manifest::new(
            Goal::new("analyze sales.csv and write report.md").with_done_signal("REPORT_WRITTEN"),
            Grant::new(Level::ReadWrite, Level::None, Level::None),
            Budget::research_default(),
        )
    }

    fn demo_parent() -> Manifest {
        // The demo dispatch: do anything inside, reach exactly one host.
        Manifest::new(
            Goal::new("build the service"),
            Grant::top(),
            Budget::research_default(),
        )
        .with_egress(vec!["results.demo.internal:443".into()])
    }

    #[test]
    fn egress_survives_roundtrip_and_affects_content_id() {
        let m = demo_parent();
        let back = Manifest::from_json(&m.to_json().unwrap()).unwrap();
        assert_eq!(back.egress, m.egress);
        assert_eq!(m.content_id(), back.content_id());
        // A different allowlist changes the content address.
        let m2 = m.clone().with_egress(vec!["evil.com".into()]);
        assert_ne!(m.content_id(), m2.content_id());
    }

    #[test]
    fn old_manifests_without_egress_still_deserialize() {
        // Back-compat: manifests written before the egress field load
        // with an empty allowlist (serde default).
        let json = r#"{"goal":{"description":"x","done_signal":null},
            "grant":{"filesystem":"ReadOnly","network":"None","exec":"None"},
            "budget":{"wall_clock_secs":1,"max_commands":1,"max_money_cents":0,"max_api_calls":0},
            "isolation_floor":"Namespace"}"#;
        let m = Manifest::from_json(json).unwrap();
        assert!(m.egress.is_empty());
    }

    #[test]
    fn narrowing_accepts_subset_and_rejects_added_host() {
        let parent = demo_parent();
        // Child drops to a read-only, no-exec grant and keeps a subset of egress.
        let ok_child = Manifest::new(
            Goal::new("child"),
            Grant::new(Level::ReadOnly, Level::None, Level::None),
            Budget::research_default(),
        )
        .with_egress(vec!["results.demo.internal".into()]);
        assert!(Manifest::validate_narrowing(&parent, &ok_child).is_ok());

        // Child tries to add a host the parent never allowed.
        let bad_child = ok_child.clone().with_egress(vec!["evil.com".into()]);
        assert!(matches!(
            Manifest::validate_narrowing(&parent, &bad_child).unwrap_err(),
            ManifestError::EgressWidens { .. }
        ));
    }

    #[test]
    fn narrowing_rejects_grant_and_budget_widening() {
        let parent = Manifest::new(
            Goal::new("p"),
            Grant::new(Level::ReadOnly, Level::None, Level::None),
            Budget {
                wall_clock_secs: 100,
                max_commands: 10,
                max_money_cents: 0,
                max_api_calls: 5,
            },
        );
        // Grant widen: child asks for network full.
        let widen_grant = Manifest::new(
            Goal::new("c"),
            Grant::new(Level::ReadOnly, Level::Full, Level::None),
            parent.budget,
        );
        assert!(matches!(
            Manifest::validate_narrowing(&parent, &widen_grant).unwrap_err(),
            ManifestError::Trust(_)
        ));
        // Budget widen: child asks for more api calls.
        let widen_budget = Manifest::new(
            Goal::new("c"),
            parent.grant,
            Budget {
                wall_clock_secs: 100,
                max_commands: 10,
                max_money_cents: 0,
                max_api_calls: 999,
            },
        );
        assert!(matches!(
            Manifest::validate_narrowing(&parent, &widen_budget).unwrap_err(),
            ManifestError::BudgetWidens {
                field: "max_api_calls",
                ..
            }
        ));
    }

    #[test]
    fn implied_floor_tracks_exec_authority() {
        assert_eq!(
            IsolationFloor::implied_by(&Grant::new(Level::ReadOnly, Level::None, Level::None)),
            IsolationFloor::Namespace
        );
        assert_eq!(
            IsolationFloor::implied_by(&Grant::new(Level::Full, Level::Full, Level::Sandboxed)),
            IsolationFloor::Gvisor
        );
        assert_eq!(
            IsolationFloor::implied_by(&Grant::top()),
            IsolationFloor::MicroVm
        );
    }

    #[test]
    fn manifest_validates_when_floor_matches_grant() {
        assert!(analyze_manifest().validate().is_ok());
        // sudo + open internet must resolve to a microVM.
        let dangerous = Manifest::new(
            Goal::new("do anything"),
            Grant::top(),
            Budget::research_default(),
        );
        assert_eq!(dangerous.isolation_floor, IsolationFloor::MicroVm);
        assert!(dangerous.validate().is_ok());
    }

    #[test]
    fn floor_cannot_be_lowered_below_grant() {
        let m = Manifest::new(Goal::new("x"), Grant::top(), Budget::research_default())
            .with_floor(IsolationFloor::Namespace);
        // with_floor only raises; grant still implies microVM.
        assert_eq!(m.isolation_floor, IsolationFloor::MicroVm);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn narrowing_clamps_budget_and_grant() {
        let parent = Manifest::new(
            Goal::new("parent"),
            Grant::top(),
            Budget {
                wall_clock_secs: 600,
                max_commands: 1000,
                max_money_cents: 5000,
                max_api_calls: 500,
            },
        );
        let child = parent
            .narrow_to(
                Grant::new(Level::ReadOnly, Level::None, Level::None),
                Budget {
                    wall_clock_secs: 9999,
                    max_commands: 50,
                    max_money_cents: 0,
                    max_api_calls: 10,
                },
            )
            .unwrap();
        // Grant narrowed.
        assert_eq!(
            child.grant,
            Grant::new(Level::ReadOnly, Level::None, Level::None)
        );
        // Budget clamped to the min of parent and requested.
        assert_eq!(child.budget.wall_clock_secs, 600);
        assert_eq!(child.budget.max_commands, 50);
        // Floor re-derived: child needs only namespace but parent was
        // microVM, so it stays microVM (never weaker than parent).
        assert_eq!(child.isolation_floor, IsolationFloor::MicroVm);
    }

    #[test]
    fn narrowing_rejects_widening() {
        let parent = analyze_manifest(); // network: none
        let err = parent
            .narrow_to(
                Grant::new(Level::ReadWrite, Level::Full, Level::None),
                parent.budget,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            ManifestError::Trust(TrustError::Widens { .. })
        ));
    }

    #[test]
    fn content_id_is_stable_and_roundtrips() {
        let m = analyze_manifest();
        assert_eq!(m.content_id(), m.content_id());
        let json = m.to_json().unwrap();
        let back = Manifest::from_json(&json).unwrap();
        assert_eq!(m, back);
        assert_eq!(m.content_id(), back.content_id());
        assert_eq!(m.content_id().0.len(), 64);
    }

    #[test]
    fn actuation_is_optional_and_roundtrips() {
        // A manifest with no actuation behaves as before.
        let plain = analyze_manifest();
        assert!(plain.actuation.is_none());
        let back = Manifest::from_json(&plain.to_json().unwrap()).unwrap();
        assert_eq!(plain.content_id(), back.content_id());

        // Adding actuation changes the content address and survives a roundtrip.
        let with_act = Manifest {
            actuation: Some(Actuation {
                skills: vec!["move_to".into()],
                arm: ActuatorArm {
                    workspace_m: [Range { min: 0.1, max: 0.5 },
                                  Range { min: -0.3, max: 0.3 },
                                  Range { min: 0.0, max: 0.4 }],
                    max_velocity_mps: 0.25,
                    max_force_n: 15.0,
                },
                gripper: ActuatorGripper { max_grip_force_n: 20.0 },
            }),
            ..plain.clone()
        };
        assert_ne!(plain.content_id(), with_act.content_id());
        let back2 = Manifest::from_json(&with_act.to_json().unwrap()).unwrap();
        assert_eq!(back2.actuation, with_act.actuation);
    }
}
