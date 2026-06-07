//! The supervisor (design doc §5, §9): the trusted thing outside the
//! box that does the three jobs the absent human used to do.
//!
//! 1. **Narrowest-possible grant.** Every command the agent runs is
//!    checked against the trust grant — through the [`Perimeter`], the
//!    kernel-level wall — before its effect happens. Ungranted effects
//!    are refused.
//! 2. **Hard, external resource bounds.** [`Budget`] is tracked by the
//!    supervisor, not the agent, and survives reprovisioning. On
//!    exhaustion the box halts regardless of goal state.
//! 3. **Liveness + tamper-proof audit.** Every decision is appended to
//!    an external [`AuditLog`] before its effect runs; the default is
//!    *stop*. When the box dies the supervisor reprovisions a fresh one
//!    from the manifest and last checkpoint — recovery belongs to the
//!    supervisor, never the agent (design doc §4).
//!
//! The agent is a "user" in the syscall sense: it never holds raw
//! authority, only the ability to *request* a command through this
//! mediated interface.

mod budget;
mod command;
mod vsock_agent;

pub use budget::{BudgetLedger, Charge};
pub use command::{Command, CommandRegistry};
pub use vsock_agent::VsockAgent;

use lex_os_audit::{AuditLog, Event};
use lex_os_manifest::{Dimension, Manifest, Reversibility};
use lex_os_perimeter::{Perimeter, SandboxPolicy};
use lex_os_resolver::{resolve, Environment, ResolveError};

/// A monotonic clock the supervisor reads for wall-clock budgeting.
/// Abstracted so tests can drive time deterministically.
pub trait Clock {
    /// Seconds since some fixed epoch; only differences matter.
    fn now_secs(&self) -> u64;
}

/// Wall-clock from the OS.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock the test harness advances by hand.
#[derive(Debug, Default)]
pub struct ManualClock {
    secs: std::cell::Cell<u64>,
}

impl ManualClock {
    pub fn new() -> Self {
        Self {
            secs: std::cell::Cell::new(0),
        }
    }
    pub fn advance(&self, by: u64) {
        self.secs.set(self.secs.get() + by);
    }
}

impl Clock for ManualClock {
    fn now_secs(&self) -> u64 {
        self.secs.get()
    }
}

/// What the agent decides to do next. The agent reasons freely inside
/// the box but can only affect the world through these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentAction {
    /// Request a mediated command by name.
    Run(String),
    /// Deliberately destroy the box (allowed — it is disposable).
    Destroy(String),
    /// Claim the goal is met (the supervisor still decides to stop).
    Done,
    /// Propose a child manifest. The supervisor validates the narrowing
    /// invariant and logs `NarrowingBlocked` if the child widens the
    /// parent grant — the live narrowing-check wall (design doc §7 Attempt 3).
    ProposeChild(Box<Manifest>),
}

/// What the agent sees between actions. The reasoning that produced an
/// action is the agent's own; the supervisor only feeds back observable
/// outcomes (design doc §12.3: effects replay, reasoning may not).
#[derive(Debug, Clone)]
pub struct AgentView<'a> {
    pub goal: &'a str,
    pub step: u64,
    pub last_outcome: Option<String>,
    /// Commands completed so far, restored from checkpoint after a
    /// reprovision — the agent is re-instantiated where it left off.
    pub completed: &'a [String],
    /// How many times the box has been rebuilt under this agent. The agent
    /// reasons on a fresh box after a reprovision; this is its only signal that
    /// the box changed underneath it (the completed list is restored either way).
    pub reprovisions: u32,
}

/// The agent: brings judgment, holds no authority.
pub trait Agent {
    fn next_action(&mut self, view: &AgentView) -> AgentAction;

    /// Called by the supervisor right after it rebuilds (reprovisions) the box,
    /// so a transport-backed agent can re-establish its channel to the freshly
    /// booted guest. Default: no-op — in-process and scripted agents have
    /// nothing to reconnect.
    fn on_reprovision(&mut self) {}
}

/// External, supervisor-owned progress record. Held outside the box so
/// a reprovisioned box can resume. Kept intentionally small.
#[derive(Debug, Clone, Default)]
pub struct Checkpoint {
    pub completed: Vec<String>,
}

/// Why a single mediation decision went the way it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// Denied for a policy reason (the command stays unrun).
    Denied(String),
    /// A budget ceiling was hit; the whole session must halt.
    BudgetExhausted(String),
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The agent signalled done and the supervisor accepted it.
    GoalMet,
    /// A hard budget ran out.
    BudgetExhausted(String),
    /// The box died too many times to be worth reprovisioning.
    MaxReprovisionsExceeded,
    /// The supervisor hit its loop ceiling (a stuck agent guard).
    StepCeilingReached,
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error("perimeter could not provision the box: {0}")]
    Provision(String),
}

/// Tuning knobs that are themselves safety bounds.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// How many times a dead box may be reprovisioned before giving up.
    pub max_reprovisions: u32,
    /// Absolute ceiling on supervisor loop iterations (guards against a
    /// stuck agent that neither finishes nor spends budget).
    pub max_steps: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_reprovisions: 3,
            max_steps: 10_000,
        }
    }
}

/// The result of running a session: the outcome plus the tamper-proof
/// audit log and the final budget ledger, both owned by the supervisor.
#[derive(Debug)]
pub struct SessionReport {
    pub outcome: Outcome,
    pub audit: AuditLog,
    pub ledger: BudgetLedger,
    pub reprovisions: u32,
}

/// The supervisor itself. Generic over the perimeter backend and the
/// clock so the same loop runs against a microVM in production and a
/// simulated box in tests.
pub struct Supervisor<P: Perimeter, C: Clock> {
    manifest: Manifest,
    registry: CommandRegistry,
    perimeter: P,
    clock: C,
    limits: Limits,
}

impl<P: Perimeter, C: Clock> Supervisor<P, C> {
    pub fn new(
        manifest: Manifest,
        registry: CommandRegistry,
        perimeter: P,
        clock: C,
        limits: Limits,
    ) -> Self {
        Self {
            manifest,
            registry,
            perimeter,
            clock,
            limits,
        }
    }

    /// Drive an agent to a terminal [`Outcome`]. This is the one
    /// end-to-end mediation loop the whole design reduces to (design doc
    /// §10): mediated, policy-checked, logged commands under a hard
    /// budget, with reprovision-on-death.
    pub fn run(
        mut self,
        env: &Environment,
        agent: &mut dyn Agent,
    ) -> Result<SessionReport, SupervisorError> {
        let _plan = resolve(&self.manifest, env)?;
        // Build the policy from the full manifest so the egress allowlist
        // is carried into the perimeter (the resolver still validates the
        // environment, but the authoritative policy comes from here).
        let policy = SandboxPolicy::from_manifest(&self.manifest);
        let mut audit = AuditLog::new();
        let mut ledger = BudgetLedger::new(self.manifest.budget, self.clock.now_secs());
        let mut checkpoint = Checkpoint::default();
        let mut reprovisions = 0u32;

        // Initial provisioning.
        self.perimeter
            .provision(policy.clone())
            .map_err(|e| SupervisorError::Provision(e.to_string()))?;
        audit.append(Event::Provisioned {
            manifest_id: self.manifest.content_id().0,
            backend: self.perimeter.backend_name().to_string(),
            reprovision: false,
        });

        let goal = self.manifest.goal.description.clone();
        let mut last_outcome: Option<String> = None;
        let mut step = 0u64;

        let outcome = loop {
            // Stuck-agent guard.
            if step >= self.limits.max_steps {
                break Outcome::StepCeilingReached;
            }

            // Wall-clock is a hard, external bound checked every step,
            // independent of whether the agent issues commands.
            if ledger.wall_clock_exhausted(self.clock.now_secs()) {
                audit.append(Event::BudgetExhausted {
                    which: "wall_clock".into(),
                });
                break Outcome::BudgetExhausted("wall_clock".into());
            }

            // Liveness contract: a dead box is reprovisioned from the
            // manifest + checkpoint, by the supervisor, outside the box.
            if !self.perimeter.is_alive() {
                audit.append(Event::LivenessFailed {
                    detail: "box not alive".into(),
                });
                if reprovisions >= self.limits.max_reprovisions {
                    break Outcome::MaxReprovisionsExceeded;
                }
                reprovisions += 1;
                self.perimeter
                    .provision(policy.clone())
                    .map_err(|e| SupervisorError::Provision(e.to_string()))?;
                audit.append(Event::Provisioned {
                    manifest_id: self.manifest.content_id().0,
                    backend: self.perimeter.backend_name().to_string(),
                    reprovision: true,
                });
                // Let the agent re-attach to the freshly booted box (the in-VM
                // agent must re-`accept()` its vsock channel — the old guest is
                // gone). The agent is re-instantiated where it left off; budget
                // is NOT reset (it is external and survives).
                agent.on_reprovision();
                continue;
            }

            let view = AgentView {
                goal: &goal,
                step,
                last_outcome: last_outcome.clone(),
                completed: &checkpoint.completed,
                reprovisions,
            };
            step += 1;

            match agent.next_action(&view) {
                AgentAction::Done => {
                    audit.append(Event::SessionEnded {
                        outcome: "goal_met".into(),
                    });
                    break Outcome::GoalMet;
                }
                AgentAction::Destroy(reason) => {
                    self.perimeter.destroy(&reason);
                    audit.append(Event::Destroyed { reason });
                    last_outcome = Some("box destroyed; supervisor will reprovision".into());
                    // Next iteration detects the dead box and recovers.
                }
                AgentAction::Run(name) => match self.mediate(&name, &mut audit, &mut ledger) {
                    Decision::Allowed => {
                        checkpoint.completed.push(name.clone());
                        last_outcome = Some(format!("ran `{name}`"));
                    }
                    Decision::Denied(reason) => {
                        last_outcome = Some(format!("`{name}` denied: {reason}"));
                    }
                    Decision::BudgetExhausted(which) => {
                        break Outcome::BudgetExhausted(which);
                    }
                },
                AgentAction::ProposeChild(child) => {
                    // Log the proposal as a command request; narrowing
                    // attempts do NOT consume command budget.
                    audit.append(Event::CommandRequested {
                        seq: ledger.commands_used(),
                        command: "manifest.narrow".into(),
                        reversibility: "irreversible-bounded".into(),
                    });
                    match Manifest::validate_narrowing(&self.manifest, &child) {
                        Err(e) => {
                            let reason = e.to_string();
                            audit.append(Event::NarrowingBlocked {
                                reason: reason.clone(),
                            });
                            last_outcome = Some(format!("narrowing attempt blocked: {reason}"));
                        }
                        Ok(()) => {
                            audit.append(Event::CommandAllowed {
                                command: "manifest.narrow".into(),
                            });
                            last_outcome = Some("child manifest accepted".into());
                        }
                    }
                }
            }
        };

        // Final book-keeping so the audit log itself records the end.
        if !matches!(outcome, Outcome::GoalMet) {
            audit.append(Event::SessionEnded {
                outcome: format!("{outcome:?}"),
            });
        }

        Ok(SessionReport {
            outcome,
            audit,
            ledger,
            reprovisions,
        })
    }

    /// Mediate one command request: the chokepoint every consequential
    /// action passes through. Order matters — log the request first, so
    /// even a denied or budget-blocked attempt is in the legible
    /// history.
    fn mediate(&self, name: &str, audit: &mut AuditLog, ledger: &mut BudgetLedger) -> Decision {
        let Some(cmd) = self.registry.get(name) else {
            audit.append(Event::CommandRequested {
                seq: ledger.commands_used(),
                command: name.to_string(),
                reversibility: "unknown".into(),
            });
            let reason = "no such command in the grant's registry".to_string();
            audit.append(Event::CommandDenied {
                command: name.to_string(),
                reason: reason.clone(),
            });
            return Decision::Denied(reason);
        };

        audit.append(Event::CommandRequested {
            seq: ledger.commands_used(),
            command: name.to_string(),
            reversibility: cmd.reversibility.as_str().to_string(),
        });

        // (1) Reversibility gate. With no human there is no approval
        // step, so an irreversible-and-consequential command must not be
        // runnable at all (design doc §6). The developer should never
        // register one; if it slips in, refuse here.
        if cmd.reversibility == Reversibility::IrreversibleConsequential {
            let reason =
                "irreversible-consequential command has no approval path in a no-human system"
                    .to_string();
            audit.append(Event::CommandDenied {
                command: name.to_string(),
                reason: reason.clone(),
            });
            return Decision::Denied(reason);
        }

        // (2) Capability gate, enforced at the perimeter (the kernel
        // wall). This holds even if the agent tries to bypass Lex.
        if let Err(e) = self.perimeter.check(cmd.dimension, cmd.required_level) {
            let reason = format!("blocked by perimeter: {e}");
            audit.append(Event::CommandDenied {
                command: name.to_string(),
                reason: reason.clone(),
            });
            return Decision::Denied(reason);
        }

        // (3) Budget gate. The charge is computed *before* the effect;
        // if it would exceed any ceiling, the box halts.
        let charge = Charge {
            commands: 1,
            money_cents: cmd.money_cents,
            api_calls: cmd.api_calls,
        };
        if let Some(which) = ledger.would_exceed(&charge) {
            audit.append(Event::BudgetExhausted {
                which: which.clone(),
            });
            return Decision::BudgetExhausted(which);
        }
        ledger.charge(&charge);
        audit.append(Event::BudgetCharged {
            commands: ledger.commands_used(),
            money_cents: ledger.money_used_cents(),
            api_calls: ledger.api_calls_used(),
            elapsed_secs: ledger.elapsed_secs(self.clock.now_secs()),
        });

        audit.append(Event::CommandAllowed {
            command: name.to_string(),
        });
        Decision::Allowed
    }
}

/// Convenience: which trust dimension a command name is conventionally
/// about, for callers building registries quickly.
pub fn dimension_hint(name: &str) -> Option<Dimension> {
    if name.starts_with("fs.") {
        Some(Dimension::Filesystem)
    } else if name.starts_with("net.") || name.starts_with("http.") {
        Some(Dimension::Network)
    } else if name.starts_with("exec.") || name.starts_with("proc.") {
        Some(Dimension::Exec)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{Budget, Goal, Grant, Level};
    use lex_os_perimeter::SimulatedPerimeter;

    /// A scripted agent that replays a fixed list of actions, then
    /// signals Done.
    struct ScriptedAgent {
        actions: Vec<AgentAction>,
        idx: usize,
    }
    impl ScriptedAgent {
        fn new(actions: Vec<AgentAction>) -> Self {
            Self { actions, idx: 0 }
        }
    }
    impl Agent for ScriptedAgent {
        fn next_action(&mut self, _view: &AgentView) -> AgentAction {
            let a = self
                .actions
                .get(self.idx)
                .cloned()
                .unwrap_or(AgentAction::Done);
            self.idx += 1;
            a
        }
    }

    /// A scripted agent that also records the supervisor's reconnect hook and
    /// the `reprovisions` count it sees on each view — the seam the in-VM agent
    /// uses to re-`accept()` the rebuilt guest over vsock.
    struct RecordingAgent {
        actions: Vec<AgentAction>,
        idx: usize,
        on_reprovision_calls: u32,
        views_reprovisions: Vec<u32>,
    }
    impl RecordingAgent {
        fn new(actions: Vec<AgentAction>) -> Self {
            Self {
                actions,
                idx: 0,
                on_reprovision_calls: 0,
                views_reprovisions: Vec::new(),
            }
        }
    }
    impl Agent for RecordingAgent {
        fn next_action(&mut self, view: &AgentView) -> AgentAction {
            self.views_reprovisions.push(view.reprovisions);
            let a = self
                .actions
                .get(self.idx)
                .cloned()
                .unwrap_or(AgentAction::Done);
            self.idx += 1;
            a
        }
        fn on_reprovision(&mut self) {
            self.on_reprovision_calls += 1;
        }
    }

    fn registry() -> CommandRegistry {
        let mut r = CommandRegistry::new();
        r.register(Command::reversible_cheap(
            "fs.read",
            Dimension::Filesystem,
            Level::ReadOnly,
        ));
        r.register(Command::irreversible_bounded(
            "fs.write",
            Dimension::Filesystem,
            Level::ReadWrite,
            0,
            0,
        ));
        r.register(Command::irreversible_bounded(
            "net.fetch",
            Dimension::Network,
            Level::Allowlist,
            5,
            1,
        ));
        // A consequential command that must always be refused.
        r.register(Command::irreversible_consequential(
            "fs.delete_all",
            Dimension::Filesystem,
            Level::ReadWrite,
        ));
        r
    }

    fn manifest(grant: Grant, budget: Budget) -> Manifest {
        Manifest::new(Goal::new("analyze and report"), grant, budget)
    }

    #[test]
    fn happy_path_reaches_goal_and_logs_everything() {
        let m = manifest(
            Grant::new(Level::ReadWrite, Level::None, Level::None),
            Budget::research_default(),
        );
        let sup = Supervisor::new(
            m,
            registry(),
            SimulatedPerimeter::new(),
            ManualClock::new(),
            Limits::default(),
        );
        let mut agent = ScriptedAgent::new(vec![
            AgentAction::Run("fs.read".into()),
            AgentAction::Run("fs.write".into()),
            AgentAction::Done,
        ]);
        let report = sup.run(&Environment::full(), &mut agent).unwrap();
        assert_eq!(report.outcome, Outcome::GoalMet);
        assert_eq!(report.ledger.commands_used(), 2);
        // The audit log is intact and tamper-evident.
        assert!(report.audit.verify().is_ok());
    }

    #[test]
    fn ungranted_effect_is_denied_by_perimeter() {
        // network: none, so net.fetch must be refused at the wall.
        let m = manifest(
            Grant::new(Level::ReadWrite, Level::None, Level::None),
            Budget::research_default(),
        );
        let sup = Supervisor::new(
            m,
            registry(),
            SimulatedPerimeter::new(),
            ManualClock::new(),
            Limits::default(),
        );
        let mut agent = ScriptedAgent::new(vec![
            AgentAction::Run("net.fetch".into()),
            AgentAction::Done,
        ]);
        let report = sup.run(&Environment::full(), &mut agent).unwrap();
        assert_eq!(report.outcome, Outcome::GoalMet);
        // Command was requested but never charged (denied before charge).
        assert_eq!(report.ledger.commands_used(), 0);
        assert_eq!(report.ledger.api_calls_used(), 0);
    }

    #[test]
    fn consequential_command_always_refused() {
        let m = manifest(Grant::top(), Budget::research_default());
        let sup = Supervisor::new(
            m,
            registry(),
            SimulatedPerimeter::new(),
            ManualClock::new(),
            Limits::default(),
        );
        let mut agent = ScriptedAgent::new(vec![
            AgentAction::Run("fs.delete_all".into()),
            AgentAction::Done,
        ]);
        let report = sup.run(&Environment::full(), &mut agent).unwrap();
        // Even with a top grant, the consequential command is refused.
        assert_eq!(report.ledger.commands_used(), 0);
        let denied = report
            .audit
            .entries()
            .iter()
            .any(|e| matches!(&e.event, Event::CommandDenied { command, .. } if command == "fs.delete_all"));
        assert!(denied);
    }

    #[test]
    fn budget_exhaustion_halts_the_box() {
        // api-call budget of 1; two net.fetch calls -> second exhausts.
        let budget = Budget {
            wall_clock_secs: 1000,
            max_commands: 100,
            max_money_cents: 1000,
            max_api_calls: 1,
        };
        let m = manifest(
            Grant::new(Level::ReadOnly, Level::Full, Level::None),
            budget,
        );
        let sup = Supervisor::new(
            m,
            registry(),
            SimulatedPerimeter::new(),
            ManualClock::new(),
            Limits::default(),
        );
        let mut agent = ScriptedAgent::new(vec![
            AgentAction::Run("net.fetch".into()),
            AgentAction::Run("net.fetch".into()),
            AgentAction::Done,
        ]);
        let report = sup.run(&Environment::full(), &mut agent).unwrap();
        assert_eq!(report.outcome, Outcome::BudgetExhausted("api_calls".into()));
        assert_eq!(report.ledger.api_calls_used(), 1);
    }

    #[test]
    fn destroyed_box_is_reprovisioned_and_resumes() {
        let m = manifest(
            Grant::new(Level::ReadWrite, Level::None, Level::None),
            Budget::research_default(),
        );
        let sup = Supervisor::new(
            m,
            registry(),
            SimulatedPerimeter::new(),
            ManualClock::new(),
            Limits::default(),
        );
        let mut agent = ScriptedAgent::new(vec![
            AgentAction::Run("fs.read".into()),
            AgentAction::Destroy("rm -rf / for fun".into()),
            AgentAction::Run("fs.write".into()),
            AgentAction::Done,
        ]);
        let report = sup.run(&Environment::full(), &mut agent).unwrap();
        assert_eq!(report.outcome, Outcome::GoalMet);
        assert_eq!(report.reprovisions, 1);
        // Budget survived the reprovision: both commands counted.
        assert_eq!(report.ledger.commands_used(), 2);
        // Audit shows a reprovision event.
        assert!(report.audit.entries().iter().any(|e| matches!(
            &e.event,
            Event::Provisioned {
                reprovision: true,
                ..
            }
        )));
        assert!(report.audit.verify().is_ok());
    }

    #[test]
    fn reprovision_notifies_agent_and_bumps_view_count() {
        // The seam the in-VM (vsock) agent needs: when the box is rebuilt the
        // supervisor must (a) tell the agent so it can re-attach its channel,
        // and (b) surface the new reprovision count on the very next view.
        let m = manifest(
            Grant::new(Level::ReadWrite, Level::None, Level::None),
            Budget::research_default(),
        );
        let sup = Supervisor::new(
            m,
            registry(),
            SimulatedPerimeter::new(),
            ManualClock::new(),
            Limits::default(),
        );
        let mut agent = RecordingAgent::new(vec![
            AgentAction::Run("fs.read".into()),
            AgentAction::Destroy("dispose the box".into()),
            AgentAction::Run("fs.write".into()),
            AgentAction::Done,
        ]);
        let report = sup.run(&Environment::full(), &mut agent).unwrap();

        assert_eq!(report.outcome, Outcome::GoalMet);
        assert_eq!(report.reprovisions, 1);
        // The agent was notified exactly once — once per reprovision.
        assert_eq!(agent.on_reprovision_calls, 1);
        // The first views are on the original box (0); the view after the
        // reprovision reports the box was rebuilt once.
        assert_eq!(agent.views_reprovisions.first(), Some(&0));
        assert_eq!(agent.views_reprovisions.last(), Some(&1));
    }

    #[test]
    fn propose_child_with_wider_grant_is_blocked_and_does_not_consume_budget() {
        // Parent has network: none; agent proposes a child with Full network
        // (a widening attempt). Supervisor must log NarrowingBlocked, the
        // session continues to GoalMet, and no command budget is spent.
        let m = manifest(
            Grant::new(Level::ReadWrite, Level::None, Level::None),
            Budget::research_default(),
        );
        let sup = Supervisor::new(
            m.clone(),
            registry(),
            SimulatedPerimeter::new(),
            ManualClock::new(),
            Limits::default(),
        );
        let child = Box::new(Manifest::new(
            Goal::new("widen"),
            Grant::top(), // Full network — widens the parent
            Budget::research_default(),
        ));
        let mut agent =
            ScriptedAgent::new(vec![AgentAction::ProposeChild(child), AgentAction::Done]);
        let report = sup.run(&Environment::full(), &mut agent).unwrap();
        // Session continues and reaches GoalMet.
        assert_eq!(report.outcome, Outcome::GoalMet);
        // Narrowing attempts do not spend command budget.
        assert_eq!(report.ledger.commands_used(), 0);
        // The audit log records the block.
        let blocked = report
            .audit
            .entries()
            .iter()
            .any(|e| matches!(&e.event, Event::NarrowingBlocked { .. }));
        assert!(blocked, "expected NarrowingBlocked in audit log");
        assert!(report.audit.verify().is_ok());
    }
}
