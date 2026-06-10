//! Real in-box execution (item 3): interpret a capsule's entrypoint with the
//! lex-bytecode VM and route every effect it performs through the supervisor's
//! mediation gate, instead of synthesising a workload from the *declared*
//! effects.
//!
//! The seam is lex-bytecode's [`EffectHandler`]: the VM calls `dispatch` for
//! every effect the program performs (`net.get`, `io.print`, …). Our handler
//! never performs the effect — it maps it to a mediated command, runs it
//! through the same [`Mediator`] the supervisor loop uses, and returns a
//! shape-correct stub on *allow* or an error on *deny*. So the box runs the
//! real code, but every consequential effect is gated at the edge — "free
//! inside the box, sealed at the edge" — and a refusal surfaces to the running
//! program as an `Err`, exactly as a real sandbox would fail the syscall.

use std::cell::RefCell;
use std::rc::Rc;

use lex_bytecode::vm::EffectHandler;
use lex_bytecode::Value;
use lex_os_audit::AuditLog;
use lex_os_perimeter::SimulatedPerimeter;
use lex_os_supervisor::{BudgetLedger, CommandRegistry, Decision, Mediator, SystemClock};

/// Session state the handler threads through the gate and the caller reads
/// back after the run completes.
pub struct MediationState {
    pub audit: AuditLog,
    pub ledger: BudgetLedger,
    /// Effects the entrypoint actually performed, in execution order
    /// (`kind.op`) — the faithful record the declared-effect stand-in couldn't
    /// give.
    pub performed: Vec<String>,
}

/// An [`EffectHandler`] that mediates rather than performs. It owns the
/// authority sources (registry, provisioned perimeter, clock) and shares the
/// mutable [`MediationState`] with its caller via `Rc<RefCell<…>>` so the audit
/// log and budget ledger survive the VM run.
pub struct MediatingHandler {
    registry: CommandRegistry,
    perimeter: SimulatedPerimeter,
    clock: SystemClock,
    state: Rc<RefCell<MediationState>>,
}

impl MediatingHandler {
    pub fn new(
        registry: CommandRegistry,
        perimeter: SimulatedPerimeter,
        state: Rc<RefCell<MediationState>>,
    ) -> Self {
        Self {
            registry,
            perimeter,
            clock: SystemClock,
            state,
        }
    }
}

impl EffectHandler for MediatingHandler {
    fn dispatch(&mut self, kind: &str, op: &str, _args: Vec<Value>) -> Result<Value, String> {
        self.state.borrow_mut().performed.push(format!("{kind}.{op}"));
        match classify(kind, op) {
            InBox::Mediated { command, stub } => {
                let mediator = Mediator::new(&self.registry, &self.perimeter, &self.clock);
                let mut guard = self.state.borrow_mut();
                // Reborrow to a plain `&mut` so the disjoint `audit`/`ledger`
                // field borrows split (they don't through the RefMut deref).
                let st = &mut *guard;
                match mediator.mediate(command, &mut st.audit, &mut st.ledger) {
                    Decision::Allowed => Ok(stub),
                    Decision::Denied(reason) => {
                        Err(format!("sealed at the edge — {kind}.{op} denied: {reason}"))
                    }
                    Decision::BudgetExhausted(which) => {
                        Err(format!("budget exhausted ({which}) at {kind}.{op}"))
                    }
                }
            }
            InBox::InProcess(stub) => Ok(stub),
            InBox::Unsupported => Err(format!(
                "effect {kind}.{op} is not yet mediated for in-box execution"
            )),
        }
    }
}

/// How lex-os mediates a given bytecode effect.
enum InBox {
    /// A consequential effect mediated as the named registry command; `stub`
    /// is the shape-correct value returned to the program when allowed.
    Mediated { command: &'static str, stub: Value },
    /// An in-process effect with no OS reach (stdout): allowed, no command.
    InProcess(Value),
    /// Not yet handled in-box; refused rather than silently performed.
    Unsupported,
}

/// `Result[Str, Str]::Ok("[mediated]")` — the shape `net.get`/`net.post` return.
fn ok_str() -> Value {
    Value::Variant {
        name: "Ok".into(),
        args: vec![Value::Str("[mediated]".into())],
    }
}

/// Map a bytecode effect `(kind, op)` to how it is mediated. Curated for the
/// first slice: network egress (the Network-dimension command) and stdout;
/// every other effect is refused until its result shape is wired up, so the
/// box never performs an effect lex-os can't yet gate.
fn classify(kind: &str, op: &str) -> InBox {
    match (kind, op) {
        ("net", _) => InBox::Mediated {
            command: "net.fetch",
            stub: ok_str(),
        },
        // Stdout has no OS boundary — `commands_for_effects` mapped `io` to
        // nothing for the same reason.
        ("io", "print") => InBox::InProcess(Value::Unit),
        _ => InBox::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_audit::AuditLog;
    use lex_os_manifest::{Budget, Grant, Level};
    use lex_os_perimeter::{Perimeter, SandboxPolicy};

    fn handler(grant: Grant) -> (MediatingHandler, Rc<RefCell<MediationState>>) {
        let mut perimeter = SimulatedPerimeter::new();
        perimeter
            .provision(SandboxPolicy::from_grant(&grant))
            .unwrap();
        // Headroom so the budget gate doesn't pre-empt the grant gate we're
        // testing (research_default allows 0¢; net.fetch costs 5¢).
        let mut budget = Budget::research_default();
        budget.max_money_cents = 100;
        let state = Rc::new(RefCell::new(MediationState {
            audit: AuditLog::new(),
            ledger: BudgetLedger::new(budget, 0),
            performed: Vec::new(),
        }));
        let h = MediatingHandler::new(crate::demo::demo_registry(), perimeter, Rc::clone(&state));
        (h, state)
    }

    #[test]
    fn net_is_allowed_and_returns_a_result_when_the_grant_permits() {
        let (mut h, state) = handler(Grant::new(Level::ReadOnly, Level::Allowlist, Level::None));
        let v = h.dispatch("net", "get", vec![]).unwrap();
        // Shape-correct stub: Result[Str, Str]::Ok(_).
        assert!(matches!(v, Value::Variant { ref name, .. } if name == "Ok"));
        // The effect was recorded and the gate logged the mediated command.
        assert_eq!(state.borrow().performed, vec!["net.get"]);
        assert!(state.borrow().audit.to_ndjson().unwrap().contains("net.fetch"));
    }

    #[test]
    fn net_is_sealed_at_the_edge_when_the_grant_forbids_it() {
        let (mut h, _s) = handler(Grant::new(Level::ReadOnly, Level::None, Level::None));
        let err = h.dispatch("net", "get", vec![]).unwrap_err();
        assert!(err.contains("sealed at the edge"), "got: {err}");
    }

    #[test]
    fn stdout_runs_in_process_without_a_command() {
        let (mut h, _s) = handler(Grant::new(Level::None, Level::None, Level::None));
        assert!(matches!(h.dispatch("io", "print", vec![]).unwrap(), Value::Unit));
    }

    #[test]
    fn an_unmediated_effect_is_refused_rather_than_performed() {
        // Even at top authority, an effect lex-os can't yet gate is refused —
        // the box never performs an effect outside the mediated set.
        let (mut h, _s) = handler(Grant::new(Level::Full, Level::Full, Level::Full));
        assert!(h.dispatch("sql", "query", vec![]).is_err());
    }
}
