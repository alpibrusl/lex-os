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

/// `Result[Str, Str]::Ok("[mediated]")` — the shape `net.get`/`io.read` return.
fn ok_str() -> Value {
    Value::Variant {
        name: "Ok".into(),
        args: vec![Value::Str("[mediated]".into())],
    }
}

/// `Result[Unit, Str]::Ok(())` — the shape `io.write` returns.
fn ok_unit() -> Value {
    Value::Variant {
        name: "Ok".into(),
        args: vec![Value::Unit],
    }
}

/// `Option[Str]::None` — the shape `io.readline` returns at EOF.
fn none_value() -> Value {
    Value::Variant {
        name: "None".into(),
        args: vec![],
    }
}

/// `Result[{stdout, stderr, exit_code}, Str]::Ok(record)` — the shape
/// `proc.spawn` returns: an empty, exit-0 result for the simulated box.
fn proc_ok() -> Value {
    let mut record = indexmap::IndexMap::new();
    record.insert("stdout".to_string(), Value::Str("".into()));
    record.insert("stderr".to_string(), Value::Str("".into()));
    record.insert("exit_code".to_string(), Value::Int(0));
    Value::Variant {
        name: "Ok".into(),
        args: vec![Value::record_dynamic(record)],
    }
}

/// `Result[List[Str], Str]::Ok([])` — the shape `fs.list_dir`/`walk`/`glob`
/// return (an empty listing in the simulated box).
fn ok_list() -> Value {
    Value::Variant {
        name: "Ok".into(),
        args: vec![Value::List(Default::default())],
    }
}

/// `Result[{size, mtime, is_dir, is_file}, Str]::Ok(record)` — the shape
/// `fs.stat` returns.
fn ok_stat() -> Value {
    let mut record = indexmap::IndexMap::new();
    record.insert("size".to_string(), Value::Int(0));
    record.insert("mtime".to_string(), Value::Int(0));
    record.insert("is_dir".to_string(), Value::Bool(false));
    record.insert("is_file".to_string(), Value::Bool(false));
    Value::Variant {
        name: "Ok".into(),
        args: vec![Value::record_dynamic(record)],
    }
}

/// Map a bytecode effect `(kind, op)` to how it is mediated. Curated to the
/// effects whose result shapes are wired up and whose grant dimension is known;
/// every other effect is refused until it is added, so the box never performs an
/// effect lex-os can't yet gate.
///
/// Dimension mapping follows the static effect model exactly (so the runtime
/// gate can't contradict the type-check wall): `net` → Network, `proc` → Exec,
/// the `fs` module → Filesystem (read-family `[fs_walk]`/`[fs_read]` at
/// read-only, mutations `[fs_write]` at read-write), and the `io` family
/// carries the ungated `[io]` effect — `io.read`/`io.write` do touch files, but
/// the language models them as `[io]`, so a capsule that type-checked with an
/// io-only grant must see them allowed here, in-process.
///
/// `arrow.read_csv`/`tls.from_pem_files` also carry `[fs_read]` but return rich
/// values (a `Table`, an opaque `TlsConfig`); they are a follow-up.
fn classify(kind: &str, op: &str) -> InBox {
    match (kind, op) {
        // Network egress → the Network-dimension command.
        ("net", _) => InBox::Mediated {
            command: "net.fetch",
            stub: ok_str(),
        },
        // Subprocess execution → the Exec-dimension command.
        ("proc", _) => InBox::Mediated {
            command: "exec.shell",
            stub: proc_ok(),
        },
        // Filesystem reads / traversal ([fs_read] / [fs_walk]) → fs.read
        // (read-only). Return shapes match each builtin: a bare `Bool`, or a
        // `Result` over a list / stat record.
        ("fs", "exists" | "is_file" | "is_dir") => InBox::Mediated {
            command: "fs.read",
            stub: Value::Bool(false),
        },
        ("fs", "list_dir" | "walk" | "glob") => InBox::Mediated {
            command: "fs.read",
            stub: ok_list(),
        },
        ("fs", "stat") => InBox::Mediated {
            command: "fs.read",
            stub: ok_stat(),
        },
        // Filesystem mutations ([fs_write]) → fs.write (read-write).
        ("fs", "mkdir_p" | "remove" | "copy") => InBox::Mediated {
            command: "fs.write",
            stub: ok_unit(),
        },
        // The `io` family carries `[io]` — ungated by the grant, so allowed
        // in-process with a shape-correct stub (no OS effect in the sim box).
        ("io", "print") => InBox::InProcess(Value::Unit),
        ("io", "read") => InBox::InProcess(ok_str()),
        ("io", "write") => InBox::InProcess(ok_unit()),
        ("io", "readline") => InBox::InProcess(none_value()),
        ("io", "argv") => InBox::InProcess(Value::List(Default::default())),
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

    #[test]
    fn proc_is_gated_on_the_exec_dimension() {
        // Allowed when exec is granted: returns Result::Ok(record).
        let (mut h, state) = handler(Grant::new(Level::None, Level::None, Level::Sandboxed));
        let v = h.dispatch("proc", "spawn", vec![]).unwrap();
        assert!(matches!(v, Value::Variant { ref name, .. } if name == "Ok"));
        assert!(state
            .borrow()
            .audit
            .to_ndjson()
            .unwrap()
            .contains("exec.shell"));

        // Sealed at the edge when exec is not granted.
        let (mut h, _s) = handler(Grant::new(Level::Full, Level::Full, Level::None));
        let err = h.dispatch("proc", "spawn", vec![]).unwrap_err();
        assert!(err.contains("sealed at the edge"), "got: {err}");
    }

    #[test]
    fn fs_reads_are_gated_at_read_only_and_writes_at_read_write() {
        // Read-only grant: traversal reads pass, mutations are sealed.
        let (mut h, state) = handler(Grant::new(Level::ReadOnly, Level::None, Level::None));
        assert!(matches!(h.dispatch("fs", "exists", vec![]).unwrap(), Value::Bool(_)));
        assert!(matches!(h.dispatch("fs", "list_dir", vec![]).unwrap(),
            Value::Variant { ref name, .. } if name == "Ok"));
        assert!(state.borrow().audit.to_ndjson().unwrap().contains("fs.read"));
        // mkdir needs read-write; a read-only grant seals it at the edge.
        let err = h.dispatch("fs", "mkdir_p", vec![]).unwrap_err();
        assert!(err.contains("sealed at the edge"), "got: {err}");

        // Read-write grant: mutations pass too.
        let (mut h, _s) = handler(Grant::new(Level::ReadWrite, Level::None, Level::None));
        assert!(matches!(h.dispatch("fs", "mkdir_p", vec![]).unwrap(),
            Value::Variant { ref name, .. } if name == "Ok"));
    }

    #[test]
    fn fs_is_sealed_when_the_grant_has_no_filesystem() {
        let (mut h, _s) = handler(Grant::new(Level::None, Level::Full, Level::Full));
        assert!(h.dispatch("fs", "exists", vec![]).unwrap_err().contains("sealed at the edge"));
    }

    #[test]
    fn the_io_family_runs_in_process_with_shape_correct_stubs() {
        // `[io]` is ungated, so these are allowed under any grant — and the
        // stub shape matches each builtin's return type.
        let (mut h, _s) = handler(Grant::new(Level::None, Level::None, Level::None));
        assert!(matches!(h.dispatch("io", "read", vec![]).unwrap(),
            Value::Variant { ref name, .. } if name == "Ok"));
        assert!(matches!(h.dispatch("io", "write", vec![]).unwrap(),
            Value::Variant { ref name, .. } if name == "Ok"));
        assert!(matches!(h.dispatch("io", "readline", vec![]).unwrap(),
            Value::Variant { ref name, .. } if name == "None"));
        assert!(matches!(h.dispatch("io", "argv", vec![]).unwrap(), Value::List(_)));
        // None of the ungated io effects logged a mediated command.
        // (only the performed list grows)
    }
}
