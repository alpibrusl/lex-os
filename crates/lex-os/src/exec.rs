//! Shared pieces for `lex-os exec`: the wire spec sent to the guest's `exec`
//! script, the command registry `proc.exec` is mediated against, and
//! interpreting the resulting `SessionReport`.
//!
//! The actual connect/boot mechanics — a subprocess for `--simulated`, a
//! real Firecracker microVM otherwise — live next to `run_guest_in_vm` /
//! `run_guest_subprocess` in `main.rs`, which this shares almost everything
//! with: same guest binary, same wire protocol, same `Supervisor` +
//! `VsockAgent` loop. Only the transport and the guest script differ
//! ("exec", not the LLM reasoning loop) — see `lex-os-guest`'s
//! `run_exec_script` for the guest side of this.
//!
//! Why not just spawn the command on the host after checking the grant (an
//! earlier version of this module did exactly that)? Because `Perimeter::
//! provision` only *boots* a box — it doesn't relocate a `std::process::
//! Command` spawn into it. Reporting `security_boundary: true` while still
//! running the payload on the host would be a real, dangerous lie. Routing
//! the actual execution through the guest — which really is inside the
//! booted box — is what makes the real Firecracker backend meaningful here,
//! not just a swapped-out `Perimeter` impl.

use lex_os_audit::Event;
use lex_os_manifest::{Dimension, Level};
use lex_os_supervisor::{Command, CommandRegistry, SessionReport};

/// The `guest_script` value that selects `lex-os-guest`'s one-shot exec
/// mode instead of its default LLM reasoning loop.
pub const GUEST_SCRIPT: &str = "exec";

/// The single command `proc.exec` is mediated as. See `crates/lex-os-guest`'s
/// module doc for why one name is enough: the grant either allows arbitrary
/// exec at all or it doesn't — there's no per-binary vocabulary to gate on.
const COMMAND_NAME: &str = "proc.exec";

/// What the host sends the guest as `AgentViewMsg.goal` (JSON) — the guest's
/// `exec` script parses this back out before doing anything.
#[derive(serde::Serialize)]
pub struct ExecSpec<'a> {
    pub argv: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin: Option<&'a str>,
    pub wall_clock_secs: u64,
}

impl ExecSpec<'_> {
    pub fn goal_json(&self) -> String {
        serde_json::to_string(self).expect("ExecSpec always serialises")
    }
}

/// A registry with just `proc.exec` — this is the whole grant vocabulary
/// `exec` needs, gated on the `Exec` trust dimension at `Sandboxed` (the
/// minimum level that means "may run external commands at all").
pub fn registry() -> CommandRegistry {
    let mut r = CommandRegistry::new();
    r.register(Command::irreversible_bounded(
        COMMAND_NAME,
        Dimension::Exec,
        Level::Sandboxed,
        0,
        0,
    ));
    r
}

/// The three ways an exec session can end, derived uniformly from a
/// `SessionReport` regardless of which backend produced it.
pub enum Outcome {
    /// `proc.exec` was allowed and the guest ran it and reported back.
    Allowed {
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
        timed_out: bool,
    },
    /// `proc.exec` was denied by the grant before anything ran.
    Denied(String),
    /// Mediation allowed the command but the guest never reported a result
    /// (a transport failure, a crashed guest, or a protocol bug) — distinct
    /// from `Denied` so a caller never mistakes "we don't know" for "no".
    ProtocolFailure(String),
}

pub fn interpret(report: &SessionReport) -> Outcome {
    if let Some(exec) = &report.exec_result {
        return Outcome::Allowed {
            exit_code: exec.exit_code,
            stdout: exec.stdout.clone(),
            stderr: exec.stderr.clone(),
            timed_out: exec.timed_out,
        };
    }
    if report.ledger.commands_used() > 0 {
        return Outcome::ProtocolFailure(
            "proc.exec was allowed but the guest never reported a result".into(),
        );
    }
    let reason = report
        .audit
        .entries()
        .iter()
        .find_map(|e| match &e.event {
            Event::CommandDenied { command, reason } if command == COMMAND_NAME => {
                Some(reason.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| "denied (no CommandDenied event found in the audit log)".into());
    Outcome::Denied(reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_spec_omits_absent_stdin() {
        let argv = vec!["echo".to_string(), "hi".to_string()];
        let spec = ExecSpec {
            argv: &argv,
            stdin: None,
            wall_clock_secs: 30,
        };
        let json = spec.goal_json();
        assert!(!json.contains("stdin"));
        assert!(json.contains("\"wall_clock_secs\":30"));
    }

    #[test]
    fn exec_spec_carries_stdin_when_present() {
        let argv = vec!["cat".to_string()];
        let spec = ExecSpec {
            argv: &argv,
            stdin: Some("hello\n"),
            wall_clock_secs: 5,
        };
        let json = spec.goal_json();
        assert!(json.contains("\"stdin\":\"hello\\n\""));
    }

    #[test]
    fn registry_has_only_proc_exec() {
        let r = registry();
        assert_eq!(r.len(), 1);
        assert!(r.get(COMMAND_NAME).is_some());
    }
}
