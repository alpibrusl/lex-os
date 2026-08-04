//! `lex-os exec`: mediate one external command through a manifest's grant,
//! then actually run it.
//!
//! `run`'s scripted/LLM agent loop only ever *decides* on a named command
//! (`AgentAction::Run` maps straight to `Mediator::mediate` and never
//! performs the real OS effect — see `Supervisor::run`); real execution
//! today happens either inside a booted Firecracker microVM or inside the
//! in-box Lex bytecode interpreter (`capsule install --run`). Neither fits
//! "run this exact external command once and capture its output," which is
//! what a caller with an existing subprocess-shaped worker (not a Lex
//! program, not an open-ended reasoning loop) actually needs.
//!
//! This is the first place lex-os both mediates *and* performs a named
//! command's real effect. It reuses `Mediator` exactly as that type's own
//! doc comment invites — "so an in-box interpreter can apply the *same*
//! gate" — rather than adding a second, parallel decision path.
//!
//! Standing in for real Firecracker process isolation until the interpreted
//! entrypoint runs under a real rootfs+exec (lex-os#36): under `--simulated`
//! this is a real grant-gated allow/deny decision plus a real audit trail,
//! but the command that's allowed to run is not kernel-isolated while it
//! runs — the same honesty `run` already surfaces via `security_boundary`.

use std::io::Write;
use std::process::{Command as ProcCommand, Stdio};
use std::time::{Duration, Instant};

use lex_os_audit::AuditLog;
use lex_os_manifest::{Dimension, Level, Manifest};
use lex_os_perimeter::{Perimeter, SandboxPolicy, SimulatedPerimeter};
use lex_os_resolver::{resolve, Environment};
use lex_os_supervisor::{
    BudgetLedger, Clock, Command, CommandRegistry, Decision, Mediator, SystemClock,
};

/// The single command this module ever registers. One name is enough: the
/// caller supplies the actual argv, and the grant either allows arbitrary
/// exec at all (`exec: Sandboxed` or above) or it doesn't — there is no
/// per-binary vocabulary to gate on, so unlike `fs.read`/`net.fetch` there
/// is nothing finer-grained to name.
const COMMAND_NAME: &str = "proc.exec";

/// The result of one `run_exec` call: the mediation decision, the real
/// process outcome (only populated when `decision` is `Allowed`), and the
/// audit trail covering the decision itself.
pub struct ExecOutcome {
    pub decision: Decision,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub audit: AuditLog,
    pub commands_used: u64,
}

/// Mediate `argv` against `manifest`'s grant (currently always through the
/// simulated perimeter — see the module doc), and if allowed, actually run
/// it: `stdin_data` is piped in and closed, stdout/stderr are captured, and
/// `manifest.budget.wall_clock_secs` bounds the whole call (the process is
/// killed on timeout, same as the supervisor's own wall-clock gate).
pub fn run_exec(
    manifest: &Manifest,
    env: &Environment,
    argv: &[String],
    stdin_data: Option<&[u8]>,
) -> anyhow::Result<ExecOutcome> {
    let Some((bin, rest)) = argv.split_first() else {
        anyhow::bail!("exec requires a command after `--`");
    };

    // Same refuse-don't-downgrade check `run` performs before provisioning:
    // if the host can't reach the manifest's isolation floor, this fails
    // rather than silently running unsandboxed.
    let _plan = resolve(manifest, env)?;

    let mut registry = CommandRegistry::new();
    registry.register(Command::irreversible_bounded(
        COMMAND_NAME,
        Dimension::Exec,
        Level::Sandboxed,
        0,
        0,
    ));

    let mut perimeter = SimulatedPerimeter::new();
    let policy = SandboxPolicy::from_manifest(manifest);
    perimeter
        .provision(policy)
        .map_err(|e| anyhow::anyhow!("perimeter could not provision the box: {e}"))?;

    let clock = SystemClock;
    let mut audit = AuditLog::default();
    let mut ledger = BudgetLedger::new(manifest.budget, clock.now_secs());

    let decision =
        Mediator::new(&registry, &perimeter, &clock).mediate(COMMAND_NAME, &mut audit, &mut ledger);
    let commands_used = ledger.commands_used();

    if !matches!(decision, Decision::Allowed) {
        return Ok(ExecOutcome {
            decision,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            audit,
            commands_used,
        });
    }

    let mut child = ProcCommand::new(bin)
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Write, then close stdin regardless of whether there was data to write
    // — a command waiting for EOF on stdin (e.g. an LLM CLI reading a
    // piped prompt) would otherwise hang until the wall-clock kill.
    if let Some(mut stdin) = child.stdin.take() {
        if let Some(data) = stdin_data {
            let _ = stdin.write_all(data);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(manifest.budget.wall_clock_secs.max(1));
    let mut timed_out = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let output = child.wait_with_output()?;
    Ok(ExecOutcome {
        decision,
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        timed_out,
        audit,
        commands_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{Budget, Goal, Grant};

    fn env() -> Environment {
        Environment::full()
    }

    fn manifest_with_exec(exec: Level) -> Manifest {
        Manifest::new(
            Goal::new("test exec"),
            Grant::new(Level::ReadOnly, Level::None, exec),
            Budget {
                wall_clock_secs: 5,
                max_commands: 10,
                max_money_cents: 0,
                max_api_calls: 0,
            },
        )
    }

    #[test]
    fn exec_none_grant_denies_without_running() {
        let manifest = manifest_with_exec(Level::None);
        let out = run_exec(
            &manifest,
            &env(),
            &["echo".to_string(), "hi".to_string()],
            None,
        )
        .unwrap();
        assert!(matches!(out.decision, Decision::Denied(_)));
        assert_eq!(out.commands_used, 0);
        assert_eq!(out.exit_code, None);
    }

    #[test]
    fn exec_sandboxed_grant_allows_and_runs() {
        let manifest = manifest_with_exec(Level::Sandboxed);
        let out = run_exec(
            &manifest,
            &env(),
            &["echo".to_string(), "hello".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(out.decision, Decision::Allowed);
        assert_eq!(out.commands_used, 1);
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout.trim(), "hello");
        assert!(!out.timed_out);
    }

    #[test]
    fn stdin_is_piped_and_closed() {
        let manifest = manifest_with_exec(Level::Full);
        let out = run_exec(
            &manifest,
            &env(),
            &["cat".to_string()],
            Some(b"piped input\n"),
        )
        .unwrap();
        assert_eq!(out.decision, Decision::Allowed);
        assert_eq!(out.stdout, "piped input\n");
    }

    #[test]
    fn wall_clock_budget_kills_a_hanging_command() {
        let mut manifest = manifest_with_exec(Level::Sandboxed);
        manifest.budget.wall_clock_secs = 1;
        let out = run_exec(
            &manifest,
            &env(),
            &["sleep".to_string(), "10".to_string()],
            None,
        )
        .unwrap();
        assert_eq!(out.decision, Decision::Allowed);
        assert!(out.timed_out);
    }
}
