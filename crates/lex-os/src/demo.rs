//! A self-contained demo slice (design doc §10): one agent, a handful
//! of commands across the reversibility spectrum, one budget, one audit
//! log, one perimeter, one reprovision-on-death event. Enough to prove
//! the core mediation loop end-to-end without any external setup.

use lex_os_manifest::{Budget, Dimension, Goal, Grant, Level, Manifest};
use lex_os_supervisor::{Agent, AgentAction, AgentView, Command, CommandRegistry};

/// The canonical "analyze data → report" manifest: filesystem
/// read-write, no network, no exec. The narrowest grant that still lets
/// the agent meet the goal (design doc §5.1).
pub fn demo_manifest() -> Manifest {
    Manifest::new(
        Goal::new("analyze sales.csv and write report.md").with_done_signal("REPORT_WRITTEN"),
        Grant::new(Level::ReadWrite, Level::None, Level::None),
        Budget {
            wall_clock_secs: 300,
            max_commands: 20,
            max_money_cents: 0,
            max_api_calls: 0,
        },
    )
}

/// A handful of commands spanning the reversibility spectrum (design doc
/// §6). What the agent can actually do is the intersection of this
/// registry and the grant.
pub fn demo_registry() -> CommandRegistry {
    let mut r = CommandRegistry::new();
    // Reversible / cheap.
    r.register(Command::reversible_cheap(
        "fs.read",
        Dimension::Filesystem,
        Level::ReadOnly,
    ));
    r.register(Command::reversible_cheap(
        "fs.list",
        Dimension::Filesystem,
        Level::ReadOnly,
    ));
    // Irreversible but bounded.
    r.register(Command::irreversible_bounded(
        "fs.write",
        Dimension::Filesystem,
        Level::ReadWrite,
        0,
        0,
    ));
    r.register(Command::irreversible_bounded(
        "report.write",
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
    r.register(Command::irreversible_bounded(
        "exec.shell",
        Dimension::Exec,
        Level::Sandboxed,
        0,
        0,
    ));
    // Irreversible and consequential — present so its refusal is
    // demonstrable; the supervisor will never run it.
    r.register(Command::irreversible_consequential(
        "fs.delete_all",
        Dimension::Filesystem,
        Level::ReadWrite,
    ));
    r
}

/// A deterministic demo agent. It does real-looking work, deliberately
/// destroys its own box partway through (to exercise reprovision), then
/// reaches for commands that the grant may or may not allow, and finally
/// signals done. Its choices don't depend on the grant — that is the
/// point: the *supervisor* is what makes some of them no-ops.
pub struct DemoAgent {
    plan: Vec<AgentAction>,
    idx: usize,
}

impl Default for DemoAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl DemoAgent {
    pub fn new() -> Self {
        let plan = vec![
            AgentAction::Run("fs.list".into()),
            AgentAction::Run("fs.read".into()),
            // Trash the box mid-task; the supervisor must recover it.
            AgentAction::Destroy("agent ran `sudo rm -rf /` to free space".into()),
            // …and carry on after reprovision, resuming from checkpoint.
            AgentAction::Run("net.fetch".into()), // denied unless network granted
            AgentAction::Run("exec.shell".into()), // denied unless exec granted
            AgentAction::Run("fs.delete_all".into()), // always refused (consequential)
            AgentAction::Run("report.write".into()),
            AgentAction::Done,
        ];
        Self { plan, idx: 0 }
    }
}

impl Agent for DemoAgent {
    fn next_action(&mut self, _view: &AgentView) -> AgentAction {
        let action = self
            .plan
            .get(self.idx)
            .cloned()
            .unwrap_or(AgentAction::Done);
        self.idx += 1;
        action
    }
}
