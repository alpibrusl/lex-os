//! Wire message types. One line in each direction per supervisor step.

use serde::{Deserialize, Serialize};

/// Host → Guest. Serialisation of `lex_os_supervisor::AgentView`.
/// Sent once at the start of every step (including after reprovision).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentViewMsg {
    pub goal: String,
    pub step: u64,
    pub last_outcome: Option<String>,
    pub completed: Vec<String>,
    /// How many times the supervisor has rebuilt the box so far. The guest is
    /// re-instantiated on a fresh box after a reprovision; this is the only
    /// signal that the box it is now running in is not the one it started in.
    /// Defaults to 0 for older peers / hand-built messages.
    #[serde(default)]
    pub reprovisions: u32,
}

/// Guest → Host. Serialisation of `lex_os_supervisor::AgentAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AgentActionMsg {
    /// Request a mediated command by name.
    Run { command: String },
    /// Request a mediated *robot skill* with structured arguments. The
    /// supervisor mediates the args against the manifest's actuation block,
    /// replies with a `SkillDecisionMsg`, and (if allowed) awaits a
    /// `SkillOutcomeMsg` after the guest executes the effect.
    RunSkill { skill: String, args: serde_json::Value },
    /// Signal goal complete.
    Done,
    /// Intentionally destroy the box.
    Destroy { reason: String },
    /// Propose a child manifest with broader trust (narrowing wall will
    /// decide whether to accept). The supervisor always builds the concrete
    /// child manifest on the host side — the guest only signals intent.
    ProposeChild { reason: String },
}

/// Host → Guest. The supervisor's decision on a `RunSkill`, sent before any
/// effect runs. On `allowed: true` the guest executes the skill against the
/// sidecar and replies with a `SkillOutcomeMsg`; on `false` it loops to the
/// next view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDecisionMsg {
    pub allowed: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Guest → Host. The observed result of executing an approved skill against
/// the sidecar. `observation` is the raw sidecar JSON (for the audit log).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillOutcomeMsg {
    pub outcome: String,
    pub observation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_round_trips() {
        let v = AgentViewMsg {
            goal: "write report".into(),
            step: 3,
            last_outcome: Some("fs.read allowed".into()),
            completed: vec!["fs.list".into()],
            reprovisions: 0,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: AgentViewMsg = serde_json::from_str(&json).unwrap();
        assert_eq!(back.step, 3);
        assert_eq!(back.completed, vec!["fs.list"]);
    }

    #[test]
    fn action_run_round_trips() {
        let a = AgentActionMsg::Run {
            command: "net.fetch".into(),
        };
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"action\":\"run\""));
        let back: AgentActionMsg = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, AgentActionMsg::Run { command } if command == "net.fetch"));
    }

    #[test]
    fn action_done_round_trips() {
        let json = serde_json::to_string(&AgentActionMsg::Done).unwrap();
        assert!(json.contains("\"action\":\"done\""));
    }

    #[test]
    fn action_propose_child_round_trips() {
        let a = AgentActionMsg::ProposeChild {
            reason: "need network".into(),
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: AgentActionMsg = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, AgentActionMsg::ProposeChild { .. }));
    }

    #[test]
    fn run_skill_round_trips() {
        let a = AgentActionMsg::RunSkill {
            skill: "move_to".into(),
            args: serde_json::json!({"x": 0.3, "y": 0.0, "z": 0.2}),
        };
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"action\":\"run_skill\""));
        let back: AgentActionMsg = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, AgentActionMsg::RunSkill { skill, .. } if skill == "move_to"));
    }

    #[test]
    fn decision_and_outcome_round_trip() {
        let d = SkillDecisionMsg { allowed: false, reason: Some("out of workspace".into()) };
        let back: SkillDecisionMsg = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert!(!back.allowed);

        let o = SkillOutcomeMsg { outcome: "reached".into(), observation: "{\"coverage\":0.9}".into() };
        let back2: SkillOutcomeMsg = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
        assert_eq!(back2.outcome, "reached");
    }
}
