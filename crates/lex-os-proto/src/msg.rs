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
}

/// Guest → Host. Serialisation of `lex_os_supervisor::AgentAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AgentActionMsg {
    /// Request a mediated command by name.
    Run { command: String },
    /// Signal goal complete.
    Done,
    /// Intentionally destroy the box.
    Destroy { reason: String },
    /// Propose a child manifest with broader trust (narrowing wall will
    /// decide whether to accept). The supervisor always builds the concrete
    /// child manifest on the host side — the guest only signals intent.
    ProposeChild { reason: String },
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
}
