//! `VsockAgent`: an `Agent` implementation that proxies every `next_action`
//! call to the in-guest agent binary over a `Transport`.
//!
//! The supervisor loop (`Supervisor::run`) does not change at all — it just
//! calls `agent.next_action(view)` as usual. `VsockAgent` serialises the view,
//! sends it down the channel, and waits for the guest's response. The guest
//! does the actual LLM reasoning; the supervisor never sees raw model output.
//!
//! ```text
//! Supervisor::run()
//!   │
//!   └─ vsock_agent.next_action(view)
//!        │  send AgentViewMsg  ──────→  guest binary
//!        │                             │  call Ollama
//!        │  recv AgentActionMsg  ←─────┘
//!        └─ convert to AgentAction → mediate
//! ```

use lex_os_manifest::{Budget, Goal, Grant, Manifest};
use lex_os_proto::msg::{AgentActionMsg, AgentViewMsg};
use lex_os_proto::transport::Transport;

use crate::{Agent, AgentAction, AgentView};

/// An `Agent` whose reasoning runs inside the microVM.
///
/// `T` is the transport — `SimulatedTransport` in tests, the vsock-backed
/// `StreamTransport` on a KVM host.
pub struct VsockAgent<T: Transport> {
    transport: T,
    /// Parent manifest — used to build the `ProposeChild` payload on the host
    /// side. The guest only sends intent ("I want broader access"); the host
    /// decides the concrete child manifest.
    parent: Manifest,
    send_failures: u32,
}

impl<T: Transport> VsockAgent<T> {
    pub fn new(transport: T, parent: Manifest) -> Self {
        Self {
            transport,
            parent,
            send_failures: 0,
        }
    }
}

impl<T: Transport> Agent for VsockAgent<T> {
    fn next_action(&mut self, view: &AgentView) -> AgentAction {
        if self.send_failures >= 3 {
            eprintln!("[vsock-agent] too many transport failures; signalling done");
            return AgentAction::Done;
        }

        let msg = AgentViewMsg {
            goal: view.goal.to_string(),
            step: view.step,
            last_outcome: view.last_outcome.clone(),
            completed: view.completed.to_vec(),
            reprovisions: view.reprovisions,
        };

        if let Err(e) = self.transport.send_view(&msg) {
            eprintln!("[vsock-agent] send error: {e}");
            self.send_failures += 1;
            return AgentAction::Done;
        }

        match self.transport.recv_action() {
            Err(e) => {
                eprintln!("[vsock-agent] recv error: {e}");
                self.send_failures += 1;
                AgentAction::Done
            }
            Ok(action) => {
                self.send_failures = 0;
                convert(action, &self.parent)
            }
        }
    }

    fn execute_skill(&mut self, decision: &crate::Decision) -> Option<crate::SkillOutcome> {
        use lex_os_proto::msg::SkillDecisionMsg;
        let (allowed, reason) = match decision {
            crate::Decision::Allowed => (true, None),
            crate::Decision::Denied(r) => (false, Some(r.clone())),
            crate::Decision::BudgetExhausted(r) => (false, Some(r.clone())),
        };
        if self.transport.send_decision(&SkillDecisionMsg { allowed, reason }).is_err() {
            return None;
        }
        if !allowed {
            return None; // guest will not execute; nothing to await
        }
        match self.transport.recv_outcome() {
            Ok(o) => Some(crate::SkillOutcome { outcome: o.outcome, observation: o.observation }),
            Err(_) => None,
        }
    }

    fn on_reprovision(&mut self) {
        // The old guest is gone with the old box; re-attach the channel so the
        // next `next_action` reaches the freshly booted guest, and clear the
        // failure latch so the deaths of the previous box don't count against it.
        if let Err(e) = self.transport.reconnect() {
            eprintln!("[vsock-agent] reconnect after reprovision failed: {e}");
        }
        self.send_failures = 0;
    }
}

fn convert(msg: AgentActionMsg, _parent: &Manifest) -> AgentAction {
    match msg {
        AgentActionMsg::Run { command } => AgentAction::Run(command),
        AgentActionMsg::RunSkill { skill, args } => AgentAction::RunSkill { skill, args },
        AgentActionMsg::Done => AgentAction::Done,
        AgentActionMsg::Destroy { reason } => AgentAction::Destroy(reason),
        AgentActionMsg::ProposeChild { .. } => {
            // Build the concrete widening attempt on the host side.
            // The narrowing wall will block this — that is the point.
            let child = Box::new(Manifest::new(
                Goal::new("get broader access to complete the goal"),
                Grant::top(),
                Budget::research_default(),
            ));
            AgentAction::ProposeChild(child)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_proto::transport::{simulated_pair, GuestTransport};
    use lex_os_proto::AgentActionMsg;

    use lex_os_manifest::{Budget, Goal, Grant, Level};

    fn parent() -> Manifest {
        Manifest::new(
            Goal::new("test goal"),
            Grant::new(Level::ReadWrite, Level::None, Level::None),
            Budget::research_default(),
        )
    }

    fn make_view(step: u64) -> AgentView<'static> {
        AgentView {
            goal: "test goal",
            step,
            last_outcome: None,
            completed: &[],
            reprovisions: 0,
        }
    }

    #[test]
    fn forwards_reprovisions_count_to_guest() {
        let (host_transport, mut guest) = simulated_pair();
        let mut agent = VsockAgent::new(host_transport, parent());

        let handle = std::thread::spawn(move || {
            let view = guest.recv_view().unwrap();
            // The guest must learn how many times its box was rebuilt.
            assert_eq!(view.reprovisions, 2);
            guest.send_action(&AgentActionMsg::Done).unwrap();
        });

        let view = AgentView {
            goal: "test goal",
            step: 5,
            last_outcome: None,
            completed: &[],
            reprovisions: 2,
        };
        let _ = agent.next_action(&view);
        handle.join().unwrap();
    }

    #[test]
    fn proxies_run_action() {
        let (host_transport, mut guest) = simulated_pair();
        let mut agent = VsockAgent::new(host_transport, parent());

        // Spawn a thread acting as the guest.
        let handle = std::thread::spawn(move || {
            let view = guest.recv_view().unwrap();
            assert_eq!(view.step, 0);
            guest
                .send_action(&AgentActionMsg::Run {
                    command: "fs.read".into(),
                })
                .unwrap();
        });

        let view = make_view(0);
        let action = agent.next_action(&view);
        handle.join().unwrap();
        assert!(matches!(action, AgentAction::Run(c) if c == "fs.read"));
    }

    #[test]
    fn proxies_done_action() {
        let (host_transport, mut guest) = simulated_pair();
        let mut agent = VsockAgent::new(host_transport, parent());

        let handle = std::thread::spawn(move || {
            guest.recv_view().unwrap();
            guest.send_action(&AgentActionMsg::Done).unwrap();
        });

        let action = agent.next_action(&make_view(1));
        handle.join().unwrap();
        assert!(matches!(action, AgentAction::Done));
    }

    #[test]
    fn propose_child_widens_grant() {
        let (host_transport, mut guest) = simulated_pair();
        let mut agent = VsockAgent::new(host_transport, parent());

        let handle = std::thread::spawn(move || {
            guest.recv_view().unwrap();
            guest
                .send_action(&AgentActionMsg::ProposeChild {
                    reason: "need network".into(),
                })
                .unwrap();
        });

        let action = agent.next_action(&make_view(2));
        handle.join().unwrap();
        assert!(matches!(action, AgentAction::ProposeChild(_)));
    }

    #[test]
    fn on_reprovision_reconnects_and_clears_failure_count() {
        use lex_os_proto::transport::Transport;
        use std::sync::{Arc, Mutex};

        // A transport whose guest has died (sends fail) until it is reconnected.
        struct Flaky {
            fail: Arc<Mutex<bool>>,
            reconnects: Arc<Mutex<u32>>,
        }
        impl Transport for Flaky {
            fn send_view(&mut self, _v: &AgentViewMsg) -> anyhow::Result<()> {
                if *self.fail.lock().unwrap() {
                    anyhow::bail!("dead guest")
                } else {
                    Ok(())
                }
            }
            fn recv_action(&mut self) -> anyhow::Result<AgentActionMsg> {
                Ok(AgentActionMsg::Run {
                    command: "fs.read".into(),
                })
            }
            fn send_decision(
                &mut self,
                _d: &lex_os_proto::msg::SkillDecisionMsg,
            ) -> anyhow::Result<()> {
                Ok(())
            }
            fn recv_outcome(&mut self) -> anyhow::Result<lex_os_proto::msg::SkillOutcomeMsg> {
                anyhow::bail!("no outcome")
            }
            fn reconnect(&mut self) -> anyhow::Result<()> {
                *self.reconnects.lock().unwrap() += 1;
                *self.fail.lock().unwrap() = false; // the rebuilt guest is reachable
                Ok(())
            }
        }

        let fail = Arc::new(Mutex::new(true));
        let reconnects = Arc::new(Mutex::new(0));
        let t = Flaky {
            fail: fail.clone(),
            reconnects: reconnects.clone(),
        };
        let mut agent = VsockAgent::new(t, parent());

        // The dead guest makes sends fail; the agent gives up (Done) and latches
        // its failure count at the ceiling.
        for _ in 0..4 {
            assert!(matches!(
                agent.next_action(&make_view(0)),
                AgentAction::Done
            ));
        }

        // Reprovision: the supervisor tells the agent to re-attach its channel.
        agent.on_reprovision();
        assert_eq!(*reconnects.lock().unwrap(), 1);

        // The latch is cleared and the channel works, so the agent talks to the
        // rebuilt guest again instead of short-circuiting to Done.
        assert!(matches!(
            agent.next_action(&make_view(0)),
            AgentAction::Run(c) if c == "fs.read"
        ));
    }

    #[test]
    fn execute_skill_relays_decision_and_returns_outcome() {
        use lex_os_proto::transport::{simulated_pair, GuestTransport};
        use lex_os_proto::msg::{SkillDecisionMsg, SkillOutcomeMsg};
        use crate::{Agent, Decision};

        let (host, mut guest) = simulated_pair();
        let mut agent = VsockAgent::new(host, parent());

        // Guest side: expect a decision, then reply with an outcome.
        let guest_thread = std::thread::spawn(move || {
            let d: SkillDecisionMsg = guest.recv_decision().unwrap();
            assert!(d.allowed);
            guest.send_outcome(&SkillOutcomeMsg {
                outcome: "reached".into(), observation: "{\"coverage\":0.9}".into(),
            }).unwrap();
        });

        let out = agent.execute_skill(&Decision::Allowed).unwrap();
        assert_eq!(out.outcome, "reached");
        guest_thread.join().unwrap();
    }

    #[test]
    fn transport_failure_signals_done() {
        let (host_transport, guest) = simulated_pair();
        // Drop the guest side immediately — next recv will fail.
        drop(guest);
        let mut agent = VsockAgent::new(host_transport, parent());
        // First failure: send succeeds (channel has buffer), recv fails.
        // Third consecutive failure threshold → Done.
        for _ in 0..3 {
            let action = agent.next_action(&make_view(0));
            if matches!(action, AgentAction::Done) {
                return;
            }
        }
        panic!("expected Done after transport failures");
    }
}
