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
        Self { transport, parent, send_failures: 0 }
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
}

fn convert(msg: AgentActionMsg, parent: &Manifest) -> AgentAction {
    match msg {
        AgentActionMsg::Run { command } => AgentAction::Run(command),
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
    use lex_os_proto::{AgentActionMsg, AgentViewMsg};

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
        }
    }

    #[test]
    fn proxies_run_action() {
        let (host_transport, mut guest) = simulated_pair();
        let mut agent = VsockAgent::new(host_transport, parent());

        // Spawn a thread acting as the guest.
        let handle = std::thread::spawn(move || {
            let view = guest.recv_view().unwrap();
            assert_eq!(view.step, 0);
            guest.send_action(&AgentActionMsg::Run { command: "fs.read".into() }).unwrap();
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
