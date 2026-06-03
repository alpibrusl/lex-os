//! `Transport` trait and the in-process `SimulatedTransport` for tests.

use std::io::{BufRead, Write};
use std::sync::mpsc;

use anyhow::Context;

use crate::msg::{AgentActionMsg, AgentViewMsg};

/// A synchronous, line-oriented byte channel between supervisor and guest.
///
/// Each `send_view` / `recv_action` pair corresponds to one supervisor step.
/// Implementations must be `Send` so the supervisor can own the transport
/// while the guest side runs on a separate thread (or in a separate process).
pub trait Transport: Send {
    /// Send the current step view to the guest (one JSON line).
    fn send_view(&mut self, view: &AgentViewMsg) -> anyhow::Result<()>;
    /// Block until the guest sends back an action (one JSON line).
    fn recv_action(&mut self) -> anyhow::Result<AgentActionMsg>;
}

/// Guest-side mirror: receive a view, send an action.
pub trait GuestTransport: Send {
    fn recv_view(&mut self) -> anyhow::Result<AgentViewMsg>;
    fn send_action(&mut self, action: &AgentActionMsg) -> anyhow::Result<()>;
}

// ── In-process simulated pair ─────────────────────────────────────────────────

/// Host side of the simulated pair.
pub struct SimulatedTransport {
    tx: mpsc::SyncSender<String>,
    rx: mpsc::Receiver<String>,
}

/// Guest side of the simulated pair.
pub struct SimulatedGuestTransport {
    tx: mpsc::SyncSender<String>,
    rx: mpsc::Receiver<String>,
}

/// Create a connected (host, guest) transport pair backed by in-process
/// channels. Usable from tests and the simulated perimeter on macOS.
pub fn simulated_pair() -> (SimulatedTransport, SimulatedGuestTransport) {
    let (host_tx, guest_rx) = mpsc::sync_channel(8);
    let (guest_tx, host_rx) = mpsc::sync_channel(8);
    (
        SimulatedTransport {
            tx: host_tx,
            rx: host_rx,
        },
        SimulatedGuestTransport {
            tx: guest_tx,
            rx: guest_rx,
        },
    )
}

impl Transport for SimulatedTransport {
    fn send_view(&mut self, view: &AgentViewMsg) -> anyhow::Result<()> {
        let line = serde_json::to_string(view).context("serialise view")?;
        self.tx.send(line).context("send view")?;
        Ok(())
    }

    fn recv_action(&mut self) -> anyhow::Result<AgentActionMsg> {
        let line = self.rx.recv().context("recv action")?;
        serde_json::from_str(&line).context("deserialise action")
    }
}

impl GuestTransport for SimulatedGuestTransport {
    fn recv_view(&mut self) -> anyhow::Result<AgentViewMsg> {
        let line = self.rx.recv().context("recv view")?;
        serde_json::from_str(&line).context("deserialise view")
    }

    fn send_action(&mut self, action: &AgentActionMsg) -> anyhow::Result<()> {
        let line = serde_json::to_string(action).context("serialise action")?;
        self.tx.send(line).context("send action")?;
        Ok(())
    }
}

// ── Stream-backed transport (e.g. vsock fd, TCP, Unix socket) ────────────────

/// Generic `Transport` backed by any `Read + Write` pair.
/// Used by the real vsock backend (wraps the vsock fd) and can wrap a
/// `std::net::TcpStream` for integration tests.
pub struct StreamTransport<R: BufRead + Send, W: Write + Send> {
    reader: R,
    writer: W,
}

impl<R: BufRead + Send, W: Write + Send> StreamTransport<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: BufRead + Send, W: Write + Send> Transport for StreamTransport<R, W> {
    fn send_view(&mut self, view: &AgentViewMsg) -> anyhow::Result<()> {
        let mut line = serde_json::to_string(view).context("serialise view")?;
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .context("write view")?;
        self.writer.flush().context("flush")?;
        Ok(())
    }

    fn recv_action(&mut self) -> anyhow::Result<AgentActionMsg> {
        let mut line = String::new();
        self.reader.read_line(&mut line).context("read action")?;
        serde_json::from_str(line.trim()).context("deserialise action")
    }
}

/// Guest-side mirror over a stream pair.
pub struct StreamGuestTransport<R: BufRead + Send, W: Write + Send> {
    reader: R,
    writer: W,
}

impl<R: BufRead + Send, W: Write + Send> StreamGuestTransport<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: BufRead + Send, W: Write + Send> GuestTransport for StreamGuestTransport<R, W> {
    fn recv_view(&mut self) -> anyhow::Result<AgentViewMsg> {
        let mut line = String::new();
        self.reader.read_line(&mut line).context("read view")?;
        serde_json::from_str(line.trim()).context("deserialise view")
    }

    fn send_action(&mut self, action: &AgentActionMsg) -> anyhow::Result<()> {
        let mut line = serde_json::to_string(action).context("serialise action")?;
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .context("write action")?;
        self.writer.flush().context("flush")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_pair_round_trips_one_step() {
        let (mut host, mut guest) = simulated_pair();

        let view = AgentViewMsg {
            goal: "test".into(),
            step: 0,
            last_outcome: None,
            completed: vec![],
        };
        host.send_view(&view).unwrap();

        let received = guest.recv_view().unwrap();
        assert_eq!(received.step, 0);
        assert_eq!(received.goal, "test");

        let action = AgentActionMsg::Run {
            command: "fs.read".into(),
        };
        guest.send_action(&action).unwrap();

        let received_action = host.recv_action().unwrap();
        assert!(matches!(received_action, AgentActionMsg::Run { command } if command == "fs.read"));
    }

    #[test]
    fn simulated_pair_done_action() {
        let (mut host, mut guest) = simulated_pair();
        let view = AgentViewMsg {
            goal: "g".into(),
            step: 1,
            last_outcome: None,
            completed: vec![],
        };
        host.send_view(&view).unwrap();
        guest.recv_view().unwrap();
        guest.send_action(&AgentActionMsg::Done).unwrap();
        assert!(matches!(host.recv_action().unwrap(), AgentActionMsg::Done));
    }

    #[test]
    fn stream_transport_round_trips() {
        use std::io::{BufReader, Cursor};

        // Encode a view, then decode it through StreamGuestTransport.
        let view = AgentViewMsg {
            goal: "stream test".into(),
            step: 5,
            last_outcome: Some("ok".into()),
            completed: vec!["fs.list".into()],
        };
        let mut buf = Vec::new();
        {
            let mut host =
                StreamTransport::new(BufReader::new(Cursor::new(b"" as &[u8])), &mut buf);
            host.send_view(&view).unwrap();
        }
        assert!(buf.ends_with(b"\n"));

        let mut guest =
            StreamGuestTransport::new(BufReader::new(Cursor::new(buf)), std::io::sink());
        let received = guest.recv_view().unwrap();
        assert_eq!(received.step, 5);
        assert_eq!(received.completed, vec!["fs.list"]);
    }
}
