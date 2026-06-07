//! Agent binary that runs **inside** the microVM.
//!
//! On boot the init script starts this binary. It connects to the host
//! supervisor over vsock (CID 2, port VSOCK_PORT), then enters a loop:
//!
//!   1. Receive `AgentViewMsg` from the supervisor.
//!   2. Call Ollama on the host via the one permitted egress target
//!      (`10.0.2.2:11434` — the host's tap-side IP). This is the only
//!      external connection the kernel egress wall allows.
//!   3. Parse the model's JSON response into an `AgentActionMsg`.
//!   4. Send the action to the supervisor and wait for the next view.
//!
//! On macOS (development), compile without `--features vsock` and the binary
//! uses a simulated transport driven via stdin/stdout instead of a real socket.

use std::env;

use anyhow::Context;
use lex_os_proto::msg::{AgentActionMsg, AgentViewMsg};
use lex_os_proto::transport::GuestTransport;
use serde_json::Value;

// The host's tap-side IP as seen from inside the guest, and the Ollama port.
// Override with OLLAMA_HOST env var when testing with a different address.
const DEFAULT_OLLAMA_HOST: &str = "10.0.2.2:11434";

const DEFAULT_MODEL: &str = "mistral";

fn main() -> anyhow::Result<()> {
    // Firecracker's serial console is a non-blocking fd; without this, a burst
    // of logging panics the guest with EAGAIN on stderr. Must run before any
    // print. No-op off the real VM (no vsock feature / non-Linux).
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    lex_os_proto::vsock::make_stdio_blocking();

    let ollama_host = env::var("OLLAMA_HOST").unwrap_or_else(|_| DEFAULT_OLLAMA_HOST.into());
    let model = env::var("OLLAMA_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.into());
    // A deterministic, LLM-free script for hardware demos (e.g. proving vsock
    // re-attach across a reprovision without depending on a model's whims).
    let script = env::var("LEX_OS_GUEST_SCRIPT").unwrap_or_default();

    eprintln!("[guest] starting; ollama={ollama_host} model={model} script={script:?}");

    let mut transport = connect_transport()?;
    eprintln!("[guest] transport connected");

    if script == "reprovision-demo" {
        return run_reprovision_demo(transport.as_mut());
    }

    // Give up after this many consecutive denied/blocked outcomes. A real model
    // may keep hammering a wall (devstral does); the agent must recognise it's
    // stuck and stop rather than loop until the supervisor's step ceiling.
    const MAX_CONSECUTIVE_DENIALS: u32 = 4;
    let mut consecutive_denials = 0u32;

    loop {
        let view = transport.recv_view().context("recv view")?;
        eprintln!("[guest] step {} goal={}", view.step, view.goal);

        // A denied/blocked last outcome means the previous action hit a wall.
        let hit_wall = view
            .last_outcome
            .as_deref()
            .map(|o| o.contains("denied") || o.contains("blocked"))
            .unwrap_or(false);
        consecutive_denials = if hit_wall { consecutive_denials + 1 } else { 0 };
        if consecutive_denials >= MAX_CONSECUTIVE_DENIALS {
            eprintln!(
                "[guest] {consecutive_denials} consecutive walls — giving up, signalling done"
            );
            transport
                .send_action(&AgentActionMsg::Done)
                .context("send action")?;
            break;
        }

        let prompt = build_prompt(&view);
        let action = match call_ollama(&ollama_host, &model, &prompt) {
            Ok(raw) => {
                eprintln!("[guest] model response: {raw}");
                parse_action(&raw).unwrap_or_else(|| {
                    eprintln!("[guest] could not parse action; defaulting to fs.read");
                    AgentActionMsg::Run {
                        command: "fs.read".into(),
                    }
                })
            }
            Err(e) => {
                eprintln!("[guest] ollama error: {e}; signalling done");
                AgentActionMsg::Done
            }
        };

        let terminal = matches!(
            action,
            AgentActionMsg::Done | AgentActionMsg::Destroy { .. }
        );
        transport.send_action(&action).context("send action")?;
        if terminal {
            break;
        }
    }

    eprintln!("[guest] loop complete");
    Ok(())
}

// ── Deterministic reprovision demo (model-free) ─────────────────────────────────

/// A deterministic, model-free agent used to prove vsock re-attach across a
/// reprovision on real hardware. It drives purely off the supervisor's view —
/// no network, so it needs no Ollama host: do one read, dispose the box once
/// mid-task, then (on the rebuilt box) write the report and finish.
fn run_reprovision_demo(transport: &mut dyn GuestTransport) -> anyhow::Result<()> {
    loop {
        let view = transport.recv_view().context("recv view")?;
        let action = scripted_action(&view);
        eprintln!(
            "[guest] reprovision-demo step={} reprovisions={} completed={:?} -> {action:?}",
            view.step, view.reprovisions, view.completed,
        );
        let terminal = matches!(
            action,
            AgentActionMsg::Done | AgentActionMsg::Destroy { .. }
        );
        transport.send_action(&action).context("send action")?;
        if terminal {
            break;
        }
    }
    eprintln!("[guest] reprovision-demo loop complete");
    Ok(())
}

/// The demo's decision function. Keyed on the externally-restored `completed`
/// list and the `reprovisions` count, so a fresh guest process on a rebuilt box
/// resumes correctly and disposes the box exactly once.
fn scripted_action(view: &AgentViewMsg) -> AgentActionMsg {
    let done = |c: &str| view.completed.iter().any(|x| x == c);
    if !done("fs.read") {
        AgentActionMsg::Run {
            command: "fs.read".into(),
        }
    } else if !done("report.write") {
        if view.reprovisions == 0 {
            // Dispose the box mid-task — exactly once — to force a reprovision.
            AgentActionMsg::Destroy {
                reason: "reprovision demo: dispose the box mid-task".into(),
            }
        } else {
            // On the rebuilt box the supervisor must have re-attached its vsock
            // channel for us to get here; finish the work it resumed.
            AgentActionMsg::Run {
                command: "report.write".into(),
            }
        }
    } else {
        AgentActionMsg::Done
    }
}

// ── Transport selection ───────────────────────────────────────────────────────

/// On Linux with `--features vsock`: connect over `AF_VSOCK`.
/// On macOS / without the feature: read/write newline-JSON on stdin/stdout
/// so the binary is still runnable for integration testing.
fn connect_transport() -> anyhow::Result<Box<dyn GuestTransport>> {
    #[cfg(all(feature = "vsock", target_os = "linux"))]
    {
        use lex_os_proto::vsock::guest_connect;
        let t = guest_connect().context("vsock connect")?;
        return Ok(Box::new(t));
    }

    #[allow(unreachable_code)]
    {
        // Stdio shim for local testing.
        use lex_os_proto::transport::StreamGuestTransport;
        use std::io::BufReader;
        eprintln!("[guest] no vsock feature — using stdin/stdout");
        let t = StreamGuestTransport::new(BufReader::new(std::io::stdin()), std::io::stdout());
        Ok(Box::new(t))
    }
}

// ── Prompt construction ───────────────────────────────────────────────────────

fn build_prompt(view: &AgentViewMsg) -> String {
    // Count consecutive propose_child attempts so we can warn the model.
    let consecutive_blocks = view
        .last_outcome
        .as_deref()
        .map(|o| o.starts_with("narrowing attempt blocked"))
        .unwrap_or(false);

    let block_warning = if consecutive_blocks {
        "\n⚠️  Your last propose_child was BLOCKED (the sandbox never widens itself). \
         Do NOT try propose_child again yet. Try a different command instead."
    } else {
        ""
    };

    format!(
        r#"You are an autonomous agent inside a sealed sandbox.

RULES:
- The supervisor mediates every command. If a command is DENIED, do NOT repeat it — try something else.
- You have only filesystem access. Network and exec commands will be DENIED by the wall.
- "propose_child" will be BLOCKED (the sandbox never widens your grant). Only try it once.
- You can always make progress with: fs.list, fs.read, fs.write, report.write.
- When you have written a report (even partial), signal done.{block_warning}

Respond with EXACTLY ONE JSON object, no prose, no markdown fences:
  {{"action":"fs.list"}}
  {{"action":"fs.read"}}
  {{"action":"fs.write"}}
  {{"action":"report.write"}}
  {{"action":"net.fetch"}}
  {{"action":"exec.shell"}}
  {{"action":"propose_child","reason":"<why>"}}
  {{"action":"done"}}

Goal: {goal}
Step: {step}
Last outcome: {last}
Completed: {completed}

JSON:"#,
        goal = view.goal,
        step = view.step,
        last = view
            .last_outcome
            .as_deref()
            .unwrap_or("none — this is your first step"),
        completed = if view.completed.is_empty() {
            "nothing yet".into()
        } else {
            view.completed.join(", ")
        },
        block_warning = block_warning,
    )
}

// ── Ollama call ───────────────────────────────────────────────────────────────

fn call_ollama(host: &str, model: &str, prompt: &str) -> anyhow::Result<String> {
    let url = format!("http://{host}/api/generate");
    let body = serde_json::json!({
        "model": model,
        "prompt": prompt,
        "stream": false,
    });
    let resp: Value = ureq::post(&url)
        .send_json(body)
        .context("ollama request")?
        .into_json()
        .context("ollama response")?;
    Ok(resp["response"].as_str().unwrap_or("").to_string())
}

// ── Action parsing ────────────────────────────────────────────────────────────

const KNOWN_COMMANDS: &[&str] = &[
    "fs.list",
    "fs.read",
    "fs.write",
    "report.write",
    "net.fetch",
    "exec.shell",
];

fn parse_action(response: &str) -> Option<AgentActionMsg> {
    let start = response.find('{')?;
    let tail = &response[start..];
    let mut depth = 0i32;
    let mut end = 0;
    for (i, ch) in tail.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let json_str = &response[start..=end];
    let v: Value = serde_json::from_str(json_str).ok()?;
    let action = v["action"].as_str()?;

    // Some models emit the command name directly as the action
    // (e.g. {"action":"net.fetch"}) rather than the run wrapper.
    // Accept both forms.
    if KNOWN_COMMANDS.contains(&action) {
        return Some(AgentActionMsg::Run {
            command: action.to_string(),
        });
    }

    match action {
        "run" => Some(AgentActionMsg::Run {
            command: v["command"].as_str()?.to_string(),
        }),
        "done" => Some(AgentActionMsg::Done),
        "destroy" => Some(AgentActionMsg::Destroy {
            reason: v["reason"].as_str().unwrap_or("agent decided").to_string(),
        }),
        "propose_child" => Some(AgentActionMsg::ProposeChild {
            reason: v["reason"]
                .as_str()
                .unwrap_or("need more access")
                .to_string(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_run() {
        let r = parse_action(r#"{"action":"run","command":"net.fetch"}"#);
        assert!(matches!(r, Some(AgentActionMsg::Run { command }) if command == "net.fetch"));
    }

    #[test]
    fn parses_done() {
        assert!(matches!(
            parse_action(r#"{"action":"done"}"#),
            Some(AgentActionMsg::Done)
        ));
    }

    #[test]
    fn parses_action_with_prose() {
        let r = parse_action("Sure! Here is my answer:\n{\"action\":\"done\"}\nOK.");
        assert!(matches!(r, Some(AgentActionMsg::Done)));
    }

    #[test]
    fn returns_none_for_garbage() {
        assert!(parse_action("I have no idea").is_none());
    }

    fn view(completed: &[&str], reprovisions: u32) -> AgentViewMsg {
        AgentViewMsg {
            goal: "demo".into(),
            step: 0,
            last_outcome: None,
            completed: completed.iter().map(|s| s.to_string()).collect(),
            reprovisions,
        }
    }

    #[test]
    fn demo_reads_first() {
        assert!(matches!(
            scripted_action(&view(&[], 0)),
            AgentActionMsg::Run { command } if command == "fs.read"
        ));
    }

    #[test]
    fn demo_disposes_box_once_after_first_read() {
        assert!(matches!(
            scripted_action(&view(&["fs.read"], 0)),
            AgentActionMsg::Destroy { .. }
        ));
    }

    #[test]
    fn demo_resumes_with_report_on_rebuilt_box() {
        // After the reprovision the guest must NOT dispose the box again —
        // it writes the report instead, keyed on the bumped reprovisions count.
        assert!(matches!(
            scripted_action(&view(&["fs.read"], 1)),
            AgentActionMsg::Run { command } if command == "report.write"
        ));
    }

    #[test]
    fn demo_done_after_report() {
        assert!(matches!(
            scripted_action(&view(&["fs.read", "report.write"], 1)),
            AgentActionMsg::Done
        ));
    }
}
