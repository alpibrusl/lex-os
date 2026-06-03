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
    let ollama_host = env::var("OLLAMA_HOST").unwrap_or_else(|_| DEFAULT_OLLAMA_HOST.into());
    let model = env::var("OLLAMA_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.into());

    eprintln!("[guest] starting; ollama={ollama_host} model={model}");

    let mut transport = connect_transport()?;
    eprintln!("[guest] transport connected");

    loop {
        let view = transport.recv_view().context("recv view")?;
        eprintln!("[guest] step {} goal={}", view.step, view.goal);

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
}
