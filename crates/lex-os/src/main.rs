//! `lex-os` — the autonomous-agent runtime CLI.
//!
//! It speaks the [acli](https://github.com/alpibrusl/acli) protocol so an
//! agent can discover and drive it the same way it discovers any other
//! tool: structured JSON envelopes, semantic exit codes, and an
//! `introspect` command tree.
//!
//! The CLI is a thin shell over the crates that do the work:
//! `lex-os-resolver` negotiates a manifest against the host,
//! `lex-os-perimeter` enforces the derived sandbox policy, and
//! `lex-os-supervisor` runs the mediated command loop under hard
//! budgets with reprovision-on-death.

mod agent;
mod demo;

use std::path::PathBuf;
use std::time::Instant;

use acli::introspect::{CommandInfo, CommandTree};
use acli::{emit, error_envelope, success_envelope, ExitCode, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

use lex_os_audit::AuditLog;
use lex_os_manifest::Manifest;
#[cfg(feature = "firecracker")]
use lex_os_perimeter::FirecrackerPerimeter;
#[cfg(not(feature = "firecracker"))]
use lex_os_perimeter::SimulatedPerimeter;
use lex_os_resolver::{resolve, Environment};
use lex_os_supervisor::{Limits, Supervisor, SystemClock};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "lex-os",
    version = VERSION,
    about = "Autonomous-agent runtime: a sealed box plus a goal, supervised from outside."
)]
struct Cli {
    /// Output format (text for humans, json for agents).
    #[arg(long, global = true, default_value = "text")]
    output: Format,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Text,
    Json,
}

impl Format {
    fn to_acli(self) -> OutputFormat {
        match self {
            Format::Text => OutputFormat::Text,
            Format::Json => OutputFormat::Json,
        }
    }
}

/// Which LLM backend drives the agent.
#[derive(Copy, Clone, ValueEnum, Default)]
enum AgentBackend {
    /// Scripted deterministic demo agent (no model required).
    #[default]
    Demo,
    /// Local Ollama model (default: mistral). No egress needed.
    Ollama,
    /// Anthropic Claude (ANTHROPIC_API_KEY env var required).
    Anthropic,
    /// OpenAI-compatible endpoint (OPENAI_API_KEY env var required).
    OpenAi,
}

#[derive(Subcommand)]
enum Cmd {
    /// Dispatch an agent against a manifest and run the mediation loop
    /// to a terminal outcome.
    Run {
        /// Path to a manifest JSON file. Omit to use the built-in demo.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Write the resulting tamper-proof audit log here.
        #[arg(long)]
        audit_out: Option<PathBuf>,
        /// Pretend the host can only do namespace isolation.
        #[arg(long)]
        namespaces_only: bool,
        /// Pretend the host has no outbound network.
        #[arg(long)]
        offline: bool,
        /// LLM backend to use as the agent brain (default: demo).
        #[arg(long, default_value = "demo")]
        agent: AgentBackend,
        /// Model name for the selected backend (e.g. "mistral", "qwen2.5-coder").
        #[arg(long)]
        model: Option<String>,
        /// Ollama base URL (default: http://localhost:11434).
        #[arg(long)]
        ollama_url: Option<String>,
    },
    /// Negotiate a manifest against the (simulated) host and show what
    /// it resolves to — without running anything.
    Resolve {
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        namespaces_only: bool,
        #[arg(long)]
        offline: bool,
    },
    /// Manifest utilities.
    Manifest {
        #[command(subcommand)]
        what: ManifestCmd,
    },
    /// Audit-log utilities.
    Audit {
        #[command(subcommand)]
        what: AuditCmd,
    },
    /// Type-check an agent Lex program against a manifest grant and
    /// refuse it if its effects exceed the grant — the type-check wall
    /// (demo Attempt 1), run *before* the program executes.
    Check {
        /// Manifest JSON whose grant + egress the program is checked against.
        #[arg(long)]
        grant: PathBuf,
        /// The agent `.lex` program to check.
        program: PathBuf,
    },
    /// Emit the acli command tree for agent discovery.
    Introspect,
    /// Standalone Wall-2 proof: boot a real Firecracker microVM with the
    /// host-side egress wall, dwell while the guest boots and runs
    /// `/sbin/init.demo` (the egress probes), then tear it down. Streams the
    /// guest console. Requires `--features firecracker`, a KVM host, and root.
    #[cfg(feature = "firecracker")]
    BoxSmoke {
        /// Manifest whose grant + egress allowlist define the box's wall.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Seconds to let the guest boot and run its init before teardown.
        #[arg(long, default_value_t = 12)]
        dwell: u64,
    },
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Print the built-in demo manifest as JSON.
    Sample,
    /// Print the content-address (hash) of a manifest.
    Hash {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Validate that a child manifest only *narrows* a parent (grant,
    /// egress allowlist, and budgets). Rejects any widening — the
    /// narrowing-invariant wall (demo Attempt 3).
    Narrow {
        #[arg(long)]
        parent: PathBuf,
        #[arg(long)]
        child: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify the hash chain of an audit log file.
    Verify {
        #[arg(long)]
        log: PathBuf,
    },
    /// Render an audit log as newline-delimited JSON (one entry per
    /// line) for a live, tailable external view.
    Render {
        #[arg(long)]
        log: PathBuf,
    },
    /// Follow an audit log file, printing new entries as they arrive
    /// (one NDJSON line per entry). Runs indefinitely; press Ctrl-C to stop.
    Tail {
        #[arg(long)]
        log: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let fmt = cli.output.to_acli();
    let code = match cli.command {
        Cmd::Run {
            manifest,
            audit_out,
            namespaces_only,
            offline,
            agent,
            model,
            ollama_url,
        } => cmd_run(&fmt, manifest, audit_out, namespaces_only, offline, agent, model, ollama_url),
        Cmd::Resolve {
            manifest,
            namespaces_only,
            offline,
        } => cmd_resolve(&fmt, manifest, namespaces_only, offline),
        Cmd::Manifest { what } => cmd_manifest(&fmt, what),
        Cmd::Audit { what } => cmd_audit(&fmt, what),
        Cmd::Check { grant, program } => cmd_check(&fmt, grant, program),
        Cmd::Introspect => cmd_introspect(&fmt),
        #[cfg(feature = "firecracker")]
        Cmd::BoxSmoke { manifest, dwell } => cmd_box_smoke(&fmt, manifest, dwell),
    };
    std::process::exit(code.code());
}

/// Load a manifest from a file, or fall back to the demo. Errors are
/// emitted as acli envelopes by the caller.
fn load_manifest(path: &Option<PathBuf>) -> anyhow::Result<Manifest> {
    match path {
        Some(p) => {
            let text = std::fs::read_to_string(p)?;
            Ok(Manifest::from_json(&text)?)
        }
        None => Ok(demo::demo_manifest()),
    }
}

fn environment(namespaces_only: bool, offline: bool) -> Environment {
    let mut env = Environment::full();
    if namespaces_only {
        env.max_floor = lex_os_manifest::IsolationFloor::Namespace;
    }
    if offline {
        env.network_available = false;
    }
    env
}

fn cmd_run(
    fmt: &OutputFormat,
    manifest_path: Option<PathBuf>,
    audit_out: Option<PathBuf>,
    namespaces_only: bool,
    offline: bool,
    agent_backend: AgentBackend,
    model: Option<String>,
    ollama_url: Option<String>,
) -> ExitCode {
    let start = Instant::now();

    // For LLM agents use a goal that motivates the three attacks naturally;
    // the scripted demo keeps its own manifest.
    let manifest = match (&manifest_path, &agent_backend) {
        (None, AgentBackend::Demo) => demo::demo_manifest(),
        (None, _) => agent::agent_demo_manifest(),
        (Some(_), _) => match load_manifest(&manifest_path) {
            Ok(m) => m,
            Err(e) => {
                return emit_err(
                    fmt,
                    "run",
                    ExitCode::InvalidArgs,
                    &format!("bad manifest: {e}"),
                )
            }
        },
    };

    let env = environment(namespaces_only, offline);
    let registry = demo::demo_registry();

    #[cfg(feature = "firecracker")]
    let make_supervisor = |m: Manifest| {
        Supervisor::new(m, registry, FirecrackerPerimeter::new(), SystemClock, Limits::default())
    };
    #[cfg(not(feature = "firecracker"))]
    let make_supervisor = |m: Manifest| {
        Supervisor::new(m, registry, SimulatedPerimeter::new(), SystemClock, Limits::default())
    };

    // Commands exposed to the LLM agent (names only, for the system prompt).
    let command_names = vec![
        "fs.list", "fs.read", "fs.write", "report.write",
        "net.fetch", "exec.shell", "fs.delete_all",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect::<Vec<_>>();

    // Dispatch to the chosen agent backend.
    let report = match agent_backend {
        AgentBackend::Demo => {
            let supervisor = make_supervisor(manifest.clone());
            let mut ag = demo::DemoAgent::new();
            match supervisor.run(&env, &mut ag) {
                Ok(r) => r,
                Err(e) => return emit_err(fmt, "run", ExitCode::PreconditionFailed, &e.to_string()),
            }
        }
        AgentBackend::Ollama => {
            let model_name = model.as_deref().unwrap_or("mistral").to_string();
            let mut provider = agent::OllamaProvider::new(model_name);
            if let Some(url) = ollama_url {
                provider = provider.with_url(url);
            }
            let supervisor = make_supervisor(manifest.clone());
            let mut ag = agent::LlmAgent::new(provider, command_names, manifest.clone());
            match supervisor.run(&env, &mut ag) {
                Ok(r) => r,
                Err(e) => return emit_err(fmt, "run", ExitCode::PreconditionFailed, &e.to_string()),
            }
        }
        AgentBackend::Anthropic => {
            let provider = match agent::AnthropicProvider::from_env() {
                Ok(p) => match model {
                    Some(m) => p.with_model(m),
                    None => p,
                },
                Err(e) => return emit_err(fmt, "run", ExitCode::PreconditionFailed, &e.to_string()),
            };
            let supervisor = make_supervisor(manifest.clone());
            let mut ag = agent::LlmAgent::new(provider, command_names, manifest.clone());
            match supervisor.run(&env, &mut ag) {
                Ok(r) => r,
                Err(e) => return emit_err(fmt, "run", ExitCode::PreconditionFailed, &e.to_string()),
            }
        }
        AgentBackend::OpenAi => {
            let provider = match agent::OpenAiProvider::from_env() {
                Ok(p) => match model {
                    Some(m) => p.with_model(m),
                    None => p,
                },
                Err(e) => return emit_err(fmt, "run", ExitCode::PreconditionFailed, &e.to_string()),
            };
            let supervisor = make_supervisor(manifest.clone());
            let mut ag = agent::LlmAgent::new(provider, command_names, manifest.clone());
            match supervisor.run(&env, &mut ag) {
                Ok(r) => r,
                Err(e) => return emit_err(fmt, "run", ExitCode::PreconditionFailed, &e.to_string()),
            }
        }
    };

    if let Some(path) = audit_out {
        if let Ok(j) = report.audit.to_json() {
            let _ = std::fs::write(&path, j);
        }
    }

    let data = json!({
        "manifest_id": manifest.content_id().0,
        "goal": manifest.goal.description,
        "grant": manifest.grant.pretty(),
        "outcome": format!("{:?}", report.outcome),
        "reprovisions": report.reprovisions,
        "commands_used": report.ledger.commands_used(),
        "money_spent_cents": report.ledger.money_used_cents(),
        "api_calls_used": report.ledger.api_calls_used(),
        "audit_entries": report.audit.len(),
        "audit_head": report.audit.head(),
        "audit_verified": report.audit.verify().is_ok(),
    });
    emit(
        &success_envelope("run", data, VERSION, Some(start), None),
        fmt,
    );
    ExitCode::Success
}

/// Standalone Wall-2 proof. Provision a real microVM (which installs the
/// host-side egress wall on the tap), dwell so the guest boots and runs
/// `/sbin/init.demo` — its console (incl. the `8.8.8.8 -> blocked` probe)
/// streams live — then tear the box down. Bypasses the supervisor loop on
/// purpose: this exercises the perimeter alone, long enough to observe it.
#[cfg(feature = "firecracker")]
fn cmd_box_smoke(fmt: &OutputFormat, manifest: Option<PathBuf>, dwell: u64) -> ExitCode {
    use lex_os_perimeter::{Perimeter, SandboxPolicy};

    let manifest = match load_manifest(&manifest) {
        Ok(m) => m,
        Err(e) => {
            return emit_err(
                fmt,
                "box-smoke",
                ExitCode::InvalidArgs,
                &format!("bad manifest: {e}"),
            )
        }
    };
    let policy = SandboxPolicy::from_manifest(&manifest);
    eprintln!(
        "box-smoke: provisioning microVM; egress allowlist = {:?}",
        policy.egress
    );

    let mut perim = FirecrackerPerimeter::new();
    if let Err(e) = perim.provision(policy) {
        return emit_err(
            fmt,
            "box-smoke",
            ExitCode::PreconditionFailed,
            &e.to_string(),
        );
    }
    eprintln!(
        "box-smoke: provisioned — dwelling {dwell}s while the guest boots and runs \
         /sbin/init.demo (watch the console below)"
    );
    std::thread::sleep(std::time::Duration::from_secs(dwell));

    perim.destroy("box-smoke complete");
    eprintln!("box-smoke: box destroyed, host tap + egress rules removed");
    emit(
        &success_envelope(
            "box-smoke",
            json!({ "dwell_secs": dwell }),
            VERSION,
            None,
            None,
        ),
        fmt,
    );
    ExitCode::Success
}

fn cmd_resolve(
    fmt: &OutputFormat,
    manifest: Option<PathBuf>,
    namespaces_only: bool,
    offline: bool,
) -> ExitCode {
    let start = Instant::now();
    let manifest = match load_manifest(&manifest) {
        Ok(m) => m,
        Err(e) => {
            return emit_err(
                fmt,
                "resolve",
                ExitCode::InvalidArgs,
                &format!("bad manifest: {e}"),
            )
        }
    };
    let env = environment(namespaces_only, offline);
    match resolve(&manifest, &env) {
        Ok(plan) => {
            let data = json!({
                "grant": manifest.grant.pretty(),
                "isolation_floor": plan.floor.as_str(),
                "fs_readable": plan.policy.fs_readable,
                "fs_writable": plan.policy.fs_writable,
                "net_egress": format!("{:?}", plan.policy.net_egress),
                "exec_allowed": plan.policy.exec_allowed,
            });
            emit(
                &success_envelope("resolve", data, VERSION, Some(start), None),
                fmt,
            );
            ExitCode::Success
        }
        Err(e) => emit_err(fmt, "resolve", ExitCode::PreconditionFailed, &e.to_string()),
    }
}

fn cmd_manifest(fmt: &OutputFormat, what: ManifestCmd) -> ExitCode {
    let start = Instant::now();
    match what {
        ManifestCmd::Sample => {
            let m = demo::demo_manifest();
            match m.to_json() {
                Ok(j) => {
                    // For sample we print the raw manifest JSON to stdout
                    // (it's meant to be saved to a file), but still wrap a
                    // structured envelope when --output json is requested.
                    match fmt {
                        OutputFormat::Json => {
                            let data: serde_json::Value =
                                serde_json::from_str(&j).unwrap_or(json!({}));
                            emit(
                                &success_envelope(
                                    "manifest.sample",
                                    data,
                                    VERSION,
                                    Some(start),
                                    None,
                                ),
                                fmt,
                            );
                        }
                        _ => println!("{j}"),
                    }
                    ExitCode::Success
                }
                Err(e) => emit_err(
                    fmt,
                    "manifest.sample",
                    ExitCode::GeneralError,
                    &e.to_string(),
                ),
            }
        }
        ManifestCmd::Hash { manifest } => match std::fs::read_to_string(&manifest)
            .map_err(anyhow::Error::from)
            .and_then(|t| Ok(Manifest::from_json(&t)?))
        {
            Ok(m) => {
                let data =
                    json!({ "manifest_id": m.content_id().0, "short": m.content_id().short() });
                emit(
                    &success_envelope("manifest.hash", data, VERSION, Some(start), None),
                    fmt,
                );
                ExitCode::Success
            }
            Err(e) => emit_err(fmt, "manifest.hash", ExitCode::InvalidArgs, &e.to_string()),
        },
        ManifestCmd::Narrow { parent, child } => {
            let load = |p: &PathBuf| -> anyhow::Result<Manifest> {
                Ok(Manifest::from_json(&std::fs::read_to_string(p)?)?)
            };
            let (parent, child) = match (load(&parent), load(&child)) {
                (Ok(p), Ok(c)) => (p, c),
                (Err(e), _) | (_, Err(e)) => {
                    return emit_err(
                        fmt,
                        "manifest.narrow",
                        ExitCode::InvalidArgs,
                        &format!("bad manifest: {e}"),
                    )
                }
            };
            match Manifest::validate_narrowing(&parent, &child) {
                Ok(()) => {
                    let data = json!({
                        "narrows": true,
                        "parent": parent.grant.pretty(),
                        "child": child.grant.pretty(),
                    });
                    emit(
                        &success_envelope("manifest.narrow", data, VERSION, Some(start), None),
                        fmt,
                    );
                    ExitCode::Success
                }
                // A widening attempt is the narrowing-invariant wall:
                // refuse, with the structured reason.
                Err(e) => emit_err(
                    fmt,
                    "manifest.narrow",
                    ExitCode::PreconditionFailed,
                    &e.to_string(),
                ),
            }
        }
    }
}

fn cmd_audit(fmt: &OutputFormat, what: AuditCmd) -> ExitCode {
    // Tail runs forever in its own helper; handle it before the
    // common read-once path so we don't try to read the file twice.
    if let AuditCmd::Tail { log } = what {
        cmd_audit_tail(&log)
    } else {
        cmd_audit_once(fmt, what)
    }
}

fn cmd_audit_once(fmt: &OutputFormat, what: AuditCmd) -> ExitCode {
    let start = Instant::now();
    let (command, log_path) = match &what {
        AuditCmd::Verify { log } => ("audit.verify", log.clone()),
        AuditCmd::Render { log } => ("audit.render", log.clone()),
        AuditCmd::Tail { .. } => unreachable!("tail is handled above"),
    };
    let text = match std::fs::read_to_string(&log_path) {
        Ok(t) => t,
        Err(e) => return emit_err(fmt, command, ExitCode::NotFound, &e.to_string()),
    };
    let parsed = match AuditLog::from_json(&text) {
        Ok(l) => l,
        Err(e) => return emit_err(fmt, command, ExitCode::InvalidArgs, &e.to_string()),
    };
    match what {
        AuditCmd::Verify { .. } => match parsed.verify() {
            Ok(()) => {
                let data =
                    json!({ "verified": true, "entries": parsed.len(), "head": parsed.head() });
                emit(
                    &success_envelope("audit.verify", data, VERSION, Some(start), None),
                    fmt,
                );
                ExitCode::Success
            }
            // A broken chain is a precondition failure, not a crash.
            Err(e) => emit_err(
                fmt,
                "audit.verify",
                ExitCode::PreconditionFailed,
                &e.to_string(),
            ),
        },
        AuditCmd::Render { .. } => match parsed.to_ndjson() {
            // NDJSON is meant to be piped to a live viewer, so print it
            // raw to stdout regardless of --output.
            Ok(nd) => {
                print!("{nd}");
                ExitCode::Success
            }
            Err(e) => emit_err(fmt, "audit.render", ExitCode::GeneralError, &e.to_string()),
        },
        AuditCmd::Tail { .. } => unreachable!("tail is handled above"),
    }
}

/// Follow `log`, printing existing entries as NDJSON and then polling every
/// 250 ms for new ones. Never returns (user must Ctrl-C).
fn cmd_audit_tail(log: &PathBuf) -> ! {
    let mut last_len: usize = 0;

    loop {
        if let Ok(text) = std::fs::read_to_string(log) {
            if let Ok(audit) = AuditLog::from_json(&text) {
                let entries = audit.entries();
                for entry in entries.iter().skip(last_len) {
                    if let Ok(line) = serde_json::to_string(entry) {
                        println!("{line}");
                    }
                }
                last_len = entries.len();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn cmd_check(fmt: &OutputFormat, grant: PathBuf, program: PathBuf) -> ExitCode {
    let start = Instant::now();
    let manifest = match std::fs::read_to_string(&grant)
        .map_err(anyhow::Error::from)
        .and_then(|t| Ok(Manifest::from_json(&t)?))
    {
        Ok(m) => m,
        Err(e) => {
            return emit_err(
                fmt,
                "check",
                ExitCode::InvalidArgs,
                &format!("bad manifest: {e}"),
            )
        }
    };
    let src = match std::fs::read_to_string(&program) {
        Ok(s) => s,
        Err(e) => return emit_err(fmt, "check", ExitCode::NotFound, &e.to_string()),
    };
    match lex_os_check::check_source_against_manifest(&src, &manifest) {
        Ok(report) => {
            let data = json!({
                "ok": true,
                "grant": manifest.grant.pretty(),
                "effects": report.effects,
                "net_hosts": report.net_hosts,
            });
            emit(
                &success_envelope("check", data, VERSION, Some(start), None),
                fmt,
            );
            ExitCode::Success
        }
        // The wall: a program exceeding the grant is refused before it
        // runs. Grant violations are a precondition failure; parse/type
        // errors are invalid input.
        Err(e @ lex_os_check::CheckError::GrantViolation(_)) => {
            emit_err(fmt, "check", ExitCode::PreconditionFailed, &e.to_string())
        }
        Err(e) => emit_err(fmt, "check", ExitCode::InvalidArgs, &e.to_string()),
    }
}

fn cmd_introspect(fmt: &OutputFormat) -> ExitCode {
    let mut tree = CommandTree::new("lex-os", VERSION);
    tree.add_command(
        CommandInfo::new(
            "run",
            "Dispatch an agent against a manifest and run the mediation loop.",
        )
        .idempotent(false)
        .add_option(
            "manifest",
            "path",
            "Manifest JSON file (omit for the demo).",
            None,
        )
        .add_option(
            "audit-out",
            "path",
            "Write the tamper-proof audit log here.",
            None,
        )
        .with_examples(vec![
            ("Run the built-in demo", "lex-os run"),
            (
                "Run a manifest and save the audit log",
                "lex-os run --manifest m.json --audit-out audit.json",
            ),
        ])
        .with_see_also(vec!["resolve", "audit"]),
    );
    tree.add_command(
        CommandInfo::new(
            "resolve",
            "Negotiate a manifest against the host; refuse if it can't be satisfied.",
        )
        .idempotent(true)
        .add_option(
            "manifest",
            "path",
            "Manifest JSON file (omit for the demo).",
            None,
        )
        .with_examples(vec![("Resolve the demo manifest", "lex-os resolve")]),
    );
    tree.add_command(
        CommandInfo::new("manifest", "Manifest utilities (sample, hash).")
            .conditionally_idempotent()
            .with_examples(vec![("Print a sample manifest", "lex-os manifest sample")]),
    );
    tree.add_command(
        CommandInfo::new(
            "audit",
            "Audit-log utilities: verify the hash chain, render as NDJSON, or follow in real time with `tail`.",
        )
        .idempotent(true)
        .with_examples(vec![
            ("Verify a log", "lex-os audit verify --log audit.json"),
            ("Render as NDJSON", "lex-os audit render --log audit.json"),
            (
                "Follow a log live (Ctrl-C to stop)",
                "lex-os audit tail --log audit.json",
            ),
        ]),
    );
    tree.add_command(
        CommandInfo::new(
            "check",
            "Type-check an agent Lex program against a manifest grant; refuse it if its effects exceed the grant.",
        )
        .idempotent(true)
        .add_option("grant", "path", "Manifest JSON to check against.", None)
        .with_examples(vec![(
            "Reject a net program under network:none",
            "lex-os check --grant manifest.json agent.lex",
        )]),
    );

    let data = serde_json::to_value(&tree).unwrap_or(json!({}));
    emit(
        &success_envelope("introspect", data, VERSION, None, None),
        fmt,
    );
    ExitCode::Success
}

/// Emit an acli error envelope and return the exit code.
fn emit_err(fmt: &OutputFormat, command: &str, code: ExitCode, message: &str) -> ExitCode {
    emit(
        &error_envelope(command, code, message, None, None, None, VERSION, None),
        fmt,
    );
    code
}
