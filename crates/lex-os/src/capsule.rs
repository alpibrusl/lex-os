//! The `capsule` subcommand: capability-addressed distribution (lex-os#34).
//!
//! This is the CLI face of the `lex-os-capsule` crate. It demonstrates the
//! full spike end-to-end:
//!
//! ```text
//! capsule keygen                       # an Ed25519 publisher key
//! capsule sign   --grant requires.json # bind an artifact to its required grant, signed
//! capsule verify --contract c.json     # check the signature
//! capsule install --consumer m.json --contract c.json
//!                                      # refuse, or provision the effective box
//! ```
//!
//! `install` is where the design rule lives: it computes the effective grant
//! `meet(consumer, requires)`, refuses (rather than downgrades) if the
//! artifact wants more than the consumer grants, then resolves the effective
//! manifest and provisions a [`SimulatedPerimeter`] so the box is exercised
//! end-to-end. The simulated perimeter is *not* a security boundary — every
//! `install` says so in its output, exactly like `run`.

use std::path::PathBuf;
use std::time::Instant;

use acli::{emit, success_envelope, ExitCode, OutputFormat};
use clap::Subcommand;
use serde_json::json;

use lex_os_audit::{AuditLog, Event};
use lex_os_capsule::{
    generate_signing_key, signing_key_from_seed, ArtifactRef, CapabilityContract, Capsule,
    CapsuleError, InstallOptions, InstalledCapsule, Keyring, SignedContract,
};
use lex_os_manifest::Manifest;
use lex_os_perimeter::{Perimeter, SandboxPolicy, SimulatedPerimeter};
use lex_os_resolver::{resolve, Environment};
use lex_os_supervisor::SystemClock;

use crate::demo::demo_registry;
use crate::{emit_err, environment, VERSION};

#[derive(Subcommand)]
pub enum CapsuleCmd {
    /// Generate an Ed25519 publisher keypair, printing the secret and public
    /// keys as hex. With `--seed` the key is derived deterministically (for
    /// reproducible demos); otherwise it comes from the OS CSPRNG.
    Keygen {
        /// 32-byte hex seed for a deterministic key (64 hex chars).
        #[arg(long)]
        seed: Option<String>,
    },
    /// Sign a capability contract: bind an artifact to the grant + egress it
    /// requires (taken from a manifest's grant), with the publisher's key.
    Sign {
        /// Artifact identity as `name@version`.
        #[arg(long)]
        artifact: String,
        /// Hex SHA-256 of the published package archive (its content address).
        /// Provide this or `--artifact-file`, not both.
        #[arg(
            long,
            conflicts_with = "artifact_file",
            required_unless_present = "artifact_file"
        )]
        content_hash: Option<String>,
        /// Path to the published archive; its SHA-256 becomes the content hash.
        #[arg(long)]
        artifact_file: Option<PathBuf>,
        /// Manifest JSON whose grant + egress are the artifact's requirement.
        #[arg(long)]
        requires: PathBuf,
        /// Signing key as 32-byte hex (the secret printed by `keygen`).
        #[arg(long)]
        key: String,
        /// Write the signed contract JSON here (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a signed contract's Ed25519 signature.
    Verify {
        #[arg(long)]
        contract: PathBuf,
    },
    /// Install a signed contract against a consumer manifest: refuse if the
    /// artifact wants more than the consumer grants, otherwise resolve and
    /// provision the effective box under the simulated perimeter.
    Install {
        /// The consumer's manifest — the ceiling the artifact is bound by.
        #[arg(long)]
        consumer: PathBuf,
        /// The signed capability contract travelling with the artifact.
        #[arg(long)]
        contract: PathBuf,
        /// The artifact archive; its SHA-256 must match the contract's
        /// content hash, or install is refused. Omit to skip the byte check
        /// (a loud warning is printed).
        #[arg(long)]
        artifact: Option<PathBuf>,
        /// A trusted-keys JSON keyring (`{"trusted":["<hex>",…]}`); the signer
        /// must be in it. Omit for any-signer mode: any valid signature from any
        /// key is accepted (warned; this is not trust-on-first-use).
        #[arg(long)]
        trusted_keys: Option<PathBuf>,
        /// Write a tamper-evident audit log of the install decision (request →
        /// installed/refused, plus the session under `--run`) here. Verify it
        /// with `lex-os audit verify`.
        #[arg(long)]
        audit_out: Option<PathBuf>,
        /// After installing, run the package's entrypoint under the effective
        /// manifest: extract it from the artifact, type-check it against the
        /// effective grant (over-reach refused before it runs), then drive the
        /// supervisor loop from its declared effects. One audit chain spans the
        /// install decision and the session it authorized. Requires `--artifact`.
        #[arg(long, requires = "artifact")]
        run: bool,
        /// Path *within the package archive* of the entrypoint Lex program to
        /// run under `--run`. Defaults to `src/main.lex`.
        #[arg(long)]
        entrypoint: Option<String>,
        /// Pretend the host can only do namespace isolation.
        #[arg(long)]
        namespaces_only: bool,
        /// Pretend the host has no outbound network.
        #[arg(long)]
        offline: bool,
    },
}

pub fn cmd_capsule(fmt: &OutputFormat, what: CapsuleCmd) -> ExitCode {
    match what {
        CapsuleCmd::Keygen { seed } => keygen(fmt, seed),
        CapsuleCmd::Sign {
            artifact,
            content_hash,
            artifact_file,
            requires,
            key,
            out,
        } => sign(
            fmt,
            artifact,
            content_hash,
            artifact_file,
            requires,
            key,
            out,
        ),
        CapsuleCmd::Verify { contract } => verify(fmt, contract),
        CapsuleCmd::Install {
            consumer,
            contract,
            artifact,
            trusted_keys,
            audit_out,
            run,
            entrypoint,
            namespaces_only,
            offline,
        } => install(
            fmt,
            consumer,
            contract,
            artifact,
            trusted_keys,
            audit_out,
            run,
            entrypoint,
            namespaces_only,
            offline,
        ),
    }
}

fn keygen(fmt: &OutputFormat, seed: Option<String>) -> ExitCode {
    let start = Instant::now();
    let key = match seed {
        Some(s) => match decode_seed(&s) {
            Ok(bytes) => signing_key_from_seed(&bytes),
            Err(e) => return emit_err(fmt, "capsule.keygen", ExitCode::InvalidArgs, &e),
        },
        None => generate_signing_key(),
    };
    let data = json!({
        "secret_key": hex::encode(key.to_bytes()),
        "public_key": hex::encode(key.verifying_key().to_bytes()),
        "note": "the secret key is the --key input to `capsule sign`; keep it out of repos",
    });
    emit(
        &success_envelope("capsule.keygen", data, VERSION, Some(start), None),
        fmt,
    );
    ExitCode::Success
}

#[allow(clippy::too_many_arguments)]
fn sign(
    fmt: &OutputFormat,
    artifact: String,
    content_hash: Option<String>,
    artifact_file: Option<PathBuf>,
    requires: PathBuf,
    key: String,
    out: Option<PathBuf>,
) -> ExitCode {
    let start = Instant::now();
    let (name, version) = match artifact.split_once('@') {
        Some((n, v)) if !n.is_empty() && !v.is_empty() => (n.to_string(), v.to_string()),
        _ => {
            return emit_err(
                fmt,
                "capsule.sign",
                ExitCode::InvalidArgs,
                "artifact must be `name@version`",
            )
        }
    };
    // Content hash: take the explicit one, or compute it from the archive so
    // the contract is bound to bytes that actually exist. clap guarantees
    // exactly one of the two is present.
    let content_hash = match (content_hash, artifact_file) {
        (Some(h), _) => h,
        (None, Some(path)) => match std::fs::read(&path) {
            Ok(bytes) => CapabilityContract::hash_artifact_bytes(&bytes),
            Err(e) => {
                return emit_err(
                    fmt,
                    "capsule.sign",
                    ExitCode::NotFound,
                    &format!("cannot read artifact file {}: {e}", path.display()),
                )
            }
        },
        (None, None) => unreachable!("clap requires one of --content-hash / --artifact-file"),
    };
    let manifest = match load_manifest(&requires) {
        Ok(m) => m,
        Err(e) => return emit_err(fmt, "capsule.sign", ExitCode::InvalidArgs, &e),
    };
    let seed = match decode_seed(&key) {
        Ok(b) => b,
        Err(e) => return emit_err(fmt, "capsule.sign", ExitCode::InvalidArgs, &e),
    };
    let signing_key = signing_key_from_seed(&seed);

    // The artifact's requirement is exactly the grant + egress of the supplied
    // manifest — reusing the manifest format keeps one spelling of a grant.
    let contract = CapabilityContract::new(
        ArtifactRef::new(name, version, content_hash),
        manifest.grant,
    )
    .with_egress(manifest.egress.clone());
    let signed = contract.sign(&signing_key);

    let pretty = match signed.to_json() {
        Ok(j) => j,
        Err(e) => return emit_err(fmt, "capsule.sign", ExitCode::GeneralError, &e.to_string()),
    };
    if let Some(path) = &out {
        if let Err(e) = std::fs::write(path, &pretty) {
            return emit_err(fmt, "capsule.sign", ExitCode::GeneralError, &e.to_string());
        }
    }
    let data = json!({
        "contract_id": signed.contract.content_id().0,
        "artifact": format!("{}@{}", signed.contract.artifact.name, signed.contract.artifact.version),
        "requires": signed.contract.requires.pretty(),
        "egress": signed.contract.egress,
        "signer": signed.signer,
        "written_to": out.as_ref().map(|p| p.display().to_string()),
    });
    // Print the contract to stdout when not writing a file, so it can be piped.
    if out.is_none() {
        match fmt {
            OutputFormat::Json => emit(
                &success_envelope("capsule.sign", data, VERSION, Some(start), None),
                fmt,
            ),
            _ => println!("{pretty}"),
        }
    } else {
        emit(
            &success_envelope("capsule.sign", data, VERSION, Some(start), None),
            fmt,
        );
    }
    ExitCode::Success
}

fn verify(fmt: &OutputFormat, contract: PathBuf) -> ExitCode {
    let start = Instant::now();
    let signed = match load_signed(&contract) {
        Ok(s) => s,
        Err(e) => return emit_err(fmt, "capsule.verify", ExitCode::InvalidArgs, &e),
    };
    match signed.verify() {
        Ok(key) => {
            let data = json!({
                "verified": true,
                "signer": hex::encode(key.to_bytes()),
                "contract_id": signed.contract.content_id().0,
                "artifact": format!("{}@{}", signed.contract.artifact.name, signed.contract.artifact.version),
            });
            emit(
                &success_envelope("capsule.verify", data, VERSION, Some(start), None),
                fmt,
            );
            ExitCode::Success
        }
        // A bad signature is a precondition failure, not malformed input.
        Err(e) => emit_err(
            fmt,
            "capsule.verify",
            ExitCode::PreconditionFailed,
            &e.to_string(),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn install(
    fmt: &OutputFormat,
    consumer: PathBuf,
    contract: PathBuf,
    artifact: Option<PathBuf>,
    trusted_keys: Option<PathBuf>,
    audit_out: Option<PathBuf>,
    run: bool,
    entrypoint: Option<String>,
    namespaces_only: bool,
    offline: bool,
) -> ExitCode {
    let start = Instant::now();
    let consumer = match load_manifest(&consumer) {
        Ok(m) => m,
        Err(e) => return emit_err(fmt, "capsule.install", ExitCode::InvalidArgs, &e),
    };
    let signed = match load_signed(&contract) {
        Ok(s) => s,
        Err(e) => return emit_err(fmt, "capsule.install", ExitCode::InvalidArgs, &e),
    };
    let label = format!(
        "{}@{}",
        signed.contract.artifact.name, signed.contract.artifact.version
    );

    // Integrity gate input: the artifact bytes, if supplied. Skipping it is
    // allowed but loudly warned — the contract's content_hash is then a
    // promise about bytes we never checked.
    let artifact_bytes = match &artifact {
        Some(path) => match std::fs::read(path) {
            Ok(b) => Some(b),
            Err(e) => {
                return emit_err(
                    fmt,
                    "capsule.install",
                    ExitCode::NotFound,
                    &format!("cannot read artifact file {}: {e}", path.display()),
                )
            }
        },
        None => {
            eprintln!(
                "⚠  artifact bytes NOT verified — pass --artifact <archive> to check the \
                 published bytes hash to the contract's content_hash."
            );
            None
        }
    };

    // Authorization gate input: the trusted-signer keyring, if supplied.
    let keyring = match &trusted_keys {
        Some(path) => match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|t| Keyring::from_json(&t).map_err(|e| e.to_string()))
        {
            Ok(k) => Some(k),
            Err(e) => {
                return emit_err(
                    fmt,
                    "capsule.install",
                    ExitCode::InvalidArgs,
                    &format!("bad keyring: {e}"),
                )
            }
        },
        None => {
            eprintln!(
                "⚠  signer NOT checked against a trusted keyring — any valid signature is \
                 accepted (any-signer mode — not trust-on-first-use). Pass --trusted-keys <keyring.json> to pin publishers."
            );
            None
        }
    };

    let opts = InstallOptions {
        artifact_bytes: artifact_bytes.as_deref(),
        keyring: keyring.as_ref(),
    };

    // Tamper-evident record of the decision. Log the request *before* any gate
    // decides — the same "log, then decide" order as the mediation loop. The
    // signer here is the claimed (not yet verified) publisher key.
    let mut audit = AuditLog::new();
    audit.append(Event::CapsuleRequested {
        artifact: label.clone(),
        signer: signed.signer.clone(),
        content_hash: signed.contract.artifact.content_hash.clone(),
    });

    // The gate: authenticity → trusted signer → artifact bytes → narrow.
    let installed = match Capsule::install(&consumer, &signed, &opts) {
        Ok(i) => i,
        // Distinguish authenticity / authorization / integrity / capability
        // failures so the exit code and message are honest about *why*. Every
        // refusal is recorded before we return.
        Err(e) => {
            let (code, msg) = match &e {
                CapsuleError::SignatureInvalid | CapsuleError::MalformedKey => {
                    (ExitCode::PreconditionFailed, format!("authenticity: {e}"))
                }
                CapsuleError::UntrustedSigner { .. }
                | CapsuleError::ArtifactHashMismatch { .. }
                | CapsuleError::Refused(_) => (ExitCode::PreconditionFailed, e.to_string()),
                _ => (ExitCode::InvalidArgs, e.to_string()),
            };
            return refuse_install(audit, &audit_out, fmt, &label, code, msg);
        }
    };

    // Resolve the effective manifest against the host and actually provision
    // the (simulated) box, so the spike runs end-to-end rather than stopping
    // at the type level. This is NOT a security boundary — say so. A host that
    // can't honor the grant is a refusal too, and recorded as one.
    let env = environment(namespaces_only, offline);
    let plan = match resolve(&installed.manifest, &env) {
        Ok(p) => p,
        Err(e) => {
            return refuse_install(
                audit,
                &audit_out,
                fmt,
                &label,
                ExitCode::PreconditionFailed,
                e.to_string(),
            )
        }
    };
    eprintln!(
        "⚠  SIMULATED PERIMETER — `capsule install` provisions an in-process box to exercise \
         the spike end-to-end; it is NOT a security boundary."
    );

    // --run: run the package's *real entrypoint* under the effective manifest.
    // Extract it from the verified archive, type-check it against the effective
    // grant (over-reach refused before the box runs), then drive the supervisor
    // loop from its declared effects — one audit chain from the install decision
    // through the session it authorized. (`--run` requires `--artifact`.) The
    // entrypoint check is a gate on *running*, so it precedes `CapsuleInstalled`.
    if run {
        let bytes = artifact_bytes
            .as_deref()
            .expect("clap guarantees --artifact is present with --run");
        let ep = entrypoint.as_deref().unwrap_or("src/main.lex");
        let source = match extract_text_from_targz(bytes, ep) {
            Ok(s) => s,
            Err(e) => {
                return refuse_install(
                    audit,
                    &audit_out,
                    fmt,
                    &label,
                    ExitCode::PreconditionFailed,
                    e,
                )
            }
        };
        // The type-check wall, now on the distributed package's own code: its
        // declared effects must fit the box's least authority, or it is refused
        // before anything runs.
        if let Err(e) = lex_os_check::check_source_against_manifest(&source, &installed.manifest) {
            return refuse_install(
                audit,
                &audit_out,
                fmt,
                &label,
                ExitCode::PreconditionFailed,
                format!("entrypoint `{ep}` exceeds the effective grant: {e}"),
            );
        }
        // Past every gate: the install is accepted; this entry seeds the chain
        // the session continues.
        audit.append(Event::CapsuleInstalled {
            artifact: label.clone(),
            signer: installed.signer.clone(),
            content_hash: installed.artifact.content_hash.clone(),
            effective_grant: installed.effective_grant.pretty(),
        });
        // Real in-box execution: interpret the entrypoint and mediate every
        // effect it performs through the supervisor gate (not a stand-in built
        // from the declared effects).
        return run_in_box(
            fmt,
            start,
            &installed,
            &consumer,
            &env,
            audit,
            &audit_out,
            ep,
            &source,
        );
    }

    // Default: provision the box and stop (the install gate, not a run).
    let policy = SandboxPolicy::from_manifest(&installed.manifest);
    let mut perimeter = SimulatedPerimeter::new();
    if let Err(e) = perimeter.provision(policy) {
        return refuse_install(
            audit,
            &audit_out,
            fmt,
            &label,
            ExitCode::PreconditionFailed,
            e.to_string(),
        );
    }
    // Provisioned: the install is accepted. Record it, then persist the log.
    audit.append(Event::CapsuleInstalled {
        artifact: label.clone(),
        signer: installed.signer.clone(),
        content_hash: installed.artifact.content_hash.clone(),
        effective_grant: installed.effective_grant.pretty(),
    });
    write_audit(&audit, &audit_out);

    let data = json!({
        "installed": true,
        "artifact": format!("{}@{}", installed.artifact.name, installed.artifact.version),
        "content_hash": installed.artifact.content_hash,
        "signer": installed.signer,
        "consumer_grant": consumer.grant.pretty(),
        "effective_grant": installed.effective_grant.pretty(),
        "effective_egress": installed.manifest.egress,
        "isolation_floor": plan.floor.as_str(),
        "box_alive": perimeter.is_alive(),
        "perimeter": perimeter.backend_name(),
        "security_boundary": false,
        // Which provenance gates actually ran (vs. were skipped with a warning).
        "artifact_bytes_verified": artifact.is_some(),
        "signer_trust_checked": trusted_keys.is_some(),
        // The tamper-evident record of this decision.
        "audit_entries": audit.len(),
        "audit_head": audit.head(),
        "audit_verified": audit.verify().is_ok(),
        "audit_out": audit_out.as_ref().map(|p| p.display().to_string()),
    });
    emit(
        &success_envelope("capsule.install", data, VERSION, Some(start), None),
        fmt,
    );
    ExitCode::Success
}

/// Record a refused install in the audit log, persist it if `--audit-out` was
/// given, and emit the error envelope. Takes the log by value because a
/// refusal always returns.
fn refuse_install(
    mut audit: AuditLog,
    out: &Option<PathBuf>,
    fmt: &OutputFormat,
    artifact: &str,
    code: ExitCode,
    msg: String,
) -> ExitCode {
    audit.append(Event::CapsuleRefused {
        artifact: artifact.to_string(),
        reason: msg.clone(),
    });
    write_audit(&audit, out);
    emit_err(fmt, "capsule.install", code, &msg)
}

/// Persist the audit log to `out` if a path was given. Best-effort: a write
/// failure must not change the install's exit code.
fn write_audit(audit: &AuditLog, out: &Option<PathBuf>) {
    if let Some(path) = out {
        if let Ok(json) = audit.to_json() {
            let _ = std::fs::write(path, json);
        }
    }
}

/// Run the package's entrypoint **in-box**: interpret it with the lex-bytecode
/// VM and route every effect it performs through the supervisor's mediation
/// gate, continuing the install audit log. Unlike the declared-effect stand-in
/// it replaces, this executes the real control flow, so the session reflects
/// exactly what the code *does* — each consequential effect gated at the edge,
/// a denial surfaced to the program as an error, and the whole thing chained
/// onto the install decision as one tamper-evident record.
#[allow(clippy::too_many_arguments)]
fn run_in_box(
    fmt: &OutputFormat,
    start: Instant,
    installed: &InstalledCapsule,
    consumer: &Manifest,
    env: &Environment,
    audit: AuditLog,
    audit_out: &Option<PathBuf>,
    entrypoint: &str,
    source: &str,
) -> ExitCode {
    use std::cell::RefCell;
    use std::rc::Rc;
    use lex_os_supervisor::{BudgetLedger, Clock};

    // Resolve + provision the (simulated) box from the effective manifest, the
    // same shape `run_under_supervisor` did, so the perimeter capability gate
    // is live before the first effect.
    if let Err(e) = resolve(&installed.manifest, env) {
        return emit_err(fmt, "capsule.install", ExitCode::PreconditionFailed, &e.to_string());
    }
    let policy = SandboxPolicy::from_manifest(&installed.manifest);
    let mut perimeter = SimulatedPerimeter::new();
    if let Err(e) = perimeter.provision(policy) {
        return emit_err(fmt, "capsule.install", ExitCode::PreconditionFailed, &e.to_string());
    }
    let mut audit = audit;
    audit.append(Event::Provisioned {
        manifest_id: installed.manifest.content_id().0,
        backend: perimeter.backend_name().to_string(),
        reprovision: false,
    });

    // Compile the entrypoint (already type-checked against the grant above).
    let program = match lex_syntax::parse_source(source) {
        Ok(p) => p,
        Err(e) => {
            return emit_err(
                fmt,
                "capsule.install",
                ExitCode::PreconditionFailed,
                &format!("entrypoint parse error: {e:?}"),
            )
        }
    };
    let stages = lex_ast::canonicalize_program(&program);
    let bytecode = std::sync::Arc::new(lex_bytecode::compile_program(&stages));

    // Mediated execution: the handler routes every effect through the same gate
    // the supervisor loop uses, sharing the seeded audit chain + budget ledger.
    let clock = SystemClock;
    let ledger = BudgetLedger::new(installed.manifest.budget, clock.now_secs());
    let state = Rc::new(RefCell::new(crate::inbox::MediationState {
        audit,
        ledger,
        performed: Vec::new(),
    }));
    let handler =
        crate::inbox::MediatingHandler::new(demo_registry(), perimeter, Rc::clone(&state));
    let mut vm = lex_bytecode::vm::Vm::with_handler(&bytecode, Box::new(handler));
    let run_result = vm.call("main", Vec::new());
    drop(vm); // release the handler's Rc clone so we hold the only reference

    let mut st = state.borrow_mut();
    let (run_ok, run_detail) = match &run_result {
        Ok(_) => (true, "entrypoint returned".to_string()),
        // A denied effect (or any runtime error) halts the box — the program
        // saw the refusal, exactly as a sealed syscall would fail.
        Err(e) => (false, e.to_string()),
    };
    st.audit.append(Event::SessionEnded {
        outcome: if run_ok { "goal_met".into() } else { "halted".into() },
    });
    write_audit(&st.audit, audit_out);

    let data = json!({
        "installed": true,
        "ran": true,
        "execution": "in-box (lex-bytecode interpreter)",
        "artifact": format!("{}@{}", installed.artifact.name, installed.artifact.version),
        "signer": installed.signer,
        "consumer_grant": consumer.grant.pretty(),
        "effective_grant": installed.effective_grant.pretty(),
        "effective_egress": installed.manifest.egress,
        "perimeter": "simulated",
        "security_boundary": false,
        "entrypoint": entrypoint,
        // The effects the entrypoint *actually performed*, in execution order.
        "effects_performed": st.performed,
        "run_ok": run_ok,
        "run_detail": run_detail,
        "commands_used": st.ledger.commands_used(),
        // One continuous, tamper-evident chain: install decision → session.
        "audit_entries": st.audit.len(),
        "audit_head": st.audit.head(),
        "audit_verified": st.audit.verify().is_ok(),
        "audit_out": audit_out.as_ref().map(|p| p.display().to_string()),
    });
    emit(
        &success_envelope("capsule.install", data, VERSION, Some(start), None),
        fmt,
    );
    ExitCode::Success
}

/// Extract a UTF-8 text file named `name` from a gzipped tar archive — the
/// `lex pkg` format (`gzip(tar(lex.toml + src/**))`). Errors are human-readable
/// refusal reasons.
fn extract_text_from_targz(bytes: &[u8], name: &str) -> Result<String, String> {
    use std::io::Read;
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut ar = tar::Archive::new(gz);
    let entries = ar
        .entries()
        .map_err(|e| format!("could not read package archive (expected a gzipped tar): {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("corrupt entry in package archive: {e}"))?;
        let path_ok = entry
            .path()
            .map(|p| p.to_string_lossy() == name)
            .unwrap_or(false);
        if path_ok {
            let mut s = String::new();
            entry
                .read_to_string(&mut s)
                .map_err(|e| format!("entrypoint `{name}` is not valid UTF-8: {e}"))?;
            return Ok(s);
        }
    }
    Err(format!("package has no entrypoint at `{name}`"))
}

fn decode_seed(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|_| "key/seed must be hex".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "key/seed must be 32 bytes (64 hex chars)".to_string())
}

fn load_manifest(path: &PathBuf) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    Manifest::from_json(&text).map_err(|e| format!("bad manifest: {e}"))
}

fn load_signed(path: &PathBuf) -> Result<SignedContract, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    SignedContract::from_json(&text).map_err(|e| format!("bad contract: {e}"))
}
