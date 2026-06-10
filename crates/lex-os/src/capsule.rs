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

use lex_os_capsule::{
    generate_signing_key, signing_key_from_seed, ArtifactRef, CapabilityContract, Capsule,
    CapsuleError, InstallOptions, Keyring, SignedContract,
};
use lex_os_manifest::Manifest;
use lex_os_perimeter::{Perimeter, SandboxPolicy, SimulatedPerimeter};
use lex_os_resolver::resolve;

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
        /// must be in it. Omit to accept any valid signature (trust-on-first-use,
        /// warned).
        #[arg(long)]
        trusted_keys: Option<PathBuf>,
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
            namespaces_only,
            offline,
        } => install(
            fmt,
            consumer,
            contract,
            artifact,
            trusted_keys,
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
                 accepted (trust-on-first-use). Pass --trusted-keys <keyring.json> to pin publishers."
            );
            None
        }
    };

    let opts = InstallOptions {
        artifact_bytes: artifact_bytes.as_deref(),
        keyring: keyring.as_ref(),
    };

    // The gate: authenticity → trusted signer → artifact bytes → narrow.
    let installed = match Capsule::install_with(&consumer, &signed, &opts) {
        Ok(i) => i,
        // Distinguish authenticity / authorization / integrity / capability
        // failures so the exit code and message are honest about *why*.
        Err(e @ (CapsuleError::SignatureInvalid | CapsuleError::MalformedKey)) => {
            return emit_err(
                fmt,
                "capsule.install",
                ExitCode::PreconditionFailed,
                &format!("authenticity: {e}"),
            )
        }
        Err(
            e @ (CapsuleError::UntrustedSigner { .. }
            | CapsuleError::ArtifactHashMismatch { .. }
            | CapsuleError::Refused(_)),
        ) => {
            return emit_err(
                fmt,
                "capsule.install",
                ExitCode::PreconditionFailed,
                &e.to_string(),
            )
        }
        Err(e) => {
            return emit_err(
                fmt,
                "capsule.install",
                ExitCode::InvalidArgs,
                &e.to_string(),
            )
        }
    };

    // Resolve the effective manifest against the host and actually provision
    // the (simulated) box, so the spike runs end-to-end rather than stopping
    // at the type level. This is NOT a security boundary — say so.
    let env = environment(namespaces_only, offline);
    let plan = match resolve(&installed.manifest, &env) {
        Ok(p) => p,
        Err(e) => {
            return emit_err(
                fmt,
                "capsule.install",
                ExitCode::PreconditionFailed,
                &e.to_string(),
            )
        }
    };
    let policy = SandboxPolicy::from_manifest(&installed.manifest);
    let mut perimeter = SimulatedPerimeter::new();
    if let Err(e) = perimeter.provision(policy) {
        return emit_err(
            fmt,
            "capsule.install",
            ExitCode::PreconditionFailed,
            &e.to_string(),
        );
    }
    eprintln!(
        "⚠  SIMULATED PERIMETER — `capsule install` provisions an in-process box to exercise \
         the spike end-to-end; it is NOT a security boundary."
    );

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
    });
    emit(
        &success_envelope("capsule.install", data, VERSION, Some(start), None),
        fmt,
    );
    ExitCode::Success
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
