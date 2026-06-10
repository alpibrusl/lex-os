//! `capsule install --audit-out` writes a tamper-evident record of the
//! install decision (follow-up to #34, the "record installs" item of #36).
//! These run the real binary, like `cli_contract.rs`, so the audit wiring in
//! the CLI is exercised end-to-end and stays verifiable with the existing
//! `audit verify` tooling.

use std::path::PathBuf;
use std::process::Command;

use lex_os_audit::AuditLog;

const BIN: &str = env!("CARGO_BIN_EXE_lex-os");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Run the binary; return (stdout, exit code). stderr (warnings) is ignored.
fn run(args: &[&str]) -> (String, i32) {
    let out = Command::new(BIN)
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("spawn lex-os");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// A scratch directory unique to this test process, cleaned up on drop.
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("lexos-capsule-audit-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_string()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Deterministic secret key from `keygen --seed`.
fn keygen(seed: &str) -> String {
    let (out, code) = run(&["--output", "json", "capsule", "keygen", "--seed", seed]);
    assert_eq!(code, 0, "keygen failed: {out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    v["data"]["secret_key"].as_str().unwrap().to_string()
}

fn example(name: &str) -> String {
    repo_root()
        .join("examples")
        .join(name)
        .to_str()
        .unwrap()
        .to_string()
}

/// Build a minimal `lex pkg` archive (gzip tar: `lex.toml` + `src/main.lex`)
/// at `path`, with `main_lex` as the entrypoint program.
fn make_package(path: &str, main_lex: &str) {
    fn append(ar: &mut tar::Builder<flate2::write::GzEncoder<Vec<u8>>>, name: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        ar.append_data(&mut h, name, data).unwrap();
    }
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut ar = tar::Builder::new(gz);
    append(
        &mut ar,
        "lex.toml",
        b"[package]\nname = \"pdf-extract\"\nversion = \"2.0.0\"\n",
    );
    append(&mut ar, "src/main.lex", main_lex.as_bytes());
    let bytes = ar.into_inner().unwrap().finish().unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn accepted_install_writes_a_verifiable_log() {
    let s = Scratch::new("accept");
    let secret = keygen(&"ac".repeat(32));
    let artifact = s.path("art.tar");
    std::fs::write(&artifact, b"the genuine published archive").unwrap();
    let contract = s.path("contract.json");
    let log = s.path("install.audit.json");

    let (_o, code) = run(&[
        "capsule",
        "sign",
        "--artifact",
        "pdf-extract@2.0.0",
        "--artifact-file",
        &artifact,
        "--requires",
        &example("capsule-requires.json"),
        "--key",
        &secret,
        "--out",
        &contract,
    ]);
    assert_eq!(code, 0, "sign should succeed");

    let (_o, code) = run(&[
        "capsule",
        "install",
        "--consumer",
        &example("capsule-consumer.json"),
        "--contract",
        &contract,
        "--artifact",
        &artifact,
        "--audit-out",
        &log,
    ]);
    assert_eq!(code, 0, "accepted install should exit 0");

    // The written log verifies with the audit crate and records request →
    // installed.
    let audit = AuditLog::from_json(&std::fs::read_to_string(&log).unwrap()).unwrap();
    assert!(audit.verify().is_ok(), "audit chain must verify");
    let nd = audit.to_ndjson().unwrap();
    assert!(nd.contains("capsule_requested"), "log records the request");
    assert!(nd.contains("capsule_installed"), "log records the install");

    // …and the standalone `audit verify` command agrees.
    let (_o, code) = run(&["audit", "verify", "--log", &log]);
    assert_eq!(code, 0, "`audit verify` should accept the written log");
}

#[test]
fn install_run_executes_the_packages_entrypoint() {
    let s = Scratch::new("run");
    let secret = keygen(&"ac".repeat(32));
    // A real package whose entrypoint declares [net] — within the read-only +
    // allowlist effective grant.
    let artifact = s.path("pdf-extract.tgz");
    make_package(
        &artifact,
        "import \"std.net\" as net\nfn run(u :: Str) -> [net] Result[Str, Str] { net.get(u) }\n",
    );
    let contract = s.path("contract.json");
    let log = s.path("run.audit.json");

    run(&[
        "capsule",
        "sign",
        "--artifact",
        "pdf-extract@2.0.0",
        "--artifact-file",
        &artifact,
        "--requires",
        &example("capsule-requires.json"),
        "--key",
        &secret,
        "--out",
        &contract,
    ]);

    let (out, code) = run(&[
        "--output",
        "json",
        "capsule",
        "install",
        "--consumer",
        &example("capsule-consumer.json"),
        "--contract",
        &contract,
        "--artifact",
        &artifact,
        "--audit-out",
        &log,
        "--run",
    ]);
    assert_eq!(
        code, 0,
        "install --run should reach a terminal outcome and exit 0"
    );
    // The entrypoint's real declared effects drove the workload.
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["data"]["entrypoint"], "src/main.lex");
    assert_eq!(v["data"]["workload"][0], "net.fetch");

    let audit = AuditLog::from_json(&std::fs::read_to_string(&log).unwrap()).unwrap();
    assert!(
        audit.verify().is_ok(),
        "the one install+session chain must verify"
    );
    let nd = audit.to_ndjson().unwrap();
    assert!(nd.contains("capsule_installed"));
    assert!(
        nd.contains("provisioned"),
        "the session provisioned the box"
    );
    assert!(
        nd.contains("net.fetch"),
        "the entrypoint's net effect was mediated"
    );
    assert!(
        nd.contains("session_ended"),
        "the session reached a terminal state"
    );
}

#[test]
fn install_run_refuses_an_overreaching_entrypoint() {
    let s = Scratch::new("overreach");
    let secret = keygen(&"ac".repeat(32));
    // Entrypoint declares [io, fs_write]; the effective grant is read-only, so
    // the type-check wall must refuse it before anything runs.
    let artifact = s.path("evil.tgz");
    make_package(
        &artifact,
        "import \"std.log\" as log\nfn run(p :: Str) -> [io, fs_write] Result[Nil, Str] { log.set_sink(p) }\n",
    );
    let contract = s.path("contract.json");
    let log = s.path("evil.audit.json");

    run(&[
        "capsule",
        "sign",
        "--artifact",
        "pdf-extract@9.9.9",
        "--artifact-file",
        &artifact,
        "--requires",
        &example("capsule-requires.json"),
        "--key",
        &secret,
        "--out",
        &contract,
    ]);

    let (_o, code) = run(&[
        "capsule",
        "install",
        "--consumer",
        &example("capsule-consumer.json"),
        "--contract",
        &contract,
        "--artifact",
        &artifact,
        "--audit-out",
        &log,
        "--run",
    ]);
    assert_eq!(code, 8, "an over-reaching entrypoint is refused (exit 8)");

    let audit = AuditLog::from_json(&std::fs::read_to_string(&log).unwrap()).unwrap();
    assert!(audit.verify().is_ok());
    let nd = audit.to_ndjson().unwrap();
    // Refused before running: request → refused, no spurious install or session.
    assert!(nd.contains("capsule_requested"));
    assert!(nd.contains("capsule_refused"));
    assert!(
        nd.contains("fs_write"),
        "the reason names the over-reaching effect"
    );
    assert!(!nd.contains("session_ended"), "nothing ran");
    assert!(
        !nd.contains("capsule_installed"),
        "it was refused, not installed"
    );
}

#[test]
fn refused_install_records_the_refusal_and_still_verifies() {
    let s = Scratch::new("refuse");
    let secret = keygen(&"ac".repeat(32));
    let artifact = s.path("art.tar");
    std::fs::write(&artifact, b"the genuine published archive").unwrap();
    let contract = s.path("contract.json");
    let keyring = s.path("keyring.json");
    let log = s.path("refuse.audit.json");

    run(&[
        "capsule",
        "sign",
        "--artifact",
        "pdf-extract@2.0.0",
        "--artifact-file",
        &artifact,
        "--requires",
        &example("capsule-requires.json"),
        "--key",
        &secret,
        "--out",
        &contract,
    ]);
    // A keyring that trusts a *different* key, so the real signer is untrusted.
    std::fs::write(
        &keyring,
        format!("{{\"trusted\":[\"{}\"]}}", "00".repeat(32)),
    )
    .unwrap();

    let (_o, code) = run(&[
        "capsule",
        "install",
        "--consumer",
        &example("capsule-consumer.json"),
        "--contract",
        &contract,
        "--artifact",
        &artifact,
        "--trusted-keys",
        &keyring,
        "--audit-out",
        &log,
    ]);
    assert_eq!(code, 8, "untrusted signer should be refused (exit 8)");

    // The refusal is durable and tamper-evident.
    let audit = AuditLog::from_json(&std::fs::read_to_string(&log).unwrap()).unwrap();
    assert!(audit.verify().is_ok(), "refusal log must still verify");
    let nd = audit.to_ndjson().unwrap();
    assert!(nd.contains("capsule_requested"));
    assert!(nd.contains("capsule_refused"));
    assert!(nd.contains("trusted keyring"), "the reason is recorded");
}
