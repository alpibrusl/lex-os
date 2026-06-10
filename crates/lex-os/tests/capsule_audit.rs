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
fn install_run_chains_the_session_onto_the_install_decision() {
    let s = Scratch::new("run");
    let secret = keygen(&"ac".repeat(32));
    let artifact = s.path("art.tar");
    std::fs::write(&artifact, b"the genuine published archive").unwrap();
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
    assert_eq!(
        code, 0,
        "install --run should reach a terminal outcome and exit 0"
    );

    let audit = AuditLog::from_json(&std::fs::read_to_string(&log).unwrap()).unwrap();
    assert!(
        audit.verify().is_ok(),
        "the one install+session chain must verify"
    );
    // First entry is the install decision; the session chains onto it.
    let nd = audit.to_ndjson().unwrap();
    assert!(nd.contains("capsule_requested"));
    assert!(nd.contains("capsule_installed"));
    assert!(
        nd.contains("provisioned"),
        "the session provisioned the box"
    );
    assert!(
        nd.contains("session_ended"),
        "the session reached a terminal state"
    );
    // The effective read-only grant is load-bearing at runtime: the workload's
    // fs.write is denied by the perimeter, mid-session.
    assert!(
        nd.contains("command_denied") && nd.contains("read-write not permitted"),
        "the effective grant must deny fs.write at runtime"
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
