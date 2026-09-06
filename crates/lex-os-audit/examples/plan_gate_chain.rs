//! The audit chain carrying a vocabulary lex-os has never heard of
//! (lex-os#67).
//!
//! A downstream gate — say `lex-iac`, deciding whether a Terraform plan
//! may apply — needs the tamper-evidence, not the supervisor's event
//! vocabulary. It declares its own payload and gets the same chain.
//!
//! Run it:
//!
//! ```sh
//! cargo run -p lex-os-audit --example plan_gate_chain
//! ```

use lex_os_audit::{AuditLog, Chain, ChainPayload, Event, GENESIS};
use serde::{Deserialize, Serialize};

/// What a plan gate records. lex-os knows nothing about any of this.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PlanEvent {
    PlanRequested { artifact_sha256: String },
    PlanRefused { effect: String, reason: String },
}

impl ChainPayload for PlanEvent {
    const DOMAIN: &'static [u8] = b"lex.iac.audit.v1";
}

fn main() {
    // ---- 1. A foreign payload chains and verifies -------------------
    println!("1. A gate records its own vocabulary\n");

    let mut gate: Chain<PlanEvent> = Chain::new();
    println!("   empty head = GENESIS: {}", gate.head() == GENESIS);

    gate.append(PlanEvent::PlanRequested {
        artifact_sha256: "9f2b…".into(),
    });
    gate.append(PlanEvent::PlanRefused {
        effect: "aws.rds.delete".into(),
        reason: "outside the grant".into(),
    });

    for e in gate.entries() {
        println!("   seq {}  {:.12}…  {:?}", e.seq, e.hash, e.event);
    }
    println!("   verify: {:?}", gate.verify().map(|_| "ok"));

    // ---- 2. Rewriting a refusal breaks the chain --------------------
    println!("\n2. A gate tries to hide the refusal it made\n");

    let json = gate.to_json().unwrap();
    let doctored = json.replace("aws.rds.delete", "aws.logs.read");
    let tampered = Chain::<PlanEvent>::from_json(&doctored).unwrap();
    println!("   the log still parses, and reads innocently:");
    println!("   {:?}", tampered.entries()[1].event);
    match tampered.verify() {
        Ok(()) => println!("   verify: ok  ← would mean the chain is worthless"),
        Err(e) => println!("   verify: {e}"),
    }

    // ---- 3. Deleting from the middle breaks it too ------------------
    println!("\n3. So it deletes an entry instead\n");

    let mut arr: serde_json::Value = serde_json::from_str(&json).unwrap();
    arr.as_array_mut().unwrap().remove(0); // drop the request, keep the refusal
    let gutted = Chain::<PlanEvent>::from_json(&arr.to_string()).unwrap();
    println!("   dropped seq 0, {} entr(y|ies) left", gutted.len());
    match gutted.verify() {
        Ok(()) => println!("   verify: ok"),
        Err(e) => println!("   verify: {e}"),
    }

    // ---- 3b. The limit: truncating the tail is NOT detected ---------
    println!("\n3b. The honest limit — it drops the LAST entry\n");

    let mut arr: serde_json::Value = serde_json::from_str(&json).unwrap();
    arr.as_array_mut().unwrap().pop(); // drop the refusal, keep the request
    let truncated = Chain::<PlanEvent>::from_json(&arr.to_string()).unwrap();
    println!("   dropped the refusal, {} entry left", truncated.len());
    match truncated.verify() {
        Ok(()) => println!("   verify: ok  ← NOT detected, and cannot be"),
        Err(e) => println!("   verify: {e}"),
    }
    println!("   A prefix of a valid chain is itself a valid chain. Nothing inside");
    println!("   the log proves an entry once followed. Only an external commitment");
    println!("   to the head — published where the log's holder cannot reach — closes");
    println!("   this, and lex-os's answer is positional: the log lives outside the box.");

    // ---- 4. Domains keep the vocabularies apart ---------------------
    println!("\n4. Two payloads, identical bytes, different domains\n");

    #[derive(Serialize, Deserialize)]
    struct Alpha(String);
    #[derive(Serialize, Deserialize)]
    struct Beta(String);
    impl ChainPayload for Alpha {
        const DOMAIN: &'static [u8] = b"example.alpha.v1";
    }
    impl ChainPayload for Beta {
        const DOMAIN: &'static [u8] = b"example.beta.v1";
    }

    let mut a: Chain<Alpha> = Chain::new();
    let mut b: Chain<Beta> = Chain::new();
    a.append(Alpha("same".into()));
    b.append(Beta("same".into()));
    println!("   alpha head: {:.16}…", a.head());
    println!("   beta  head: {:.16}…", b.head());
    println!(
        "   equal: {}  ← an entry cannot be replayed across chains",
        a.head() == b.head()
    );

    // ---- 5. The supervisor's own log is untouched -------------------
    println!("\n5. And lex-os's own vocabulary hashes exactly as before\n");

    let mut log = AuditLog::new();
    log.append(Event::Provisioned {
        manifest_id: "m".into(),
        backend: "simulated".into(),
        reprovision: false,
    });
    log.append(Event::CommandDenied {
        command: "curl evil.com".into(),
        reason: "perimeter".into(),
    });
    const FROZEN_HEAD: &str = "1d05861fbe92c0af3b1f1db2c4fa07e3e91ee6b90756088d070e15ac0b2391af";
    println!("   head:   {}", log.head());
    println!("   frozen: {FROZEN_HEAD}");
    println!("   match:  {}", log.head() == FROZEN_HEAD);
    println!(
        "   (captured from the pre-refactor build; `lex attest import-install` reads these logs)"
    );
}
