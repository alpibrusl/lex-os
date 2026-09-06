//! Tamper-evident audit log (design doc §5.3).
//!
//! The log lives *outside* the box, owned by the supervisor. "An agent
//! editing its own logs is a classic failure to design out", so the log
//! is a hash chain: each entry commits to the hash of the previous one,
//! and any after-the-fact edit, reorder, or deletion breaks the chain
//! and is caught by [`AuditLog::verify`].
//!
//! The default posture is *legible history*: every mediated decision —
//! allowed or denied — is recorded before its effect runs.
//!
//! # What the chain does and does not prove
//!
//! [`Chain::verify`] catches an edited payload, a reordered entry, and a
//! deletion from anywhere but the end. It does **not** catch truncation
//! of the tail: a prefix of a valid chain is itself a valid chain, and
//! nothing inside the log proves that a further entry once followed.
//! Nor does it stop a holder who recomputes every hash after an edit —
//! the hashes are derived, not signed.
//!
//! Both gaps close the same way, and neither is cryptographic: commit to
//! the head somewhere the log'"'"'s holder does not control. lex-os'"'"'s answer
//! is positional — the log lives outside the box, owned by the supervisor
//! the agent cannot reach — so the party who could truncate it is the
//! party being protected, not the one being audited. A consumer that
//! *does* need to distrust the holder must publish or countersign the
//! head; see `Chain::head`.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The genesis hash that the first entry chains from. A fixed,
/// well-known value so an empty log has a defined head.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A single thing worth recording. Kept as a flat enum so the log is
/// self-describing and replayable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// A box was provisioned (or reprovisioned) from a manifest.
    Provisioned {
        manifest_id: String,
        backend: String,
        reprovision: bool,
    },
    /// The agent requested a mediated command.
    CommandRequested {
        seq: u64,
        command: String,
        reversibility: String,
    },
    /// The supervisor allowed the command.
    CommandAllowed { command: String },
    /// The observed result of an approved skill executed in the guest.
    /// Recorded after the effect so the audit log carries outcomes, not
    /// just decisions.
    SkillOutcome {
        command: String,
        outcome: String,
        observation: String,
    },
    /// The supervisor denied the command, with a reason.
    CommandDenied { command: String, reason: String },
    /// Budget was consumed; the running totals after the charge.
    BudgetCharged {
        commands: u64,
        money_cents: u64,
        api_calls: u64,
        elapsed_secs: u64,
    },
    /// A budget ceiling was hit; the box is halting.
    BudgetExhausted { which: String },
    /// A liveness check failed — the box is presumed dead/wedged.
    LivenessFailed { detail: String },
    /// The box was destroyed (by the agent or the supervisor).
    Destroyed { reason: String },
    /// An attempt to widen the grant (rewrite the manifest / spawn a
    /// child with broader trust) was rejected by the narrowing
    /// invariant. The demo's `[BLOCKED:narrowing]` line.
    NarrowingBlocked { reason: String },
    /// A capsule install was requested — logged *before* any gate decides,
    /// like [`Event::CommandRequested`]. `signer` is the claimed (not yet
    /// verified) publisher key; `content_hash` is the archive hash the
    /// contract claims (not yet checked against the bytes).
    CapsuleRequested {
        artifact: String,
        signer: String,
        content_hash: String,
    },
    /// A capsule passed every gate (authenticity, trusted signer, byte
    /// integrity, narrowing) and the effective box was provisioned.
    /// `content_hash` names the exact published bytes that installed —
    /// the publish-time identity, so the record says *which* artifact ran,
    /// not just its mutable `name@version` label. Promoted into the
    /// lex-lang attestation graph by `lex attest import-install`.
    CapsuleInstalled {
        artifact: String,
        signer: String,
        content_hash: String,
        effective_grant: String,
    },
    /// A capsule install was refused, with the reason (an untrusted signer,
    /// a substituted archive, a widening grant, an unsatisfiable host, …).
    CapsuleRefused { artifact: String, reason: String },
    /// A one-shot escalation grant was armed by a named resolver for a
    /// single command (#60). Logged BEFORE any re-evaluation uses it —
    /// the authorization is on the record even if the widened call never
    /// happens. The grant levels are recorded verbatim.
    EscalationGranted {
        command: String,
        resolver: String,
        filesystem: String,
        network: String,
        exec: String,
    },
    /// An escalation was rejected at arm time (non-widening, empty
    /// resolver, wrong command). A rejected escalation must be as legible
    /// in the record as an applied one.
    EscalationRejected { command: String, reason: String },
    /// An armed escalation was consumed by exactly one mediation of its
    /// command — `outcome` is "applied" (the widened check admitted the
    /// command) or "insufficient" (even the delta did not cover the
    /// required level). Either way the grant is dead afterwards.
    EscalationConsumed { command: String, outcome: String },
    /// The classified outcome of an in-box execution (#61): `class` is
    /// the backend-independent stable label (denied_by_perimeter /
    /// launch_failure / timed_out / exited_in_guest), `detail` the
    /// backend-dialect specifics (matched rule, cause, or exit code).
    /// "The perimeter denied X" and "X never launched" are different
    /// facts; conflating them poisons both debugging and the record.
    ExecClassified { class: String, detail: String },
    /// The session reached a terminal state.
    SessionEnded { outcome: String },
}

/// What a [`Chain`] can carry (lex-os#67).
///
/// The tamper-evidence — each entry committing to its predecessor's hash
/// from a fixed [`GENESIS`], with [`Chain::verify`] catching any edit,
/// reorder or deletion — is domain-neutral and worth reusing. The
/// *vocabulary* is not: [`Event`] is the supervisor's mediation model and
/// has no business learning what Terraform or Kubernetes are. So a
/// downstream gate instantiates the chain with its own payload and gets
/// the same guarantees, while lex-os keeps its own closed enum.
///
/// `DOMAIN` is the hash's domain separator. Each payload type must pick
/// its own, so an entry from one vocabulary can never be replayed as an
/// entry in another. [`Event`]'s is fixed forever at `lex.os.audit.v1`:
/// changing it would invalidate every audit log ever written.
pub trait ChainPayload: Serialize + DeserializeOwned {
    const DOMAIN: &'static [u8];
}

impl ChainPayload for Event {
    const DOMAIN: &'static [u8] = b"lex.os.audit.v1";
}

/// One link in the chain: a sequence number, the previous entry's hash,
/// the event, and this entry's own hash over all of the above.
///
/// Generic over the payload, defaulting to [`Event`] so the supervisor's
/// `Entry` keeps its unparameterised spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry<E = Event> {
    pub seq: u64,
    pub prev_hash: String,
    pub event: E,
    pub hash: String,
}

impl<E: ChainPayload> Entry<E> {
    /// Recompute the hash this entry *should* have from its contents.
    /// Hashing the canonical JSON of the event keeps it stable.
    fn compute_hash(seq: u64, prev_hash: &str, event: &E) -> String {
        let event_json = serde_json::to_string(event).expect("event is serializable");
        let mut hasher = Sha256::new();
        hasher.update(E::DOMAIN);
        hasher.update(seq.to_be_bytes());
        hasher.update(prev_hash.as_bytes());
        hasher.update(event_json.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit chain broken at seq {seq}: {detail}")]
    Broken { seq: u64, detail: String },
    #[error("failed to (de)serialize audit log: {0}")]
    Serde(#[from] serde_json::Error),
}

/// An append-only, hash-chained log. Conceptually owned by the
/// supervisor and persisted to external storage the box cannot reach.
///
/// Generic over its payload (lex-os#67); [`AuditLog`] is the
/// supervisor's instantiation over [`Event`]. Append-only is a property
/// of the chain, not of any one vocabulary: no instantiation gets an
/// edit or truncate API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain<E = Event> {
    entries: Vec<Entry<E>>,
}

/// The supervisor's audit log: a [`Chain`] of [`Event`].
pub type AuditLog = Chain<Event>;

// Hand-written rather than derived: a chain of any payload starts empty,
// whether or not the payload itself is `Default`.
impl<E> Default for Chain<E> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<E: ChainPayload> Chain<E> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// The hash at the head of the chain — `GENESIS` when empty.
    pub fn head(&self) -> String {
        self.entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Entry<E>] {
        &self.entries
    }

    /// Append an event, chaining it to the current head. Returns the new
    /// head hash. This is the only way to grow the log.
    pub fn append(&mut self, event: E) -> String {
        let seq = self.entries.len() as u64;
        let prev_hash = self.head();
        let hash = Entry::compute_hash(seq, &prev_hash, &event);
        self.entries.push(Entry {
            seq,
            prev_hash,
            event,
            hash: hash.clone(),
        });
        hash
    }

    /// Verify the entire chain: sequence numbers are contiguous, each
    /// entry's `prev_hash` matches its predecessor's hash, and every
    /// stored hash matches a fresh recomputation. An edited payload, a
    /// reordered entry, or a deletion from anywhere but the end is
    /// detected here.
    ///
    /// Truncating the *tail* is not, and cannot be: the remaining prefix
    /// is a well-formed chain. See the module docs for why lex-os treats
    /// that as acceptable and what a consumer who cannot must do.
    pub fn verify(&self) -> Result<(), AuditError> {
        let mut expected_prev = GENESIS.to_string();
        for (i, entry) in self.entries.iter().enumerate() {
            let seq = i as u64;
            if entry.seq != seq {
                return Err(AuditError::Broken {
                    seq,
                    detail: format!("expected seq {seq}, found {}", entry.seq),
                });
            }
            if entry.prev_hash != expected_prev {
                return Err(AuditError::Broken {
                    seq,
                    detail: "prev_hash does not match predecessor".into(),
                });
            }
            let recomputed = Entry::compute_hash(entry.seq, &entry.prev_hash, &entry.event);
            if recomputed != entry.hash {
                return Err(AuditError::Broken {
                    seq,
                    detail: "entry hash does not match its contents (payload tampered)".into(),
                });
            }
            expected_prev = entry.hash.clone();
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, AuditError> {
        Ok(serde_json::to_string_pretty(&self.entries)?)
    }

    /// Render the log as newline-delimited JSON (one entry per line) for
    /// a live, tailable viewer — the demo's on-screen external log. Each
    /// line carries the full chained `Entry` (seq, prev_hash, event,
    /// hash), so a consumer can verify the chain incrementally.
    pub fn to_ndjson(&self) -> Result<String, AuditError> {
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&serde_json::to_string(entry)?);
            out.push('\n');
        }
        Ok(out)
    }

    pub fn from_json(s: &str) -> Result<Self, AuditError> {
        let entries: Vec<Entry<E>> = serde_json::from_str(s)?;
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Generic chain (lex-os#67) -----------------------------------

    /// A downstream gate's vocabulary. lex-os knows nothing about plan
    /// artifacts; this exists to prove the chain does not need to.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum PlanEvent {
        PlanRequested { artifact_sha256: String },
        PlanRefused { effect: String, reason: String },
    }

    impl ChainPayload for PlanEvent {
        const DOMAIN: &'static [u8] = b"test.plan.v1";
    }

    /// The whole point of #67: a second payload gets the same
    /// tamper-evidence with no change to `Event`.
    #[test]
    fn chain_carries_a_foreign_payload() {
        let mut chain: Chain<PlanEvent> = Chain::new();
        assert_eq!(chain.head(), GENESIS);
        chain.append(PlanEvent::PlanRequested {
            artifact_sha256: "abc".into(),
        });
        chain.append(PlanEvent::PlanRefused {
            effect: "aws.rds.delete".into(),
            reason: "outside grant".into(),
        });
        assert_eq!(chain.len(), 2);
        chain.verify().expect("a well-formed chain verifies");

        // Round-trips through the same array-of-entries wire format.
        let json = chain.to_json().unwrap();
        let back = Chain::<PlanEvent>::from_json(&json).unwrap();
        assert_eq!(back.entries(), chain.entries());
        back.verify().unwrap();
    }

    /// Tamper-evidence is a property of the chain, so it holds for any
    /// payload — not just the one lex-os ships.
    #[test]
    fn foreign_payload_tampering_is_still_caught() {
        let mut chain: Chain<PlanEvent> = Chain::new();
        chain.append(PlanEvent::PlanRequested {
            artifact_sha256: "abc".into(),
        });
        chain.append(PlanEvent::PlanRefused {
            effect: "aws.rds.delete".into(),
            reason: "outside grant".into(),
        });

        // Rewrite a refusal into something innocuous, as a gate that
        // wanted to hide a denial would.
        let mut tampered = chain.clone();
        tampered.entries[1].event = PlanEvent::PlanRefused {
            effect: "aws.logs.read".into(),
            reason: "outside grant".into(),
        };
        assert!(matches!(
            tampered.verify().unwrap_err(),
            AuditError::Broken { seq: 1, .. }
        ));

        // Dropping the denial entirely breaks the chain at the seam.
        let mut truncated = chain.clone();
        truncated.entries.remove(0);
        assert!(truncated.verify().is_err());
    }

    /// Tail truncation is the chain's known limit, pinned so nobody
    /// later reads `verify` as proving more than it does: a prefix of a
    /// valid chain verifies, because nothing inside the log says another
    /// entry once followed. Deletion from the middle IS caught (the test
    /// above), which is the distinction that matters when reasoning about
    /// what an audit log is worth.
    #[test]
    fn tail_truncation_is_not_detected() {
        let mut log = AuditLog::new();
        log.append(Event::CommandAllowed {
            command: "read report.md".into(),
        });
        log.append(Event::CommandDenied {
            command: "curl evil.com".into(),
            reason: "perimeter".into(),
        });
        log.verify().expect("the full chain verifies");

        // Drop the denial — the embarrassing entry is always the last one.
        let mut truncated = log.clone();
        truncated.entries.pop();
        assert_eq!(truncated.len(), 1);
        assert!(
            truncated.verify().is_ok(),
            "a truncated prefix still verifies — this is the documented limit, \
             not a regression; the mitigation is an external commitment to the head"
        );

        // The head is what changes, which is why it is the thing to publish.
        assert_ne!(log.head(), truncated.head());
    }

    /// Domain separation: identical bytes under a different payload type
    /// hash differently, so an entry from one vocabulary can never be
    /// replayed into another's chain.
    #[test]
    fn payload_domains_are_separated() {
        #[derive(Serialize, Deserialize)]
        struct Same(String);
        impl ChainPayload for Same {
            const DOMAIN: &'static [u8] = b"test.same.v1";
        }
        #[derive(Serialize, Deserialize)]
        struct Other(String);
        impl ChainPayload for Other {
            const DOMAIN: &'static [u8] = b"test.other.v1";
        }

        let a = Entry::<Same>::compute_hash(0, GENESIS, &Same("x".into()));
        let b = Entry::<Other>::compute_hash(0, GENESIS, &Other("x".into()));
        assert_ne!(a, b, "different domains must not collide on equal bodies");
    }

    /// Golden fixture. `lex attest import-install` (lex-lang) parses these
    /// logs as a JSON array and keys on `event.kind`, and `lex-os audit
    /// verify` must keep accepting logs written by older versions — so
    /// both the wire shape and the hashes are frozen here. If making the
    /// chain generic had perturbed either, this fails.
    #[test]
    fn event_wire_format_and_hashes_are_frozen() {
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

        assert_eq!(
            log.entries()[0].hash,
            "fb395143df9e0e4da7b221ababda66496331256a2d2213aa70648726942ed3da"
        );
        assert_eq!(
            log.head(),
            "1d05861fbe92c0af3b1f1db2c4fa07e3e91ee6b90756088d070e15ac0b2391af"
        );

        // The exact JSON an importer sees: a flat array, `kind`-tagged
        // events, snake_case field names.
        let parsed: serde_json::Value = serde_json::from_str(&log.to_json().unwrap()).unwrap();
        let entries = parsed.as_array().expect("a JSON array of entries");
        assert_eq!(entries[0]["event"]["kind"], "provisioned");
        assert_eq!(entries[0]["event"]["manifest_id"], "m");
        assert_eq!(entries[1]["event"]["kind"], "command_denied");
        assert_eq!(entries[1]["prev_hash"], entries[0]["hash"]);
    }

    #[test]
    fn empty_log_head_is_genesis() {
        let log = AuditLog::new();
        assert_eq!(log.head(), GENESIS);
        assert!(log.verify().is_ok());
    }

    #[test]
    fn appending_chains_and_verifies() {
        let mut log = AuditLog::new();
        log.append(Event::Provisioned {
            manifest_id: "abc".into(),
            backend: "simulated".into(),
            reprovision: false,
        });
        log.append(Event::CommandRequested {
            seq: 0,
            command: "fs.read".into(),
            reversibility: "reversible-cheap".into(),
        });
        log.append(Event::CommandAllowed {
            command: "fs.read".into(),
        });
        assert_eq!(log.len(), 3);
        assert!(log.verify().is_ok());
        // Each entry chains to the previous.
        assert_eq!(log.entries()[1].prev_hash, log.entries()[0].hash);
        assert_eq!(log.entries()[2].prev_hash, log.entries()[1].hash);
    }

    #[test]
    fn tampering_with_a_payload_is_detected() {
        let mut log = AuditLog::new();
        log.append(Event::CommandAllowed {
            command: "spend".into(),
        });
        log.append(Event::CommandAllowed {
            command: "delete".into(),
        });
        // Agent tries to rewrite history: change a recorded command but
        // leave the stored hash in place.
        log.entries[0].event = Event::CommandDenied {
            command: "spend".into(),
            reason: "faked".into(),
        };
        let err = log.verify().unwrap_err();
        assert!(matches!(err, AuditError::Broken { seq: 0, .. }));
    }

    #[test]
    fn deleting_an_entry_breaks_the_chain() {
        let mut log = AuditLog::new();
        log.append(Event::CommandAllowed {
            command: "a".into(),
        });
        log.append(Event::CommandAllowed {
            command: "b".into(),
        });
        log.append(Event::CommandAllowed {
            command: "c".into(),
        });
        // Remove the middle entry and renumber to hide it.
        log.entries.remove(1);
        log.entries[1].seq = 1;
        let err = log.verify().unwrap_err();
        assert!(matches!(err, AuditError::Broken { .. }));
    }

    #[test]
    fn capsule_install_events_chain_and_verify() {
        // A capsule install records request → decision, like the mediation
        // loop's request → allow/deny.
        let mut log = AuditLog::new();
        log.append(Event::CapsuleRequested {
            artifact: "pdf-extract@2.0.0".into(),
            signer: "f9b43983".into(),
            content_hash: "deadbeef".into(),
        });
        log.append(Event::CapsuleInstalled {
            artifact: "pdf-extract@2.0.0".into(),
            signer: "f9b43983".into(),
            content_hash: "deadbeef".into(),
            effective_grant: "fs=read-only net=allowlist exec=none".into(),
        });
        assert!(log.verify().is_ok());
        assert_eq!(log.entries()[1].prev_hash, log.entries()[0].hash);
        // A refusal is just as recordable, and tamper-evident.
        let mut refused = AuditLog::new();
        refused.append(Event::CapsuleRefused {
            artifact: "pdf-extract@2.1.0".into(),
            reason: "signer not in trusted keyring".into(),
        });
        assert!(refused.verify().is_ok());
        assert!(refused.to_ndjson().unwrap().contains("capsule_refused"));
    }

    #[test]
    fn roundtrips_through_json() {
        let mut log = AuditLog::new();
        log.append(Event::SessionEnded {
            outcome: "goal_met".into(),
        });
        let json = log.to_json().unwrap();
        let back = AuditLog::from_json(&json).unwrap();
        assert!(back.verify().is_ok());
        assert_eq!(back.head(), log.head());
    }

    #[test]
    fn ndjson_has_one_line_per_entry() {
        let mut log = AuditLog::new();
        log.append(Event::CommandDenied {
            command: "net.fetch".into(),
            reason: "blocked".into(),
        });
        log.append(Event::NarrowingBlocked {
            reason: "child widens network".into(),
        });
        let nd = log.to_ndjson().unwrap();
        let lines: Vec<&str> = nd.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line is independently parseable JSON.
        for line in lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
        assert!(nd.contains("narrowing_blocked"));
    }

    #[test]
    fn skill_outcome_event_chains_and_verifies() {
        let mut log = AuditLog::new();
        log.append(Event::CommandAllowed {
            command: "move_to".into(),
        });
        log.append(Event::SkillOutcome {
            command: "move_to".into(),
            outcome: "reached".into(),
            observation: "{\"coverage_reward\":0.9}".into(),
        });
        assert!(log.verify().is_ok());
        assert!(log.to_ndjson().unwrap().contains("skill_outcome"));
    }
}
