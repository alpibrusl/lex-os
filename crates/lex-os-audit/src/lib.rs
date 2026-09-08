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
//! # Three layers, and what each one actually closes
//!
//! The chain alone is the first layer, and it is the weakest of the
//! three. [`Chain::verify`] catches an edited payload, a reordered
//! entry, and a deletion from anywhere but the end. It does **not**
//! catch two things, and neither is an oversight:
//!
//! 1. **Truncation of the tail.** A prefix of a valid chain is itself a
//!    valid chain, and nothing inside the log proves a further entry
//!    once followed. Pinned by `tail_truncation_is_not_detected`.
//! 2. **A holder who recomputes.** The hashes are *derived*, so whoever
//!    can edit the log can rebuild every hash after the edit and hand
//!    you something that verifies perfectly.
//!
//! lex-os#54 is the observation that "the log lives outside the box" was
//! carrying both of these on its own, and that a positional argument is
//! only as good as the position. So there are two more layers:
//!
//! **Seals** ([`Chain::append_signed`], [`Chain::verify_seals`]) put an
//! Ed25519 signature over each entry's hash. That closes (2): a holder
//! without the key can still rewrite the log, but they cannot re-sign
//! it, so the rewrite is *visible*. It does nothing for (1) — a
//! truncated chain of properly sealed entries is properly sealed.
//!
//! **Checkpoints** ([`Chain::checkpoint`], [`Chain::verify_against`])
//! are a signature over `(domain, len, head)`. That closes (1), because
//! a checkpoint asserts the chain *was at least this long*, and a
//! truncated chain fails against it. It closes (1) **only if the
//! checkpoint is held somewhere the auditee cannot reach** — which is
//! why a checkpoint is a few hundred bytes: small enough to print in a
//! log line, mail, commit, or hand to another service, none of which
//! the box can rewrite.
//!
//! None of the three closes "the signer is compromised". A key that
//! signs whatever it is given produces a log that verifies and lies.
//! What the layers buy is that a *rewrite* now requires the key, and a
//! *truncation* now requires reaching two places instead of one.
//!
//! An empty trusted-key list trusts nobody, and a chain with no seals
//! is reported as unsealed rather than treated as passing — the same
//! rule as everywhere else here: an empty X is not a permissive X.
//!
use ed25519_dalek::{Signature, Signer, Verifier};
// Re-exported: a consumer that seals a log needs a key type, and making
// every one of them depend on `ed25519-dalek` directly is how two crates
// end up on two versions of it and stop verifying each other's logs.
pub use ed25519_dalek::{SigningKey, VerifyingKey};
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
    /// What authorised this session, as a decision recorded elsewhere.
    ///
    /// First in a session that has one, so a reader holding only the
    /// session can say which decision it descends from. A gate writes
    /// its own chain and the box writes another; without this the two
    /// are related by nothing stronger than the filenames an operator
    /// chose (lex-iac#19).
    ///
    /// Knowing the head is itself the evidence of order: a hash cannot
    /// be quoted before the thing it commits to exists, so a session
    /// naming one demonstrably began after that decision was made. It
    /// does not prove the decision's record still exists — that is what
    /// a ledger is for — nor that this was the only session it
    /// authorised.
    AuthorisedBy {
        /// The head hash of the deciding chain.
        decision_head: String,
        /// That chain's payload domain, e.g. `lex.iac.audit.v1`.
        ///
        /// Recorded because a head is meaningless without knowing what
        /// kind of log it is the head of, and because it stops a head
        /// from one vocabulary being presented as another — the same
        /// reason `Checkpoint` carries one.
        decision_domain: String,
    },
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
    /// The signature over `hash`, when this entry was sealed
    /// (lex-os#54).
    ///
    /// Optional, and omitted from the JSON entirely when absent, so
    /// every log written before seals existed still parses and still
    /// hashes to the same values. An unsealed entry is not a failure —
    /// it is a log nobody signed, which [`Chain::verify_seals`] reports
    /// as exactly that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<Seal>,
}

/// Domain separator for an entry seal. Distinct from the entry hash's
/// own domain so a signature over one can never be read as the other.
const SEAL_DOMAIN: &[u8] = b"lex.os.audit.seal.v1";

/// Domain separator for a checkpoint signature.
const CHECKPOINT_DOMAIN: &[u8] = b"lex.os.audit.checkpoint.v1";

/// An Ed25519 signature over one entry's hash, by a named signer
/// (lex-os#54).
///
/// The signature is over the *hash*, not the payload: the hash already
/// commits to the payload, the sequence number, the predecessor and the
/// payload domain, so signing it commits to all of them and to the
/// entry's position in the chain.
///
/// Deliberately **not** part of [`Entry::compute_hash`]. If the seal
/// fed the hash, the hash would change when the entry was signed, and
/// every already-written unsealed log would stop verifying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    /// Hex-encoded Ed25519 public key (32 bytes) of whoever sealed it.
    pub signer: String,
    /// Hex-encoded Ed25519 signature (64 bytes).
    pub signature: String,
}

impl Seal {
    /// Does this seal name `key` as its signer?
    ///
    /// Names, not proves — a signer field is a claim until the signature
    /// is checked. Use it to ask *whose* seal an entry carries;
    /// [`Chain::verify_seals`] is what decides whether the claim holds.
    pub fn names(&self, key: &VerifyingKey) -> bool {
        decode_key(&self.signer).is_ok_and(|k| k == *key)
    }
}

/// A signed commitment that a chain reached a given length and head
/// (lex-os#54).
///
/// This is the only thing here that catches tail truncation, and it
/// catches it by being *elsewhere*: a chain cannot contradict a
/// checkpoint its holder never had a copy of. Small on purpose — a few
/// hundred bytes of JSON — so publishing one is never the hard part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The payload domain of the chain this commits to, so a checkpoint
    /// for a `lex.iac.audit.v1` log can never be presented as one for a
    /// `lex.os.audit.v1` log.
    pub domain: String,
    /// How many entries the chain had. The number truncation cannot
    /// survive.
    pub len: u64,
    /// The head hash at that length.
    pub head: String,
    /// When, as the caller counts time. This crate does no I/O and does
    /// not read a clock; the value is whatever the caller can defend —
    /// seconds since the epoch, a block height, a monotonic counter.
    pub at: u64,
    /// Hex-encoded Ed25519 public key of the signer.
    pub signer: String,
    /// Hex-encoded Ed25519 signature over the fields above.
    pub signature: String,
}

/// A [`Checkpoint`] whose signature has been verified against a key the
/// caller chose to trust.
///
/// [`Chain::verify_against`] takes one of these rather than a bare
/// `Checkpoint`, so checking a chain against an unverified commitment
/// is not an API this crate offers. The failure it prevents is quiet
/// and total: an attacker who can truncate a log can also write the
/// checkpoint that says the truncated length was right.
#[derive(Debug, Clone)]
pub struct VerifiedCheckpoint(Checkpoint);

impl VerifiedCheckpoint {
    pub fn as_checkpoint(&self) -> &Checkpoint {
        &self.0
    }
}

/// The bytes an entry seal covers: the domain, the payload vocabulary,
/// the position, and the hash.
///
/// The hash alone would nearly do — it already commits to the payload,
/// the predecessor and the vocabulary. The rest is there so a signature
/// made for an entry seal can never be presented as a checkpoint, and
/// vice versa.
fn seal_payload<E: ChainPayload>(seq: u64, hash: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SEAL_DOMAIN);
    out.extend_from_slice(E::DOMAIN);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(hash.as_bytes());
    out
}

fn decode_key(hex_key: &str) -> Result<VerifyingKey, AuditError> {
    let bytes: [u8; 32] = hex::decode(hex_key)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| AuditError::Seal {
            seq: 0,
            detail: "signer is not 32 hex-encoded bytes".into(),
        })?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| AuditError::Seal {
        seq: 0,
        detail: "signer is not a valid Ed25519 public key".into(),
    })
}

fn decode_sig(hex_sig: &str, seq: u64) -> Result<Signature, AuditError> {
    let bytes: [u8; 64] = hex::decode(hex_sig)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| AuditError::Seal {
            seq,
            detail: "signature is not 64 hex-encoded bytes".into(),
        })?;
    Ok(Signature::from_bytes(&bytes))
}

impl Checkpoint {
    /// The bytes a checkpoint signature covers.
    fn signing_payload(domain: &str, len: u64, head: &str, at: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CHECKPOINT_DOMAIN);
        out.extend_from_slice(domain.as_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(&at.to_be_bytes());
        out
    }

    /// Check the signature against one key the caller trusts.
    ///
    /// The key is a parameter rather than read from `self.signer`,
    /// which would be circular: a checkpoint that names its own key
    /// proves only that *somebody* signed it.
    pub fn verify(&self, trusted: &VerifyingKey) -> Result<VerifiedCheckpoint, AuditError> {
        let named = decode_key(&self.signer)?;
        if named != *trusted {
            return Err(AuditError::Checkpoint {
                detail: format!(
                    "checkpoint is signed by {}, which is not the key given to verify it",
                    self.signer
                ),
            });
        }
        let sig = decode_sig(&self.signature, self.len)?;
        let payload = Self::signing_payload(&self.domain, self.len, &self.head, self.at);
        named
            .verify(&payload, &sig)
            .map_err(|_| AuditError::Checkpoint {
                detail: "checkpoint signature is invalid for the declared signer".into(),
            })?;
        Ok(VerifiedCheckpoint(self.clone()))
    }
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
    #[error("audit seal invalid at seq {seq}: {detail}")]
    Seal { seq: u64, detail: String },
    #[error("audit checkpoint: {detail}")]
    Checkpoint { detail: String },
}

/// An append-only, hash-chained log. Conceptually owned by the
/// supervisor and persisted to external storage the box cannot reach.
///
/// Generic over its payload (lex-os#67); [`AuditLog`] is the
/// supervisor's instantiation over [`Event`]. Append-only is a property
/// of the chain, not of any one vocabulary: no instantiation gets an
/// edit or truncate API.
#[derive(Clone, Serialize, Deserialize)]
pub struct Chain<E = Event> {
    entries: Vec<Entry<E>>,
    /// The key that seals each entry as it is appended, when the owner
    /// set one (lex-os#54).
    ///
    /// On the chain rather than in a wrapper, because the failure this
    /// is guarding against is a call site that *forgets*: an unsealed
    /// entry in a sealed log is exactly where a forged one goes, and
    /// there are twenty-odd `append` sites in the supervisor alone.
    /// Whoever owns the log decides once, and no caller can get it
    /// wrong afterwards.
    ///
    /// Never serialized (`skip`), never printed (see the hand-written
    /// `Debug`), and never part of the log's identity (see `PartialEq`):
    /// two chains with the same entries are the same log whoever holds
    /// the pen.
    #[serde(skip)]
    signing_key: Option<SigningKey>,
}

// Hand-written so a signing key can never reach a log line, a panic
// message or a test failure. `SigningKey`'s own `Debug` does redact, but
// relying on a dependency's discretion about our secrets is not a thing
// to do once and then forget.
impl<E: std::fmt::Debug> std::fmt::Debug for Chain<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chain")
            .field("entries", &self.entries)
            .field(
                "signing_key",
                &self.signing_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

// Identity is the entries, and only the entries. A log that was sealed
// and one that was replayed from JSON hold the same history; that the
// first still has the pen in its hand is not part of what it says.
impl<E: PartialEq> PartialEq for Chain<E> {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl<E: Eq> Eq for Chain<E> {}

/// The supervisor's audit log: a [`Chain`] of [`Event`].
pub type AuditLog = Chain<Event>;

// Hand-written rather than derived: a chain of any payload starts empty,
// whether or not the payload itself is `Default`.
impl<E> Default for Chain<E> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            signing_key: None,
        }
    }
}

impl<E: ChainPayload> Chain<E> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            signing_key: None,
        }
    }

    /// Seal every entry appended from here on (lex-os#54).
    ///
    /// Set once by whoever owns the log; after that no `append` call
    /// site can forget. Entries already in the chain are left alone —
    /// re-sealing entries this holder did not write would be vouching
    /// for decisions they did not make, which is the opposite of what a
    /// seal is for.
    ///
    /// Sealing closes "a holder who can edit the log can recompute every
    /// hash in it". It does **not** close truncation; publish a
    /// [`Chain::checkpoint`] somewhere you do not control for that.
    #[must_use]
    pub fn sealed_with(mut self, key: SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Is this chain sealing what it appends?
    pub fn is_sealing(&self) -> bool {
        self.signing_key.is_some()
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
    /// Append an event, chaining it to the current head, sealing it if
    /// this chain was given a key. Returns the new head hash. This is
    /// the only way to grow the log.
    pub fn append(&mut self, event: E) -> String {
        let seq = self.entries.len() as u64;
        let prev_hash = self.head();
        let hash = Entry::compute_hash(seq, &prev_hash, &event);
        let seal = self.signing_key.as_ref().map(|key| {
            let payload = seal_payload::<E>(seq, &hash);
            Seal {
                signer: hex::encode(key.verifying_key().to_bytes()),
                signature: hex::encode(key.sign(&payload).to_bytes()),
            }
        });
        self.entries.push(Entry {
            seq,
            prev_hash,
            event,
            hash: hash.clone(),
            seal,
        });
        hash
    }

    /// Append one entry sealed by a key that is not the chain's own.
    ///
    /// For a caller that seals occasionally rather than throughout;
    /// [`Chain::sealed_with`] is the one to reach for otherwise, because
    /// it removes the chance of forgetting.
    pub fn append_signed(&mut self, event: E, key: &SigningKey) -> String {
        let hash = self.append(event);
        let last = self.entries.last_mut().expect("just appended");
        let payload = seal_payload::<E>(last.seq, &last.hash);
        last.seal = Some(Seal {
            signer: hex::encode(key.verifying_key().to_bytes()),
            signature: hex::encode(key.sign(&payload).to_bytes()),
        });
        hash
    }

    /// How many entries carry a seal.
    ///
    /// Reported rather than inferred: "no entry is sealed" and "some
    /// entries are sealed" are different situations, and only the
    /// second one is a gap.
    pub fn sealed_count(&self) -> usize {
        self.entries.iter().filter(|e| e.seal.is_some()).count()
    }

    /// Verify every entry's seal against a list of keys the caller
    /// trusts.
    ///
    /// Three separate failures, and they are worth keeping apart:
    ///
    /// - an entry with **no seal** — the log has a gap, and a gap in a
    ///   sealed log is where a forged entry goes;
    /// - a seal by a key **not on the list** — somebody signed, but not
    ///   somebody you trust;
    /// - a seal that **does not verify** — the entry was edited after
    ///   signing.
    ///
    /// An empty `trusted` trusts nobody, so a sealed log fails against
    /// it. That is the same rule the rest of the project holds: an empty
    /// allow-list grants nothing, an empty keyring trusts nobody. A
    /// caller who does not want the seal wall does not call this.
    ///
    /// Each seal is checked against the hash **recomputed from the
    /// entry's contents**, not against its stored `hash` field — so an
    /// edited payload fails here even if nobody recomputed the chain.
    ///
    /// It still says nothing about the *sequence*: a log can be
    /// perfectly sealed and have its entries reordered, because a seal
    /// covers one entry rather than the order they arrived in. Call
    /// [`Chain::verify`] as well; the two walls catch different things.
    pub fn verify_seals(&self, trusted: &[VerifyingKey]) -> Result<(), AuditError> {
        for entry in &self.entries {
            let Some(seal) = &entry.seal else {
                return Err(AuditError::Seal {
                    seq: entry.seq,
                    detail: "entry carries no seal, so nobody vouched for it".into(),
                });
            };
            let key = decode_key(&seal.signer).map_err(|e| match e {
                AuditError::Seal { detail, .. } => AuditError::Seal {
                    seq: entry.seq,
                    detail,
                },
                other => other,
            })?;
            if !trusted.contains(&key) {
                return Err(AuditError::Seal {
                    seq: entry.seq,
                    detail: format!(
                        "sealed by {}, which is not among the {} trusted key(s)",
                        seal.signer,
                        trusted.len()
                    ),
                });
            }
            let sig = decode_sig(&seal.signature, entry.seq)?;
            // Against the hash *recomputed from the contents*, never the
            // stored `hash` field. Checking the seal against the stored
            // hash would verify that somebody signed a number sitting
            // next to the payload — which an editor is free to leave
            // alone. This wall has to stand on its own, because the
            // caller who forgets to also call `verify` is the one it
            // exists for.
            let recomputed = Entry::compute_hash(entry.seq, &entry.prev_hash, &entry.event);
            let payload = seal_payload::<E>(entry.seq, &recomputed);
            key.verify(&payload, &sig).map_err(|_| AuditError::Seal {
                seq: entry.seq,
                detail: "seal does not verify against the entry's actual contents".into(),
            })?;
        }
        Ok(())
    }

    /// Commit to this chain's current length and head (lex-os#54).
    ///
    /// Publish the result somewhere the log's holder cannot rewrite.
    /// That is the whole mechanism: a checkpoint kept beside the log it
    /// commits to proves nothing, because whoever truncates one can
    /// replace the other.
    ///
    /// `at` is the caller's own notion of time — this crate reads no
    /// clock. It is signed, so it is worth making something a reader can
    /// check.
    pub fn checkpoint(&self, key: &SigningKey, at: u64) -> Checkpoint {
        let domain = String::from_utf8_lossy(E::DOMAIN).into_owned();
        let len = self.entries.len() as u64;
        let head = self.head();
        let payload = Checkpoint::signing_payload(&domain, len, &head, at);
        Checkpoint {
            domain,
            len,
            head,
            at,
            signer: hex::encode(key.verifying_key().to_bytes()),
            signature: hex::encode(key.sign(&payload).to_bytes()),
        }
    }

    /// Hold this chain to a checkpoint somebody signed earlier.
    ///
    /// **This is the truncation wall**, and the only one there is. Three
    /// things are checked, in the order they matter:
    ///
    /// 1. The checkpoint is for *this* vocabulary. A commitment to a
    ///    Terraform gate's log says nothing about a supervisor's.
    /// 2. The chain is **at least** as long as the checkpoint says. A
    ///    shorter one has lost entries that provably existed — which is
    ///    exactly the attack the bare chain cannot see.
    /// 3. The entry at the checkpointed length still hashes to the
    ///    checkpointed head. A chain that grew from a *different*
    ///    prefix is not this chain, however long it is.
    ///
    /// Takes a [`VerifiedCheckpoint`], so there is no way to reach this
    /// with a commitment whose signature was never checked.
    pub fn verify_against(&self, checkpoint: &VerifiedCheckpoint) -> Result<(), AuditError> {
        let cp = &checkpoint.0;
        let domain = String::from_utf8_lossy(E::DOMAIN);
        if cp.domain != domain {
            return Err(AuditError::Checkpoint {
                detail: format!(
                    "checkpoint commits to a `{}` log; this is a `{domain}` log",
                    cp.domain
                ),
            });
        }
        if (self.entries.len() as u64) < cp.len {
            return Err(AuditError::Checkpoint {
                detail: format!(
                    "chain has {} entries but was checkpointed at {} — {} entr(y/ies) \
                     have been truncated from the tail",
                    self.entries.len(),
                    cp.len,
                    cp.len - self.entries.len() as u64
                ),
            });
        }
        // `.get`, not `[..]`. The length check above already makes this
        // unreachable — but this is verification code reading a document
        // an attacker chose, and code like that must not have a panic in
        // it that a future edit to the guard could expose.
        let head_at_checkpoint = match cp.len.checked_sub(1) {
            None => GENESIS.to_string(),
            Some(i) => match self.entries.get(i as usize) {
                Some(e) => e.hash.clone(),
                None => {
                    return Err(AuditError::Checkpoint {
                        detail: format!(
                            "chain has {} entries but the checkpoint commits to entry {i}",
                            self.entries.len()
                        ),
                    })
                }
            },
        };
        if head_at_checkpoint != cp.head {
            return Err(AuditError::Checkpoint {
                detail: format!(
                    "at entry {} this chain heads at {head_at_checkpoint}, but the \
                     checkpoint committed to {} — this is a different history, not a \
                     shorter one",
                    cp.len, cp.head
                ),
            });
        }
        Ok(())
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
        // A log read back from disk holds no pen: whoever wrote it may
        // have sealed it, but this reader is not that party.
        Ok(Self {
            entries,
            signing_key: None,
        })
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

    // --- Seals and checkpoints (lex-os#54) ---------------------------

    /// Deterministic keys. Generation needs an OS CSPRNG; a test needs
    /// the same key twice.
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sealed_log(k: &SigningKey) -> AuditLog {
        let mut log = AuditLog::new();
        log.append_signed(
            Event::CommandAllowed {
                command: "read report.md".into(),
            },
            k,
        );
        log.append_signed(
            Event::CommandDenied {
                command: "curl evil.com".into(),
                reason: "perimeter".into(),
            },
            k,
        );
        log
    }

    /// Sealing must not change what the chain hashes to, or every log
    /// written before seals existed would stop verifying.
    #[test]
    fn sealing_does_not_disturb_the_hashes() {
        let mut plain = AuditLog::new();
        plain.append(Event::CommandAllowed {
            command: "read report.md".into(),
        });
        let mut sealed = AuditLog::new();
        sealed.append_signed(
            Event::CommandAllowed {
                command: "read report.md".into(),
            },
            &key(1),
        );
        assert_eq!(plain.head(), sealed.head());
        assert_eq!(plain.entries()[0].hash, sealed.entries()[0].hash);
    }

    #[test]
    fn a_seal_verifies_against_its_signer_and_not_another() {
        let k = key(1);
        let log = sealed_log(&k);
        assert_eq!(log.sealed_count(), 2);
        log.verify_seals(&[k.verifying_key()]).expect("its own key");

        // The negative control: a different key must not do.
        assert!(log.verify_seals(&[key(2).verifying_key()]).is_err());
    }

    /// The project-wide rule, in this crate: an empty X is not a
    /// permissive X.
    #[test]
    fn an_empty_trusted_list_trusts_nobody() {
        let log = sealed_log(&key(1));
        assert!(
            log.verify_seals(&[]).is_err(),
            "trusting nobody must reject a perfectly valid seal"
        );
    }

    /// A gap in a sealed log is where a forged entry goes, so a mixed
    /// chain fails rather than passing on the entries that happen to be
    /// signed.
    #[test]
    fn an_unsealed_entry_in_a_sealed_log_is_a_gap() {
        let k = key(1);
        let mut log = sealed_log(&k);
        log.append(Event::CommandAllowed {
            command: "slipped in".into(),
        });
        assert_eq!(log.sealed_count(), 2);
        assert_eq!(log.len(), 3);
        let err = log.verify_seals(&[k.verifying_key()]).unwrap_err();
        assert!(format!("{err}").contains("no seal"), "{err}");
        // ...and the chain itself is still fine, which is the point:
        // these two walls catch different things.
        log.verify().expect("the chain is intact");
    }

    /// Editing a sealed payload trips both walls, for different reasons:
    /// the hash no longer matches the contents, and the seal no longer
    /// matches the hash.
    #[test]
    fn editing_a_sealed_payload_trips_both_walls() {
        let k = key(1);
        let mut log = sealed_log(&k);
        log.entries[1].event = Event::CommandAllowed {
            command: "curl evil.com".into(),
        };
        assert!(log.verify().is_err(), "the chain catches the edit");
        assert!(log.verify_seals(&[k.verifying_key()]).is_err());

        // And the interesting half: a holder who recomputes the hash
        // defeats the chain, and is still stopped by the seal. This is
        // the gap lex-os#54 exists to close.
        log.entries[1].hash =
            Entry::compute_hash(1, &log.entries[1].prev_hash, &log.entries[1].event);
        log.verify()
            .expect("a recomputed chain verifies — the hashes are derived, not signed");
        assert!(
            log.verify_seals(&[k.verifying_key()]).is_err(),
            "the seal is the thing they cannot recompute"
        );
    }

    /// **The truncation wall.** `tail_truncation_is_not_detected` pins
    /// what the bare chain cannot do; this is the thing that can.
    #[test]
    fn a_checkpoint_catches_the_truncation_the_chain_cannot() {
        let k = key(1);
        let signer = k.verifying_key();
        let log = sealed_log(&k);
        let cp = log.checkpoint(&k, 1_757_000_000).verify(&signer).unwrap();

        // The untruncated chain passes — the negative control, without
        // which this test would pass on a function that always failed.
        log.verify_against(&cp)
            .expect("the chain it was taken from");

        let mut truncated = log.clone();
        truncated.entries.pop();
        truncated.verify().expect("a prefix is still a valid chain");
        truncated
            .verify_seals(&[signer])
            .expect("and its remaining seals are still good");

        let err = truncated.verify_against(&cp).unwrap_err();
        assert!(format!("{err}").contains("truncated"), "{err}");
    }

    /// A chain may be *longer* than its checkpoint — that is just a log
    /// that kept going.
    #[test]
    fn a_longer_chain_still_satisfies_an_earlier_checkpoint() {
        let k = key(1);
        let signer = k.verifying_key();
        let mut log = sealed_log(&k);
        let cp = log.checkpoint(&k, 1).verify(&signer).unwrap();
        log.append_signed(
            Event::SessionEnded {
                outcome: "ok".into(),
            },
            &k,
        );
        log.verify_against(&cp).expect("growing is not truncating");
    }

    /// Replacing history rather than shortening it: same length, or
    /// longer, but a different prefix.
    #[test]
    fn a_different_history_is_not_a_shorter_one() {
        let k = key(1);
        let signer = k.verifying_key();
        let log = sealed_log(&k);
        let cp = log.checkpoint(&k, 1).verify(&signer).unwrap();

        let mut rewritten = AuditLog::new();
        rewritten.append_signed(
            Event::CommandAllowed {
                command: "something else entirely".into(),
            },
            &k,
        );
        rewritten.append_signed(
            Event::CommandAllowed {
                command: "and another".into(),
            },
            &k,
        );
        rewritten.verify().expect("it is a well-formed chain");
        rewritten
            .verify_seals(&[signer])
            .expect("and properly sealed");

        let err = rewritten.verify_against(&cp).unwrap_err();
        assert!(format!("{err}").contains("different history"), "{err}");
    }

    /// A checkpoint names the vocabulary it commits to, so a Terraform
    /// gate's commitment can never be presented as a supervisor's.
    #[test]
    fn a_checkpoint_for_another_vocabulary_is_refused() {
        let k = key(1);
        let signer = k.verifying_key();
        let mut foreign: Chain<PlanEvent> = Chain::new();
        foreign.append_signed(
            PlanEvent::PlanRequested {
                artifact_sha256: "abc".into(),
            },
            &k,
        );
        let cp = foreign.checkpoint(&k, 1).verify(&signer).unwrap();

        let log = sealed_log(&k);
        let err = log.verify_against(&cp).unwrap_err();
        assert!(format!("{err}").contains("test.plan.v1"), "{err}");
    }

    #[test]
    fn a_checkpoint_signed_by_someone_else_does_not_verify() {
        let k = key(1);
        let cp = sealed_log(&k).checkpoint(&k, 1);
        assert!(
            cp.verify(&key(2).verifying_key()).is_err(),
            "a checkpoint must be verified against a key the reader chose, not the one it names"
        );
    }

    /// The forgery the `VerifiedCheckpoint` type exists to prevent:
    /// whoever truncates a log would also write the checkpoint that
    /// blesses the truncation.
    #[test]
    fn an_edited_checkpoint_does_not_verify() {
        let k = key(1);
        let signer = k.verifying_key();
        let log = sealed_log(&k);

        let mut forged = log.checkpoint(&k, 1);
        forged.len = 1;
        forged.head = log.entries()[0].hash.clone();
        assert!(
            forged.verify(&signer).is_err(),
            "the signature covers len and head, so editing either voids it"
        );
    }

    /// An entry seal and a checkpoint are both Ed25519 signatures by the
    /// same key. They must not be interchangeable, or a seal harvested
    /// from a log would serve as a commitment to it.
    #[test]
    fn a_seal_and_a_checkpoint_sign_different_bytes() {
        let log = sealed_log(&key(1));
        let entry = &log.entries()[0];
        let seal_bytes = seal_payload::<Event>(entry.seq, &entry.hash);
        let cp_bytes = Checkpoint::signing_payload("lex.os.audit.v1", 1, &entry.hash, 0);
        assert_ne!(seal_bytes, cp_bytes);
    }

    #[test]
    fn a_checkpoint_over_an_empty_chain_commits_to_genesis() {
        let k = key(1);
        let signer = k.verifying_key();
        let empty = AuditLog::new();
        let cp = empty.checkpoint(&k, 0);
        assert_eq!(cp.len, 0);
        assert_eq!(cp.head, GENESIS);
        let cp = cp.verify(&signer).unwrap();
        // Every chain satisfies it, which is correct: committing to
        // nothing constrains nothing.
        empty.verify_against(&cp).expect("empty");
        sealed_log(&k)
            .verify_against(&cp)
            .expect("and any successor");
    }

    /// Old logs have no `seal` field at all, and must keep parsing.
    #[test]
    fn unsealed_json_still_parses_and_sealed_json_roundtrips() {
        let legacy = r#"[{"seq":0,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","event":{"kind":"command_allowed","command":"read report.md"},"hash":"x"}]"#;
        let parsed = AuditLog::from_json(legacy).expect("a log written before seals existed");
        assert!(parsed.entries()[0].seal.is_none());

        let k = key(1);
        let log = sealed_log(&k);
        let round = AuditLog::from_json(&log.to_json().unwrap()).unwrap();
        assert_eq!(round, log);
        round
            .verify_seals(&[k.verifying_key()])
            .expect("seals survive the round trip");
    }

    /// An unsealed log serialises exactly as it did before this
    /// existed — no empty `seal` key.
    #[test]
    fn an_unsealed_entry_writes_no_seal_field() {
        let mut log = AuditLog::new();
        log.append(Event::SessionEnded {
            outcome: "ok".into(),
        });
        assert!(!log.to_json().unwrap().contains("seal"));
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
