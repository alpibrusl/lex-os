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

use serde::{Deserialize, Serialize};
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
    /// The session reached a terminal state.
    SessionEnded { outcome: String },
}

/// One link in the chain: a sequence number, the previous entry's hash,
/// the event, and this entry's own hash over all of the above.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub prev_hash: String,
    pub event: Event,
    pub hash: String,
}

impl Entry {
    /// Recompute the hash this entry *should* have from its contents.
    /// Hashing the canonical JSON of the event keeps it stable.
    fn compute_hash(seq: u64, prev_hash: &str, event: &Event) -> String {
        let event_json = serde_json::to_string(event).expect("event is serializable");
        let mut hasher = Sha256::new();
        hasher.update(b"lex.os.audit.v1");
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditLog {
    entries: Vec<Entry>,
}

impl AuditLog {
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

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Append an event, chaining it to the current head. Returns the new
    /// head hash. This is the only way to grow the log.
    pub fn append(&mut self, event: Event) -> String {
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
    /// stored hash matches a fresh recomputation. Any tampering — an
    /// edited payload, a removed or reordered entry — is detected here.
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

    pub fn from_json(s: &str) -> Result<Self, AuditError> {
        let entries: Vec<Entry> = serde_json::from_str(s)?;
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
