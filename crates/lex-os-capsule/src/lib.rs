//! Capability-addressed distribution (lex-os#34, the first spike).
//!
//! A *capsule* is a distributable artifact (a `lex pkg` package, addressed
//! by its content hash) bound to a **capability contract**: the trust
//! [`Grant`] the artifact declares it needs, plus the network egress hosts
//! it must reach. The contract is signed with Ed25519 by the publisher and
//! verified by the consumer with the publisher's public key.
//!
//! The central design rule (lex-os#34, and the repo invariant "the grant is
//! the whole safety story") is that **the consumer's grant — not the
//! publisher's declaration — is the ceiling.** A contract's declared
//! requirement is a *transparency and matching* aid; it can never widen what
//! the consumer is willing to allow. Two things fall out of that:
//!
//! 1. **Effective grant = `meet(consumer, requires)`.** The box runs at the
//!    greatest authority *both* sides allow — least authority, never the
//!    consumer's full grant. (See [`Capsule::install`].)
//! 2. **Refuse, don't downgrade.** If the artifact declares it needs more
//!    authority than the consumer grants on *any* dimension (grant or
//!    egress), installation is refused with a structured error rather than
//!    silently clamped. This reuses the tested narrowing invariant
//!    [`Manifest::validate_narrowing`] — installing a capsule *is* a
//!    narrowing of the consumer's manifest.
//!
//! This crate is the pure-logic half. Resolving the effective manifest
//! against a host and provisioning a perimeter lives in the `lex-os` CLI's
//! `capsule` subcommand (which drives the `SimulatedPerimeter`).
//!
//! ## Scope of the spike
//!
//! Deliberately *not* solved here (open questions on lex-os#34): the
//! rootfs/layer model that maps the package bytes to the box the perimeter
//! boots; where the signed contract lives relative to the attestation graph;
//! and how a consumer decides a *signer* is trustworthy (this crate verifies
//! that a signature is valid for a given key, not that the key is trusted).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use lex_os_manifest::{Grant, Manifest, ManifestError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator mixed into the signed payload and the content id, so a
/// contract signature can never be confused with a signature over any other
/// lex-os structure (manifest, grant, audit entry).
const CONTRACT_DOMAIN: &[u8] = b"lex.os.capsule.contract.v1";

/// A handle to the distributable bits: a `lex pkg` artifact identified by
/// name, version, and the content hash of its published archive. The hash is
/// authoritative — name/version are for humans and discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub name: String,
    pub version: String,
    /// Hex SHA-256 of the published package archive (the `lex pkg publish`
    /// content address). The signature binds the contract to *these* bytes.
    pub content_hash: String,
}

impl ArtifactRef {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        content_hash: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            content_hash: content_hash.into(),
        }
    }
}

/// The capability envelope an artifact declares it needs to run as intended:
/// the trust [`Grant`] and the network egress allowlist. This is a *declared
/// requirement*, bound to a specific artifact, never a grant of authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityContract {
    pub artifact: ArtifactRef,
    /// The grant the artifact needs. At install time this is checked to
    /// *narrow* the consumer's grant (refuse, don't downgrade).
    pub requires: Grant,
    /// Network hosts the artifact must reach (`host` or `host:port`, with a
    /// leading `*.` wildcard). Must be a subset of the consumer's egress.
    #[serde(default)]
    pub egress: Vec<String>,
}

/// Content address of a [`CapabilityContract`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractId(pub String);

impl ContractId {
    pub fn short(&self) -> &str {
        &self.0[..self.0.len().min(12)]
    }
}

impl std::fmt::Display for ContractId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "contract:{}", self.short())
    }
}

impl CapabilityContract {
    pub fn new(artifact: ArtifactRef, requires: Grant) -> Self {
        Self {
            artifact,
            requires,
            egress: Vec::new(),
        }
    }

    pub fn with_egress(mut self, hosts: Vec<String>) -> Self {
        self.egress = hosts;
        self
    }

    /// Canonical JSON used for hashing and signing. Field order is fixed,
    /// the grant is encoded by *rank* (so `Sandboxed`/`ReadOnly` aliases
    /// address identically, matching [`Grant::content_id`]), and egress is
    /// sorted — so the bytes are reproducible across processes and languages.
    pub fn canonical_json(&self) -> String {
        let mut egress = self.egress.clone();
        egress.sort();
        let v = serde_json::json!({
            "artifact": {
                "name": self.artifact.name,
                "version": self.artifact.version,
                "content_hash": self.artifact.content_hash,
            },
            "requires": {
                "filesystem": self.requires.filesystem.rank(),
                "network": self.requires.network.rank(),
                "exec": self.requires.exec.rank(),
            },
            "egress": egress,
        });
        serde_json::to_string(&v).expect("contract json is always serializable")
    }

    /// The exact bytes that get signed and verified: the domain separator
    /// followed by the canonical JSON. Exposed so callers can sign with an
    /// external key manager if they don't hold the [`SigningKey`] directly.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(CONTRACT_DOMAIN.len() + 1);
        payload.extend_from_slice(CONTRACT_DOMAIN);
        payload.push(b'\0');
        payload.extend_from_slice(self.canonical_json().as_bytes());
        payload
    }

    /// Content address of the contract — SHA-256 over the same canonical
    /// form (independent of who signed it).
    pub fn content_id(&self) -> ContractId {
        let mut hasher = Sha256::new();
        hasher.update(CONTRACT_DOMAIN);
        hasher.update(self.canonical_json().as_bytes());
        ContractId(hex::encode(hasher.finalize()))
    }

    /// Sign this contract with `key`, producing a [`SignedContract`] the
    /// consumer can verify with the corresponding public key.
    pub fn sign(self, key: &SigningKey) -> SignedContract {
        let signature = key.sign(&self.signing_payload());
        SignedContract {
            signer: hex::encode(key.verifying_key().to_bytes()),
            signature: hex::encode(signature.to_bytes()),
            contract: self,
        }
    }

    /// SHA-256 of an artifact archive as lowercase hex — the value the
    /// [`ArtifactRef::content_hash`] field is expected to hold. Use it to
    /// compute the hash at publish time (`capsule sign --artifact-file`).
    pub fn hash_artifact_bytes(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Check that `bytes` are the artifact this contract was signed over:
    /// their SHA-256 must equal `artifact.content_hash`. This closes the loop
    /// the signature only *promises* — the signature binds the contract (and
    /// thus the declared hash) to the publisher, but nothing forces the bytes
    /// you actually run to match that hash unless you call this.
    pub fn matches_artifact(&self, bytes: &[u8]) -> Result<(), CapsuleError> {
        let actual = Self::hash_artifact_bytes(bytes);
        if actual.eq_ignore_ascii_case(&self.artifact.content_hash) {
            Ok(())
        } else {
            Err(CapsuleError::ArtifactHashMismatch {
                expected: self.artifact.content_hash.clone(),
                actual,
            })
        }
    }
}

/// A capability contract plus the publisher's Ed25519 signature over its
/// canonical bytes. This is the unit that travels with (or alongside) a
/// distributed artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContract {
    pub contract: CapabilityContract,
    /// Hex-encoded Ed25519 public key (32 bytes) of the signer.
    pub signer: String,
    /// Hex-encoded Ed25519 signature (64 bytes) over [`signing_payload`].
    ///
    /// [`signing_payload`]: CapabilityContract::signing_payload
    pub signature: String,
}

impl SignedContract {
    /// Verify the signature binds *this* contract to the declared signer
    /// key. Returns the verified [`VerifyingKey`] on success so the caller
    /// can decide, separately, whether that *key* is trusted — see
    /// [`Keyring`] for the trusted-signer policy.
    pub fn verify(&self) -> Result<VerifyingKey, CapsuleError> {
        let key_bytes: [u8; 32] = decode_fixed(&self.signer, "signer public key")?;
        let sig_bytes: [u8; 64] = decode_fixed(&self.signature, "signature")?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| CapsuleError::MalformedKey)?;
        let signature = Signature::from_bytes(&sig_bytes);
        key.verify(&self.contract.signing_payload(), &signature)
            .map_err(|_| CapsuleError::SignatureInvalid)?;
        Ok(key)
    }

    pub fn to_json(&self) -> Result<String, CapsuleError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(s: &str) -> Result<SignedContract, CapsuleError> {
        Ok(serde_json::from_str(s)?)
    }
}

/// A consumer's set of trusted publisher public keys (hex Ed25519). A valid
/// signature proves *who* signed a contract; the keyring decides whether that
/// signer is *allowed*. Without one, any valid signature is accepted —
/// trust-on-first-use, which the CLI warns about.
///
/// This is deliberately the simplest trust policy: an explicit allowlist of
/// keys. Earning trust from a publisher's track record (tying the signer into
/// lex-lang's `ProducerTrust` attestation scoring) is the richer follow-up on
/// lex-os#34; a keyring is the floor under it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    /// Trusted signer public keys, hex-encoded (32-byte Ed25519).
    pub trusted: Vec<String>,
}

impl Keyring {
    pub fn new(keys: impl IntoIterator<Item = String>) -> Self {
        Self {
            trusted: keys.into_iter().collect(),
        }
    }

    /// Is `key` trusted? Compared by canonical hex, case-insensitively.
    pub fn trusts(&self, key: &VerifyingKey) -> bool {
        let hex_key = hex::encode(key.to_bytes());
        self.trusted
            .iter()
            .any(|k| k.eq_ignore_ascii_case(&hex_key))
    }

    pub fn from_json(s: &str) -> Result<Keyring, CapsuleError> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn to_json(&self) -> Result<String, CapsuleError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Options narrowing how a capsule is installed: optional artifact-byte
/// integrity and an optional trusted-signer keyring. Both default to *off*
/// (unverified bytes, trust-on-first-use) so [`Capsule::install`] stays the
/// simplest call; the CLI surfaces both and warns when either is skipped.
#[derive(Default)]
pub struct InstallOptions<'a> {
    /// The artifact archive bytes. When present, their SHA-256 must equal the
    /// contract's `content_hash` or install is refused.
    pub artifact_bytes: Option<&'a [u8]>,
    /// Trusted publisher keyring. When present, the verified signer must be in
    /// it or install is refused.
    pub keyring: Option<&'a Keyring>,
}

/// The result of installing a capsule against a consumer manifest: the
/// effective box to provision, plus provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledCapsule {
    pub artifact: ArtifactRef,
    /// The verified signer's public key (hex). The caller still decides
    /// whether to trust this key.
    pub signer: String,
    /// The grant the box will actually run at — `meet(consumer, requires)`,
    /// which equals `requires` on the accepted path (always ≤ the consumer
    /// grant).
    pub effective_grant: Grant,
    /// The manifest to hand to the resolver/perimeter: the consumer's
    /// manifest narrowed to the artifact's least authority and egress.
    pub manifest: Manifest,
}

/// Why a capsule could not be installed. Authenticity failures and
/// capability-widening failures are kept distinct so the CLI can map them to
/// different exit codes and an audit reason.
#[derive(Debug, thiserror::Error)]
pub enum CapsuleError {
    #[error("contract signature is invalid for the declared signer key")]
    SignatureInvalid,
    #[error("signer public key is not a valid Ed25519 key")]
    MalformedKey,
    #[error("malformed {field}: expected {expected} hex bytes")]
    BadHex {
        field: &'static str,
        expected: usize,
    },
    /// The supplied artifact bytes are not the ones the contract was signed
    /// over — a substituted or corrupted archive.
    #[error(
        "artifact bytes do not match the contract: content_hash is {expected} but the supplied bytes hash to {actual}"
    )]
    ArtifactHashMismatch { expected: String, actual: String },
    /// The signature is valid, but the signer is not in the consumer's
    /// trusted keyring — a real but unauthorized publisher.
    #[error("signer {signer} is not in the consumer's trusted keyring")]
    UntrustedSigner { signer: String },
    /// The artifact declared it needs more authority than the consumer
    /// grants. Refuse, don't downgrade: the wrapped [`ManifestError`] names
    /// the exact widening (a grant dimension, an egress host, …).
    #[error("capsule refused: artifact requires more than the consumer grants — {0}")]
    Refused(#[source] ManifestError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("failed to (de)serialize a capsule structure: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Decode a hex string into a fixed-size byte array, mapping the size/hex
/// failure to a typed [`CapsuleError::BadHex`].
fn decode_fixed<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], CapsuleError> {
    let bytes = hex::decode(s).map_err(|_| CapsuleError::BadHex { field, expected: N })?;
    bytes
        .try_into()
        .map_err(|_| CapsuleError::BadHex { field, expected: N })
}

/// The installation entry point: bind a signed capsule to a consumer's
/// manifest, or refuse.
pub struct Capsule;

impl Capsule {
    /// Install `signed` against `consumer` with default options (unverified
    /// artifact bytes, trust-on-first-use). See [`Capsule::install_with`] for
    /// the full gate set; this is the simplest call.
    pub fn install(
        consumer: &Manifest,
        signed: &SignedContract,
    ) -> Result<InstalledCapsule, CapsuleError> {
        Self::install_with(consumer, signed, &InstallOptions::default())
    }

    /// Install `signed` against `consumer`, producing the effective box to
    /// provision. Gates, in order — each a hard refusal, never a silent
    /// downgrade:
    ///
    /// 1. **Authenticity.** The signature must verify for the declared key.
    /// 2. **Authorization.** If `opts.keyring` is set, the verified signer
    ///    must be in it ([`CapsuleError::UntrustedSigner`]).
    /// 3. **Integrity.** If `opts.artifact_bytes` is set, their SHA-256 must
    ///    equal the contract's `content_hash`
    ///    ([`CapsuleError::ArtifactHashMismatch`]) — the bytes you run are the
    ///    bytes that were signed.
    /// 4. **Refuse, don't downgrade.** The artifact's declared requirement
    ///    must *narrow* the consumer's manifest on every dimension (grant +
    ///    egress). Any widening is [`CapsuleError::Refused`]. Budgets stay the
    ///    consumer's ceiling.
    /// 5. **Least authority.** The effective grant is
    ///    `meet(consumer, requires)` (== `requires` here, always ≤ consumer),
    ///    and egress is the artifact's declared subset — the box gets only
    ///    what the artifact said it needs, never the consumer's full grant.
    pub fn install_with(
        consumer: &Manifest,
        signed: &SignedContract,
        opts: &InstallOptions<'_>,
    ) -> Result<InstalledCapsule, CapsuleError> {
        // (1) Authenticity first — never reason about an unverified contract.
        let key = signed.verify()?;
        let contract = &signed.contract;

        // (2) Authorization: is this publisher trusted at all? Checked before
        //     any capability reasoning, so an untrusted signer is refused even
        //     when its declared grant would fit.
        if let Some(keyring) = opts.keyring {
            if !keyring.trusts(&key) {
                return Err(CapsuleError::UntrustedSigner {
                    signer: hex::encode(key.to_bytes()),
                });
            }
        }

        // (3) Integrity: are these the bytes that were signed? Closes the loop
        //     the signature only promised about `content_hash`.
        if let Some(bytes) = opts.artifact_bytes {
            contract.matches_artifact(bytes)?;
        }

        // (4) Refuse, don't downgrade. Model the artifact's ask as a child
        //     manifest (its required grant + egress, the consumer's budget so
        //     budgets trivially pass) and demand it narrows the consumer.
        //     This reuses the tested narrowing invariant verbatim.
        let requested = Manifest::new(consumer.goal.clone(), contract.requires, consumer.budget)
            .with_egress(contract.egress.clone());
        Manifest::validate_narrowing(consumer, &requested).map_err(CapsuleError::Refused)?;

        // (5) Effective grant, stated as the design's rule literally. Because
        //     step (4) proved `requires ≤ consumer`, the meet equals
        //     `requires`; we assert that so the two formulations can never
        //     silently diverge.
        let effective_grant = consumer.grant.meet(&contract.requires);
        debug_assert_eq!(
            effective_grant, contract.requires,
            "meet must equal the requirement once narrowing is proven"
        );

        // Build the box: consumer manifest narrowed to least authority, with
        // egress restricted to exactly what the artifact declared it needs.
        let mut manifest = consumer.narrow_to(effective_grant, consumer.budget)?;
        manifest.egress = contract.egress.clone();

        Ok(InstalledCapsule {
            artifact: contract.artifact.clone(),
            signer: hex::encode(key.to_bytes()),
            effective_grant,
            manifest,
        })
    }
}

/// Generate a fresh Ed25519 signing key from the OS CSPRNG. Convenience for
/// the CLI `capsule keygen`; production keys belong in a key manager.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand_core::OsRng)
}

/// Deterministically derive a signing key from a 32-byte seed. Used by the
/// CLI's `--seed` flag and tests so demos are reproducible.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{Budget, Goal, Level};

    fn artifact() -> ArtifactRef {
        ArtifactRef::new("lex-weather", "1.2.0", "a".repeat(64))
    }

    /// A consumer willing to allow read-write fs and one egress host, no exec.
    fn consumer() -> Manifest {
        Manifest::new(
            Goal::new("install and run the weather tool"),
            Grant::new(Level::ReadWrite, Level::Allowlist, Level::None),
            Budget::research_default(),
        )
        .with_egress(vec![
            "api.weather.example:443".into(),
            "*.cdn.example".into(),
        ])
    }

    fn key() -> SigningKey {
        signing_key_from_seed(&[7u8; 32])
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let signed = CapabilityContract::new(
            artifact(),
            Grant::new(Level::ReadOnly, Level::None, Level::None),
        )
        .sign(&key());
        let vk = signed.verify().expect("freshly signed contract verifies");
        assert_eq!(vk.to_bytes(), key().verifying_key().to_bytes());
        // Survives a JSON roundtrip (how it travels with the artifact).
        let back = SignedContract::from_json(&signed.to_json().unwrap()).unwrap();
        assert!(back.verify().is_ok());
        assert_eq!(back, signed);
    }

    #[test]
    fn tampering_with_the_contract_breaks_the_signature() {
        let mut signed = CapabilityContract::new(
            artifact(),
            Grant::new(Level::ReadOnly, Level::None, Level::None),
        )
        .sign(&key());
        // Attacker escalates the declared requirement after signing.
        signed.contract.requires = Grant::top();
        assert!(matches!(
            signed.verify().unwrap_err(),
            CapsuleError::SignatureInvalid
        ));
    }

    #[test]
    fn install_accepts_a_narrowing_artifact() {
        // Artifact needs only read-only fs + the one weather host — well
        // within what the consumer grants.
        let signed = CapabilityContract::new(
            artifact(),
            Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
        )
        .with_egress(vec!["api.weather.example".into()])
        .sign(&key());

        let installed =
            Capsule::install(&consumer(), &signed).expect("narrowing artifact installs");
        // Effective grant is the artifact's least authority, ≤ consumer.
        assert_eq!(
            installed.effective_grant,
            Grant::new(Level::ReadOnly, Level::Allowlist, Level::None)
        );
        assert!(installed.effective_grant.leq(&consumer().grant));
        // Egress narrowed to exactly what the artifact asked for.
        assert_eq!(
            installed.manifest.egress,
            vec!["api.weather.example".to_string()]
        );
    }

    #[test]
    fn install_refuses_when_artifact_wants_more_grant() {
        // Artifact declares it needs exec — the consumer grants none.
        let signed = CapabilityContract::new(
            artifact(),
            Grant::new(Level::ReadOnly, Level::None, Level::Full),
        )
        .sign(&key());
        let err = Capsule::install(&consumer(), &signed).unwrap_err();
        assert!(
            matches!(err, CapsuleError::Refused(ManifestError::Trust(_))),
            "expected a refusal naming the exec widening, got {err:?}"
        );
    }

    #[test]
    fn install_refuses_when_artifact_wants_an_unlisted_host() {
        // Grant fits, but the artifact wants a host the consumer never allowed.
        let signed = CapabilityContract::new(
            artifact(),
            Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
        )
        .with_egress(vec!["telemetry.evil.example".into()])
        .sign(&key());
        let err = Capsule::install(&consumer(), &signed).unwrap_err();
        assert!(
            matches!(
                err,
                CapsuleError::Refused(ManifestError::EgressWidens { .. })
            ),
            "expected an egress refusal, got {err:?}"
        );
    }

    #[test]
    fn install_rejects_an_invalid_signature_before_any_capability_check() {
        // A contract that *would* install fine, but signed by a different
        // key than it claims — authenticity must fail first.
        let honest = CapabilityContract::new(
            artifact(),
            Grant::new(Level::ReadOnly, Level::None, Level::None),
        )
        .sign(&key());
        let mut forged = honest.clone();
        // Claim a different signer than the one that actually signed.
        forged.signer = hex::encode(signing_key_from_seed(&[9u8; 32]).verifying_key().to_bytes());
        assert!(matches!(
            Capsule::install(&consumer(), &forged).unwrap_err(),
            CapsuleError::SignatureInvalid
        ));
    }

    #[test]
    fn contract_id_is_stable_and_alias_insensitive() {
        // exec=Sandboxed and exec=ReadOnly share a rank, so contracts that
        // differ only by that alias address identically (matches GrantId).
        let c1 = CapabilityContract::new(
            artifact(),
            Grant::new(Level::None, Level::None, Level::Sandboxed),
        );
        let c2 = CapabilityContract::new(
            artifact(),
            Grant::new(Level::None, Level::None, Level::ReadOnly),
        );
        assert_eq!(c1.content_id(), c2.content_id());
        assert_eq!(c1.content_id().0.len(), 64);
    }

    #[test]
    fn artifact_hash_matches_real_bytes_and_rejects_substitution() {
        let bytes = b"the published pdf-extract archive";
        let hash = CapabilityContract::hash_artifact_bytes(bytes);
        let contract = CapabilityContract::new(
            ArtifactRef::new("pdf-extract", "2.0.0", hash),
            Grant::new(Level::ReadOnly, Level::None, Level::None),
        );
        // The genuine bytes match.
        assert!(contract.matches_artifact(bytes).is_ok());
        // A substituted archive (even one byte off) is rejected.
        assert!(matches!(
            contract
                .matches_artifact(b"a different archive")
                .unwrap_err(),
            CapsuleError::ArtifactHashMismatch { .. }
        ));
    }

    #[test]
    fn install_with_bytes_refuses_a_substituted_artifact() {
        let real = b"genuine bytes";
        let signed = CapabilityContract::new(
            ArtifactRef::new(
                "pdf-extract",
                "2.0.0",
                CapabilityContract::hash_artifact_bytes(real),
            ),
            Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
        )
        .with_egress(vec!["api.weather.example".into()])
        .sign(&key());

        // Right bytes install; wrong bytes are refused even though the
        // signature and the capability are both fine.
        let ok = InstallOptions {
            artifact_bytes: Some(real),
            keyring: None,
        };
        assert!(Capsule::install_with(&consumer(), &signed, &ok).is_ok());
        let tampered = InstallOptions {
            artifact_bytes: Some(b"swapped payload"),
            keyring: None,
        };
        assert!(matches!(
            Capsule::install_with(&consumer(), &signed, &tampered).unwrap_err(),
            CapsuleError::ArtifactHashMismatch { .. }
        ));
    }

    #[test]
    fn keyring_gates_unknown_publishers() {
        let signed = CapabilityContract::new(
            artifact(),
            Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
        )
        .with_egress(vec!["api.weather.example".into()])
        .sign(&key());
        let signer_hex = hex::encode(key().verifying_key().to_bytes());

        // A keyring that trusts the signer: install proceeds.
        let trusting = Keyring::new([signer_hex]);
        let ok = InstallOptions {
            artifact_bytes: None,
            keyring: Some(&trusting),
        };
        assert!(Capsule::install_with(&consumer(), &signed, &ok).is_ok());

        // A keyring that trusts only some *other* key: refused as untrusted,
        // even though the signature is valid and the capability would fit.
        let other = hex::encode(signing_key_from_seed(&[1u8; 32]).verifying_key().to_bytes());
        let stranger = Keyring::new([other]);
        let no = InstallOptions {
            artifact_bytes: None,
            keyring: Some(&stranger),
        };
        assert!(matches!(
            Capsule::install_with(&consumer(), &signed, &no).unwrap_err(),
            CapsuleError::UntrustedSigner { .. }
        ));
    }

    #[test]
    fn keyring_roundtrips_through_json() {
        let kr = Keyring::new(["aa".repeat(32), "bb".repeat(32)]);
        let back = Keyring::from_json(&kr.to_json().unwrap()).unwrap();
        assert_eq!(kr, back);
    }

    #[test]
    fn effective_grant_is_least_authority_not_consumer_full() {
        // Consumer is generous (read-write, allowlist net); artifact only
        // needs read-only + no net. The box must run at the artifact's
        // minimum, NOT the consumer's full grant.
        let signed = CapabilityContract::new(
            artifact(),
            Grant::new(Level::ReadOnly, Level::None, Level::None),
        )
        .sign(&key());
        let installed = Capsule::install(&consumer(), &signed).unwrap();
        assert_eq!(
            installed.effective_grant,
            Grant::new(Level::ReadOnly, Level::None, Level::None)
        );
        assert_ne!(installed.effective_grant, consumer().grant);
    }
}
