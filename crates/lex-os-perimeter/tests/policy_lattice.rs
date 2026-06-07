//! Exhaustive lattice properties for the grant → policy mapping.
//!
//! `SandboxPolicy::from_grant` is the single source of truth that turns a
//! capability [`Grant`] into the kernel-level posture (lex-os#22, the
//! linchpin of the two-enforcement-layer story). The unit tests in
//! `lib.rs` pin specific grants; this file proves the *properties* the
//! whole safety argument rests on, and it does so **exhaustively** rather
//! than by sampling: the canonical grant space is finite and tiny — 7
//! `Level` variants over 3 dimensions = 343 grants — so we can check
//! every grant, and every *pair* of grants (343² ≈ 118k), in milliseconds.
//! Exhaustive beats random when the domain is small enough to enumerate.
//!
//! The three properties (workstream 1, lex-os half of lex-lang#614):
//!
//!  1. **Totality & determinism.** `from_grant` is total (no panic on any
//!     grant) and a pure function of the per-dimension *ranks* — aliases
//!     like `Sandboxed`/`ReadOnly` that share a rank map to one policy.
//!  2. **Monotonicity (the linchpin).** Narrowing a grant never widens the
//!     derived policy, on *any* dimension: if `child ⊑ parent` then
//!     `from_grant(child)` is no more permissive — and no more demanding —
//!     than `from_grant(parent)`.
//!  3. **Mirror agreement.** The perimeter's `permits` check (the
//!     kernel-side mirror of the type check) is itself monotone under
//!     narrowing: a narrower box never authorises an operation a wider box
//!     would refuse.

use lex_os_manifest::{Dimension, Grant, Level};
use lex_os_perimeter::{NetEgress, SandboxPolicy};

/// Every `Level` variant, including the rank-aliases (`Sandboxed`,
/// `Loopback`, `Allowlist`) so the enumeration exercises alias handling.
const ALL_LEVELS: [Level; 7] = [
    Level::None,
    Level::ReadOnly,
    Level::Sandboxed,
    Level::Loopback,
    Level::ReadWrite,
    Level::Allowlist,
    Level::Full,
];

/// Enumerate the entire canonical grant space: 7³ = 343 grants.
fn all_grants() -> Vec<Grant> {
    let mut grants = Vec::with_capacity(7 * 7 * 7);
    for &fs in &ALL_LEVELS {
        for &net in &ALL_LEVELS {
            for &exec in &ALL_LEVELS {
                grants.push(Grant::new(fs, net, exec));
            }
        }
    }
    grants
}

/// Total order rank for a network posture, used to compare policies.
/// Denied (no egress) is the least permissive, Open the most.
fn net_rank(n: NetEgress) -> u8 {
    match n {
        NetEgress::Denied => 0,
        NetEgress::Loopback => 1,
        NetEgress::Allowlist => 2,
        NetEgress::Open => 3,
    }
}

/// `a` is "no more permissive and no more demanding" than `b` —
/// componentwise across every field a policy carries. This is the
/// ordering narrowing must respect: a narrower grant may only move each
/// field down or hold it.
///
/// Note `required_floor` moves the *same* direction as permission: a more
/// powerful grant (e.g. `exec: full`) both grants more and demands a
/// stronger isolation floor, so "≤ on the floor" is the correct
/// non-widening condition here too.
fn policy_leq(a: &SandboxPolicy, b: &SandboxPolicy) -> bool {
    (!a.fs_readable || b.fs_readable)
        && (!a.fs_writable || b.fs_writable)
        && net_rank(a.net_egress) <= net_rank(b.net_egress)
        && (!a.exec_allowed || b.exec_allowed)
        && a.required_floor <= b.required_floor
}

#[test]
fn from_grant_is_total_and_deterministic() {
    for g in all_grants() {
        // Total: never panics for any grant in the space.
        let p1 = SandboxPolicy::from_grant(&g);
        let p2 = SandboxPolicy::from_grant(&g);
        // Deterministic / referentially transparent.
        assert_eq!(p1, p2, "from_grant not deterministic for {g}");
        // Internal coherence: a writable box must also be readable, and
        // an empty egress list is the documented invariant of from_grant
        // (the allowlist is carried only via from_manifest).
        if p1.fs_writable {
            assert!(p1.fs_readable, "writable but not readable for {g}");
        }
        assert!(
            p1.egress.is_empty(),
            "from_grant must not populate egress (got {:?} for {g})",
            p1.egress
        );
    }
}

#[test]
fn from_grant_depends_only_on_ranks() {
    // Aliases that share a rank (Sandboxed/ReadOnly/Loopback at rank 1,
    // Allowlist/ReadWrite at rank 2) must produce identical policies —
    // the mapping reads authority, not spelling.
    for g in all_grants() {
        let key = (g.filesystem.rank(), g.network.rank(), g.exec.rank());
        // Find any other grant with the same rank-triple and assert the
        // policies match.
        for h in all_grants() {
            let hkey = (h.filesystem.rank(), h.network.rank(), h.exec.rank());
            if key == hkey {
                assert_eq!(
                    SandboxPolicy::from_grant(&g),
                    SandboxPolicy::from_grant(&h),
                    "equal-rank grants {g} and {h} produced different policies"
                );
            }
        }
    }
}

#[test]
fn narrowing_never_widens_the_policy() {
    // THE linchpin property. For every ordered pair of grants where the
    // child narrows the parent (child ⊑ parent on the trust lattice), the
    // derived policy must not widen on any dimension.
    let grants = all_grants();
    let mut checked = 0u64;
    for parent in &grants {
        for child in &grants {
            if child.leq(parent) {
                let pp = SandboxPolicy::from_grant(parent);
                let pc = SandboxPolicy::from_grant(child);
                assert!(
                    policy_leq(&pc, &pp),
                    "narrowing widened the policy:\n  parent grant {parent} -> {pp:?}\n  child  grant {child} -> {pc:?}"
                );
                checked += 1;
            }
        }
    }
    // Sanity: we actually exercised a large number of narrowing pairs,
    // not zero (a vacuously-true test would be worthless).
    assert!(checked > 1000, "only {checked} narrowing pairs checked");
}

#[test]
fn perimeter_permits_is_monotone_under_narrowing() {
    // The kernel-side mirror of the type check must itself be monotone: if
    // the child box authorises an operation, the wider parent box must too.
    // Equivalently, narrowing never *unlocks* a capability.
    let grants = all_grants();
    for parent in &grants {
        for child in &grants {
            if !child.leq(parent) {
                continue;
            }
            let pp = SandboxPolicy::from_grant(parent);
            let pc = SandboxPolicy::from_grant(child);
            for dim in Dimension::ALL {
                for required in ALL_LEVELS {
                    if pc.permits(dim, required) {
                        assert!(
                            pp.permits(dim, required),
                            "child {child} permits {dim} ≥ {required} but parent {parent} does not"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn extremes_map_to_extremes() {
    // bottom (deny-all) is the least permissive policy; top (sudo + open
    // internet) the most. Every other grant's policy sits between them.
    let bottom = SandboxPolicy::from_grant(&Grant::bottom());
    let top = SandboxPolicy::from_grant(&Grant::top());

    assert!(!bottom.fs_readable && !bottom.fs_writable);
    assert_eq!(bottom.net_egress, NetEgress::Denied);
    assert!(!bottom.exec_allowed);

    assert!(top.fs_readable && top.fs_writable);
    assert_eq!(top.net_egress, NetEgress::Open);
    assert!(top.exec_allowed);

    for g in all_grants() {
        let p = SandboxPolicy::from_grant(&g);
        assert!(policy_leq(&bottom, &p), "{g}: policy below bottom");
        assert!(policy_leq(&p, &top), "{g}: policy above top");
    }
}
