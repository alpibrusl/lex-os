//! Two things narrowing did not compare, and now does.
//!
//! Both were found by a cold-read participant probing the narrowing API
//! from the outside (lex-os#89, pass 3) after reading the
//! implementation. Neither was caught by the existing suite, and the
//! reason is worth recording: the suite tested each axis it knew about,
//! and these are the two axes nobody had written a test for. A test per
//! known rule cannot find a missing rule.
//!
//! # The port
//!
//! `lex-os-perimeter` parses each egress entry into a host *and a port*
//! and pins an iptables ACCEPT to both, with a bare host meaning 443. So
//! the port is enforced by the kernel. Narrowing stripped the child's
//! port before comparing, and `host_matches` strips the parent's, so it
//! was never compared by anything — a child could keep an authorised
//! host, change `:443` to `:8443`, narrow cleanly, and have the wall
//! open the port it named.
//!
//! # The floor
//!
//! `validate_narrowing_with` compared grant, egress, budgets, actuation
//! and facets. It did not compare `isolation_floor` at all. It is the
//! one axis where "narrower" means a *larger* value — a child may demand
//! a stronger boundary, never a weaker one — which is presumably how it
//! was missed.

use lex_os_manifest::{Budget, Goal, Grant, IsolationFloor, Level, Manifest, ManifestError};

/// `exec: None` on purpose: `with_floor` only ever *raises* the floor —
/// it will not take a manifest below what its grant implies — so a
/// fixture meant to sit at `Namespace` has to be built from a grant that
/// implies `Namespace`. With `exec: Sandboxed` every one of these would
/// silently clamp to `Gvisor` and the floor tests would compare a value
/// against itself.
fn base(floor: IsolationFloor, egress: &[&str]) -> Manifest {
    let m = Manifest::new(
        Goal::new("g"),
        Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
        Budget::research_default(),
    )
    .with_egress(egress.iter().map(|s| s.to_string()).collect())
    .with_floor(floor);
    assert_eq!(
        m.isolation_floor, floor,
        "the fixture must actually sit at the floor it asked for"
    );
    m
}

// ---------------------------------------------------------------- egress

/// The probe as the participant wrote it: keep the authorised host,
/// change the port.
#[test]
fn a_child_may_not_change_the_port_of_an_authorised_host() {
    let parent = base(IsolationFloor::Gvisor, &["alice.opentimestamps.org:443"]);
    let child = base(IsolationFloor::Gvisor, &["alice.opentimestamps.org:8443"]);

    assert!(
        matches!(
            Manifest::validate_narrowing(&parent, &child),
            Err(ManifestError::EgressWidens { .. })
        ),
        "the perimeter opens the port the child names, so changing it widens the grant"
    );
}

#[test]
fn the_same_host_and_port_still_narrows() {
    let parent = base(IsolationFloor::Gvisor, &["a.example:443", "b.example:8443"]);
    let child = base(IsolationFloor::Gvisor, &["b.example:8443"]);
    assert!(Manifest::validate_narrowing(&parent, &child).is_ok());
}

/// A bare host means 443, because that is what the perimeter does with
/// it. The two spellings therefore have to agree in both directions, or
/// narrowing would be checking a different grant than the wall enforces.
#[test]
fn a_bare_host_and_an_explicit_443_are_the_same_entry() {
    let bare = base(IsolationFloor::Gvisor, &["a.example"]);
    let explicit = base(IsolationFloor::Gvisor, &["a.example:443"]);
    assert!(Manifest::validate_narrowing(&bare, &explicit).is_ok());
    assert!(Manifest::validate_narrowing(&explicit, &bare).is_ok());
}

/// ...and a bare parent does not therefore admit any port.
#[test]
fn a_bare_parent_host_does_not_admit_another_port() {
    let parent = base(IsolationFloor::Gvisor, &["postgres.payments.svc"]);
    let child = base(IsolationFloor::Gvisor, &["postgres.payments.svc:5432"]);
    assert!(
        Manifest::validate_narrowing(&parent, &child).is_err(),
        "a bare entry means 443; 5432 is a port the parent never granted"
    );
}

/// The wildcard still works, and still only for the port it was written
/// with — otherwise the fix would have closed one hole by opening it
/// somewhere less obvious.
#[test]
fn a_wildcard_parent_covers_a_subdomain_on_the_same_port_only() {
    let parent = base(IsolationFloor::Gvisor, &["*.internal.example:443"]);
    assert!(Manifest::validate_narrowing(
        &parent,
        &base(IsolationFloor::Gvisor, &["a.internal.example:443"])
    )
    .is_ok());
    assert!(Manifest::validate_narrowing(
        &parent,
        &base(IsolationFloor::Gvisor, &["a.internal.example:8443"])
    )
    .is_err());
}

/// The control. If this ever fails, the tests above are passing because
/// narrowing refuses everything rather than because it compares ports.
#[test]
fn an_entirely_different_host_is_still_refused() {
    let parent = base(IsolationFloor::Gvisor, &["a.example:443"]);
    let child = base(IsolationFloor::Gvisor, &["evil.example:443"]);
    assert!(Manifest::validate_narrowing(&parent, &child).is_err());
}

// ----------------------------------------------------------------- floor

/// The second probe: lower the floor while keeping everything else
/// consistent, so nothing else could be doing the refusing.
#[test]
fn a_child_may_not_lower_the_isolation_floor() {
    let parent = base(IsolationFloor::MicroVm, &["a.example:443"]);
    let child = base(IsolationFloor::Namespace, &["a.example:443"]);

    match Manifest::validate_narrowing(&parent, &child) {
        Err(ManifestError::IsolationWidens { parent, child }) => {
            assert_eq!(parent, "microvm");
            assert_eq!(child, "namespace");
        }
        other => panic!("lowering the floor must be refused, got {other:?}"),
    }
}

/// Every weakening step, not just the extremes — a check that only
/// caught MicroVm→Namespace would still admit MicroVm→Gvisor.
#[test]
fn every_weakening_step_is_refused() {
    use IsolationFloor::*;
    for (p, c) in [(MicroVm, Gvisor), (MicroVm, Namespace), (Gvisor, Namespace)] {
        assert!(
            Manifest::validate_narrowing(
                &base(p, &["a.example:443"]),
                &base(c, &["a.example:443"])
            )
            .is_err(),
            "{p:?} -> {c:?} must be refused"
        );
    }
}

/// Raising it is the narrowing direction and must stay allowed — this is
/// the axis where narrower means a larger value, and getting the
/// comparison backwards would refuse exactly the cautious child.
#[test]
fn a_child_may_raise_the_isolation_floor() {
    use IsolationFloor::*;
    for (p, c) in [(Namespace, Gvisor), (Namespace, MicroVm), (Gvisor, MicroVm)] {
        assert!(
            Manifest::validate_narrowing(
                &base(p, &["a.example:443"]),
                &base(c, &["a.example:443"])
            )
            .is_ok(),
            "{p:?} -> {c:?} is a tightening and must be allowed"
        );
    }
}

#[test]
fn an_equal_floor_narrows() {
    let m = base(IsolationFloor::Gvisor, &["a.example:443"]);
    assert!(Manifest::validate_narrowing(&m, &m).is_ok());
}

/// `narrow_to` derives a child rather than validating a supplied one,
/// and already raises the floor to at least the parent's. Pinned so the
/// two paths cannot come to different answers about the same pair.
#[test]
fn a_derived_child_never_lands_below_its_parent() {
    let parent = base(IsolationFloor::MicroVm, &["a.example:443"]);
    let child = parent
        .narrow_to(
            Grant::new(Level::None, Level::None, Level::None),
            Budget::research_default(),
        )
        .expect("a strictly smaller grant narrows");
    assert!(child.isolation_floor >= parent.isolation_floor);
    assert!(Manifest::validate_narrowing(&parent, &child).is_ok());
}
