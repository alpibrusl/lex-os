//! End-to-end spike (lex-os#34): a signed capsule, installed against a
//! consumer manifest, must produce an effective box that *resolves* against
//! a host and *provisions* a perimeter — and the refusal path must stop
//! before any box is built. This exercises the capsule → resolver →
//! perimeter seam that the library unit tests don't reach.

use lex_os_capsule::{
    signing_key_from_seed, ArtifactRef, CapabilityContract, Capsule, CapsuleError, InstallOptions,
};
use lex_os_manifest::{Budget, Goal, Grant, Level, Manifest};
use lex_os_perimeter::{Perimeter, SandboxPolicy, SimulatedPerimeter};
use lex_os_resolver::{resolve, Environment};

fn consumer() -> Manifest {
    Manifest::new(
        Goal::new("host the weather tool"),
        Grant::new(Level::ReadWrite, Level::Allowlist, Level::None),
        Budget::research_default(),
    )
    .with_egress(vec!["api.weather.example:443".into()])
}

#[test]
fn accepted_capsule_resolves_and_provisions_a_live_box() {
    let key = signing_key_from_seed(&[3u8; 32]);
    let signed = CapabilityContract::new(
        ArtifactRef::new("lex-weather", "1.2.0", "a".repeat(64)),
        Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
    )
    .with_egress(vec!["api.weather.example".into()])
    .sign(&key);

    let installed = Capsule::install(&consumer(), &signed, &InstallOptions::unverified())
        .expect("narrowing capsule installs");

    // The effective manifest must resolve on a full host and provision a box.
    let plan = resolve(&installed.manifest, &Environment::full()).expect("effective box resolves");
    let mut perimeter = SimulatedPerimeter::new();
    perimeter
        .provision(SandboxPolicy::from_manifest(&installed.manifest))
        .expect("effective box provisions");
    assert!(perimeter.is_alive());

    // Least authority reached the kernel-side policy: the box can read but not
    // write, and reach only the one declared host.
    let policy = SandboxPolicy::from_manifest(&installed.manifest);
    assert!(policy.fs_readable);
    assert!(
        !policy.fs_writable,
        "consumer offered read-write; artifact only needed read-only"
    );
    assert!(policy.permits_host("api.weather.example"));
    assert!(!policy.permits_host("telemetry.evil.example"));
    // Floor is never weaker than the consumer required, even though the
    // narrowed grant alone would only imply a namespace.
    assert_eq!(plan.floor, installed.manifest.isolation_floor);
}

#[test]
fn refused_capsule_never_yields_a_box() {
    let key = signing_key_from_seed(&[3u8; 32]);
    // Wants exec the consumer never grants.
    let signed = CapabilityContract::new(
        ArtifactRef::new("lex-evil", "9.9.9", "b".repeat(64)),
        Grant::new(Level::ReadOnly, Level::Allowlist, Level::Full),
    )
    .sign(&key);

    let err = Capsule::install(&consumer(), &signed, &InstallOptions::unverified()).unwrap_err();
    assert!(
        matches!(err, CapsuleError::Refused(_)),
        "overreaching capsule must be refused before any box exists, got {err:?}"
    );
}
