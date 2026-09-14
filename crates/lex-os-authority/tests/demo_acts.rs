//! The three acts of `demo/authority` as assertions.
//!
//! The demo's whole value is that a stranger can run it and see the
//! verdicts for themselves, which makes a demo that has quietly drifted
//! worse than no demo. These tests read the *same files* the runbook
//! runs, so a change to either one that breaks the story fails CI.

use lex_os_authority::{derive, diff, gate, narrow_manifest, Verdict};
use lex_os_manifest::Manifest;
use lex_types::trust::Level;

const V1: &str = include_str!("../../../demo/authority/v1_approved.lex");
const V2: &str = include_str!("../../../demo/authority/v2_agent_improved.lex");
const V3: &str = include_str!("../../../demo/authority/v3_narrowed.lex");
const MANIFEST: &str = include_str!("../../../demo/authority/manifest.json");

fn manifest() -> Manifest {
    Manifest::from_json(MANIFEST).expect("demo manifest parses")
}

#[test]
fn act_1_the_approved_version_fits_and_the_over_grant_is_named() {
    let m = manifest();
    let (v1, _) = derive(V1).expect("v1 derives");
    let report = gate(&m.grant, &m.egress, &v1);
    assert!(report.allowed, "v1 should fit its own manifest");
    // filesystem `full` and exec `full` are authority the code never uses.
    let shed: Vec<_> = report
        .slack
        .dimensions
        .iter()
        .map(|d| (d.dimension.as_str(), d.to))
        .collect();
    assert!(shed.contains(&("filesystem", Level::None)));
    assert!(shed.contains(&("exec", Level::None)));
}

#[test]
fn act_2_the_agents_improvement_is_a_widening_and_is_refused() {
    let m = manifest();
    let (v1, _) = derive(V1).expect("v1 derives");
    let (v2, _) = derive(V2).expect("v2 derives");

    // The coarse grant is *identical* — this is the point of the act.
    // A grant-only review would see nothing here.
    assert_eq!(v1.grant, v2.grant);
    assert_eq!(v1.grant_id(), v2.grant_id());

    let delta = diff(&v1, &v2);
    assert_eq!(delta.verdict, Verdict::Widening);
    assert_eq!(
        delta.egress_added,
        vec!["telemetry.vendor.example".to_string()]
    );
    assert_eq!(delta.off_lattice_added, vec!["env".to_string()]);

    // And the box refuses it before it runs.
    let report = gate(&m.grant, &m.egress, &v2);
    assert!(!report.allowed);
    assert!(report
        .violations
        .iter()
        .any(|v| v.contains("telemetry.vendor.example")));
}

#[test]
fn act_3_the_fix_narrows_and_the_box_narrows_with_it() {
    let m = manifest();
    let (v1, _) = derive(V1).expect("v1 derives");
    let (v3, _) = derive(V3).expect("v3 derives");

    let delta = diff(&v1, &v3);
    assert_eq!(delta.verdict, Verdict::Narrowing);
    assert_eq!(
        delta.egress_removed,
        vec!["results.demo.internal".to_string()]
    );

    let narrowed = narrow_manifest(&m, &v3).expect("narrows");
    assert_eq!(narrowed.grant.network, Level::None);
    assert_eq!(narrowed.grant.filesystem, Level::None);
    assert_eq!(narrowed.grant.exec, Level::None);
    assert!(narrowed.egress.is_empty());

    // The narrowed box is a real narrowing: the old code no longer fits it.
    assert!(!gate(&narrowed.grant, &narrowed.egress, &v1).allowed);
    assert!(gate(&narrowed.grant, &narrowed.egress, &v3).allowed);

    // And it is still a manifest — it round-trips, so the supervisor can
    // derive a perimeter from it like any other.
    let text = serde_json::to_string(&narrowed).expect("serialises");
    assert_eq!(
        Manifest::from_json(&text).expect("round-trips").grant,
        narrowed.grant
    );
}
