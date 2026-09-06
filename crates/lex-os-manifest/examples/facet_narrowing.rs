//! Manifest facets, end to end (lex-os#66).
//!
//! An owner grants a robot a workspace box, a force ceiling and two
//! skills. A child manifest — a sub-task the agent dispatches for itself
//! — may tighten any of that and may widen none of it.
//!
//! Run it:
//!
//! ```sh
//! cargo run -p lex-os-manifest --example facet_narrowing
//! ```

use std::collections::BTreeMap;

use lex_os_manifest::{
    facet, Actuation, ActuatorArm, ActuatorGripper, Budget, Facet, Goal, Grant, Level, Manifest,
    Range,
};

/// The owner's grant: one arm reaching 0.5 m, capped at 15 N.
fn parent_actuation() -> Actuation {
    Actuation {
        skills: vec!["move_to".into(), "grasp".into()],
        arms: BTreeMap::from([(
            "arm".to_string(),
            ActuatorArm {
                workspace_m: [
                    Range { min: 0.0, max: 0.5 },
                    Range {
                        min: -0.3,
                        max: 0.3,
                    },
                    Range { min: 0.0, max: 0.4 },
                ],
                max_velocity_mps: 0.25,
                max_force_n: 15.0,
            },
        )]),
        grippers: BTreeMap::from([(
            "gripper".to_string(),
            ActuatorGripper {
                max_grip_force_n: 20.0,
            },
        )]),
        bases: BTreeMap::new(),
    }
}

fn base_manifest() -> Manifest {
    Manifest::new(
        Goal::new("tidy the bench"),
        Grant::new(Level::ReadOnly, Level::None, Level::None),
        Budget::research_default(),
    )
}

/// Print the verdict for one child, so accept and refuse read the same way.
fn verdict(label: &str, result: Result<(), impl std::fmt::Display>) {
    match result {
        Ok(()) => println!("  ACCEPT  {label}"),
        Err(e) => println!("  REFUSE  {label}\n          → {e}"),
    }
}

fn main() {
    let parent = Manifest {
        actuation: Some(parent_actuation()),
        ..base_manifest()
    };

    println!("parent grants: arm reach x≤0.5 m, ≤0.25 m/s, ≤15 N; gripper ≤20 N; skills [move_to, grasp]");
    println!("manifest id:   {}\n", parent.content_id());

    println!("A child may tighten anything:");

    let mut tighter = parent_actuation();
    tighter.skills = vec!["move_to".into()]; // dropped grasp
    tighter.arms.get_mut("arm").unwrap().max_force_n = 5.0;
    tighter.arms.get_mut("arm").unwrap().workspace_m[0] = Range { min: 0.1, max: 0.3 };
    verdict(
        "drops `grasp`, force 15 N → 5 N, reach 0.5 m → 0.3 m",
        Actuation::validate_narrowing(&parent_actuation(), &tighter),
    );

    let mut dropped = parent_actuation();
    dropped.grippers.clear();
    verdict(
        "drops the gripper entirely",
        Actuation::validate_narrowing(&parent_actuation(), &dropped),
    );

    println!("\nAnd may widen nothing:");

    let mut stronger = parent_actuation();
    stronger.arms.get_mut("arm").unwrap().max_force_n = 450.0;
    verdict(
        "raises the arm's force ceiling to 450 N",
        Actuation::validate_narrowing(&parent_actuation(), &stronger),
    );

    let mut farther = parent_actuation();
    farther.arms.get_mut("arm").unwrap().workspace_m[0] = Range { min: 0.0, max: 2.0 };
    verdict(
        "reaches 2.0 m, outside the granted box",
        Actuation::validate_narrowing(&parent_actuation(), &farther),
    );

    let mut extra_skill = parent_actuation();
    extra_skill.skills.push("open_door".into());
    verdict(
        "claims the skill `open_door`",
        Actuation::validate_narrowing(&parent_actuation(), &extra_skill),
    );

    let mut second_arm = parent_actuation();
    let arm = second_arm.arms["arm"];
    second_arm.arms.insert("second".into(), arm);
    verdict(
        "invents a second arm",
        Actuation::validate_narrowing(&parent_actuation(), &second_arm),
    );

    // NaN compares false against everything, so a naive `child > parent`
    // check would wave this through.
    let mut nan = parent_actuation();
    nan.arms.get_mut("arm").unwrap().max_force_n = f64::NAN;
    verdict(
        "sets the force ceiling to NaN",
        Actuation::validate_narrowing(&parent_actuation(), &nan),
    );

    println!("\nAuthority cannot appear from nowhere:");
    let no_actuation = base_manifest(); // parent holds no actuation at all
    verdict(
        "a child claims actuation its parent never held",
        facet::validate_optional(no_actuation.actuation.as_ref(), Some(&parent_actuation())),
    );

    println!("\nAnd the whole wall runs on the manifest, not just the facet:");
    let widening_child = Manifest {
        actuation: Some(stronger),
        ..base_manifest()
    };
    verdict(
        "Manifest::validate_narrowing with the 450 N child",
        Manifest::validate_narrowing(&parent, &widening_child),
    );
}
