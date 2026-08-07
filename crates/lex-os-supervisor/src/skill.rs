//! Skill-level mediation: the robot analogue of `mediate`. Where `mediate`
//! checks a command *name* against a trust dimension/level, `mediate_skill`
//! checks a skill's *arguments* against the manifest's `Actuation` bounds —
//! the run-time block that catches an out-of-workspace `move_to` or an
//! over-force `grasp` before the effect leaves the box.
//!
//! Each actuating skill first *resolves* which granted actuator instance it
//! targets (`Actuation::resolve_arm`/`resolve_gripper`/`resolve_base`) via
//! the request's `"arm"` selector argument, then checks its arguments
//! against that instance's bounds. A dual-arm robot with independent
//! left/right envelopes needs no change here — only in the manifest.

use lex_os_manifest::Actuation;
use serde_json::Value;

/// The supervisor's verdict on a skill request, mapped later onto the
/// existing `Decision` type by the run loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillVerdict {
    Allowed,
    Denied(String),
}

/// Mediate one skill request against the actuation grant. Pure: no audit,
/// no budget (the run loop owns those, reusing the existing gates).
/// Skills a grant may name that carry no supervisor-checkable bounds by
/// design: sensing reads, resets, releases, and the delegated paths whose
/// arguments are governed elsewhere (`run_policy` hands the high-rate loop to
/// the sidecar under its own budget; `policy_action`/`apply_action` are the
/// step-wise path where the in-box Lex grant vets every command). Everything
/// NOT in this registry and NOT carrying a mediation rule below is REFUSED —
/// the resolver rule (refuse, don't downgrade): a skill the supervisor cannot
/// bound must not be silently admitted just because its name was granted.
const UNBOUNDED_BY_DESIGN: &[&str] = &[
    "read_joints",
    "read_camera",
    "listen",
    "read_base",
    "locate_object",
    "read_inlet",
    "workpiece_status",
    "reset",
    "reset_depot",
    "reset_episode",
    "release_arm",
    "disconnect_charger",
    "run_policy",
    "record_episode",
    "policy_action",
    "apply_action",
    "clamp_workpiece",
];

fn verdict(result: Result<(), String>) -> SkillVerdict {
    match result {
        Ok(()) => SkillVerdict::Allowed,
        Err(e) => SkillVerdict::Denied(e),
    }
}

pub fn mediate_skill(actuation: &Actuation, skill: &str, args: &Value) -> SkillVerdict {
    if !actuation.allows(skill) {
        return SkillVerdict::Denied(format!("skill `{skill}` not in the grant"));
    }
    let num = |k: &str, default: f64| args.get(k).and_then(Value::as_f64).unwrap_or(default);
    let selector = args.get("arm").and_then(Value::as_str);
    match skill {
        // Arm reaches: `move_to` (single-arm robots) and `move_arm` (a
        // dual-arm robot's per-side variant, selecting which arm by the
        // `"arm"` argument) are the same check once resolved to an instance.
        "move_to" | "move_arm" => {
            let arm = match actuation.resolve_arm(selector) {
                Ok(a) => a,
                Err(e) => return SkillVerdict::Denied(e),
            };
            if let Err(e) = arm.check_move_to(num("x", 0.5), num("y", 0.5), num("z", 0.0)) {
                return SkillVerdict::Denied(e);
            }
            // Enforce the velocity cap whenever the caller commands a velocity.
            // Current move args carry only a target pose, so this is usually
            // a no-op — but it makes `max_velocity_mps` a real gate the moment a
            // skill conveys speed, rather than a declared-but-ignored cap.
            if let Some(v) = args.get("velocity").and_then(Value::as_f64) {
                if let Err(e) = arm.check_velocity(v) {
                    return SkillVerdict::Denied(e);
                }
            }
            SkillVerdict::Allowed
        }
        // Grips: `grasp` and a dual-arm robot's `grasp_arm` — the gripper
        // cap, resolved by the same `"arm"` selector as the reach above.
        "grasp" | "grasp_arm" => match actuation.resolve_gripper(selector) {
            Ok(g) => verdict(g.check_grasp(num("force", 0.0))),
            Err(e) => SkillVerdict::Denied(e),
        },
        // Mobile base: target inside the granted floor area, speed under the
        // cap. A manifest with no base granted refuses every base move.
        "move_base" => {
            let base = match actuation.resolve_base() {
                Ok(b) => b,
                Err(e) => return SkillVerdict::Denied(e),
            };
            if let Err(e) = base.check_move_base(num("x", 0.0), num("y", 0.0)) {
                return SkillVerdict::Denied(e);
            }
            if let Some(v) = args.get("speed").and_then(Value::as_f64) {
                if let Err(e) = base.check_speed(v) {
                    return SkillVerdict::Denied(e);
                }
            }
            SkillVerdict::Allowed
        }
        // Insertion force: the arm's `max_force_n` is the transient-contact
        // cap (ISO/TS 15066-derived in production grants).
        "connect_charger" => {
            let arm = match actuation.resolve_arm(selector) {
                Ok(a) => a,
                Err(e) => return SkillVerdict::Denied(e),
            };
            match args.get("force").and_then(Value::as_f64) {
                Some(f) => verdict(arm.check_contact_force(f)),
                None => SkillVerdict::Allowed,
            }
        }
        other if UNBOUNDED_BY_DESIGN.contains(&other) => SkillVerdict::Allowed,
        other => SkillVerdict::Denied(format!(
            "skill `{other}` has no supervisor mediation rule — refused (refuse, don't downgrade)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{ActuatorArm, ActuatorGripper, Range};
    use serde_json::json;
    use std::collections::BTreeMap;

    fn arm() -> ActuatorArm {
        ActuatorArm {
            workspace_m: [
                Range { min: 0.1, max: 0.5 },
                Range {
                    min: -0.3,
                    max: 0.3,
                },
                Range { min: 0.0, max: 0.4 },
            ],
            max_velocity_mps: 0.25,
            max_force_n: 15.0,
        }
    }

    fn act() -> Actuation {
        Actuation {
            skills: vec!["move_to".into(), "grasp".into(), "run_policy".into()],
            arms: BTreeMap::from([("arm".to_string(), arm())]),
            grippers: BTreeMap::from([(
                "gripper".to_string(),
                ActuatorGripper {
                    max_grip_force_n: 20.0,
                },
            )]),
            bases: BTreeMap::new(),
        }
    }

    fn act_xle() -> Actuation {
        use lex_os_manifest::ActuatorBase;
        Actuation {
            skills: vec![
                "move_arm".into(),
                "grasp_arm".into(),
                "move_base".into(),
                "read_base".into(),
            ],
            arms: BTreeMap::from([("left".to_string(), arm()), ("right".to_string(), arm())]),
            grippers: BTreeMap::from([
                (
                    "left".to_string(),
                    ActuatorGripper {
                        max_grip_force_n: 20.0,
                    },
                ),
                (
                    "right".to_string(),
                    ActuatorGripper {
                        max_grip_force_n: 20.0,
                    },
                ),
            ]),
            bases: BTreeMap::from([(
                "base".to_string(),
                ActuatorBase {
                    floor_area_m: [Range { min: 0.0, max: 4.0 }, Range { min: 0.0, max: 3.0 }],
                    max_speed_mps: 0.5,
                },
            )]),
        }
    }

    #[test]
    fn ungranted_skill_denied() {
        assert!(matches!(
            mediate_skill(&act(), "connect_charger", &json!({})),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn in_workspace_move_allowed() {
        assert_eq!(
            mediate_skill(&act(), "move_to", &json!({"x":0.3,"y":0.0,"z":0.2})),
            SkillVerdict::Allowed
        );
    }
    #[test]
    fn out_of_workspace_move_denied() {
        assert!(matches!(
            mediate_skill(&act(), "move_to", &json!({"x":0.9,"y":0.0})),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn over_force_grasp_denied() {
        assert!(matches!(
            mediate_skill(&act(), "grasp", &json!({"force":50.0})),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn over_velocity_move_denied() {
        // act()'s max_velocity_mps is 0.25; an in-workspace move at 2.0 m/s is denied.
        assert!(matches!(
            mediate_skill(
                &act(),
                "move_to",
                &json!({"x":0.3,"y":0.0,"z":0.2,"velocity":2.0})
            ),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn in_cap_velocity_move_allowed() {
        assert_eq!(
            mediate_skill(
                &act(),
                "move_to",
                &json!({"x":0.3,"y":0.0,"z":0.2,"velocity":0.2})
            ),
            SkillVerdict::Allowed
        );
    }
    #[test]
    fn run_policy_passes_allowlist_gate() {
        assert_eq!(
            mediate_skill(&act(), "run_policy", &json!({"name":"x"})),
            SkillVerdict::Allowed
        );
    }
    #[test]
    fn move_arm_checked_like_move_to() {
        assert_eq!(
            mediate_skill(
                &act_xle(),
                "move_arm",
                &json!({"arm":"left","x":0.3,"y":0.0,"z":0.2})
            ),
            SkillVerdict::Allowed
        );
        assert!(matches!(
            mediate_skill(
                &act_xle(),
                "move_arm",
                &json!({"arm":"left","x":0.9,"y":0.0})
            ),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn move_arm_without_selector_is_ambiguous_and_denied() {
        // act_xle() grants two arms; a request that doesn't say which one is
        // never guessed among them (refuse, don't downgrade).
        let d = mediate_skill(&act_xle(), "move_arm", &json!({"x":0.3,"y":0.0,"z":0.2}));
        assert!(matches!(&d, SkillVerdict::Denied(e) if e.contains("multiple arms granted")));
    }
    #[test]
    fn move_arm_unknown_side_denied() {
        let d = mediate_skill(
            &act_xle(),
            "move_arm",
            &json!({"arm":"middle","x":0.3,"y":0.0,"z":0.2}),
        );
        assert!(matches!(&d, SkillVerdict::Denied(e) if e.contains("no `middle` arm granted")));
    }
    #[test]
    fn grasp_arm_checked_like_grasp() {
        assert_eq!(
            mediate_skill(
                &act_xle(),
                "grasp_arm",
                &json!({"arm":"right","force":10.0})
            ),
            SkillVerdict::Allowed
        );
        assert!(matches!(
            mediate_skill(
                &act_xle(),
                "grasp_arm",
                &json!({"arm":"right","force":99.0})
            ),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn move_base_checked_against_floor_area_and_speed() {
        assert_eq!(
            mediate_skill(
                &act_xle(),
                "move_base",
                &json!({"x":2.5,"y":1.0,"speed":0.3})
            ),
            SkillVerdict::Allowed
        );
        // out of the floor area — the capsule's declared 4x3m room
        assert!(matches!(
            mediate_skill(&act_xle(), "move_base", &json!({"x":9.0,"y":1.5})),
            SkillVerdict::Denied(_)
        ));
        // over the speed cap
        assert!(matches!(
            mediate_skill(
                &act_xle(),
                "move_base",
                &json!({"x":2.5,"y":1.0,"speed":2.0})
            ),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn move_base_without_base_granted_refused() {
        // granted by name, but the manifest declares no base bounds:
        // refuse, don't downgrade — never admit what cannot be bounded.
        let mut a = act();
        a.skills.push("move_base".into());
        assert!(matches!(
            mediate_skill(&a, "move_base", &json!({"x":1.0,"y":1.0})),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn connect_charger_force_capped_by_arm_max_force() {
        let mut a = act();
        a.skills.push("connect_charger".into());
        assert_eq!(
            mediate_skill(&a, "connect_charger", &json!({"force":10.0})),
            SkillVerdict::Allowed
        );
        assert!(matches!(
            mediate_skill(&a, "connect_charger", &json!({"force":99.0})),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn granted_but_unknown_skill_refused() {
        // The referee-evasion shape, one layer down (lex-games#21 / lex-robot#77):
        // a granted name with no mediation rule must be refused, not admitted.
        let mut a = act();
        a.skills.push("teleport".into());
        assert!(matches!(
            mediate_skill(&a, "teleport", &json!({"x":9.0})),
            SkillVerdict::Denied(_)
        ));
    }
    #[test]
    fn sensing_and_delegated_skills_still_allowed() {
        let mut a = act_xle();
        a.skills.push("read_joints".into());
        a.skills.push("release_arm".into());
        assert_eq!(
            mediate_skill(&a, "read_base", &json!({})),
            SkillVerdict::Allowed
        );
        assert_eq!(
            mediate_skill(&a, "read_joints", &json!({"arm":"left"})),
            SkillVerdict::Allowed
        );
        a.skills.push("listen".into());
        assert_eq!(
            mediate_skill(&a, "listen", &json!({"seconds":3})),
            SkillVerdict::Allowed
        );
        assert_eq!(
            mediate_skill(&a, "release_arm", &json!({"arm":"left"})),
            SkillVerdict::Allowed
        );
        a.skills.push("locate_object".into());
        assert_eq!(
            mediate_skill(&a, "locate_object", &json!({"name":"cup"})),
            SkillVerdict::Allowed
        );
    }
}
