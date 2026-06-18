//! Skill-level mediation: the robot analogue of `mediate`. Where `mediate`
//! checks a command *name* against a trust dimension/level, `mediate_skill`
//! checks a skill's *arguments* against the manifest's `Actuation` bounds —
//! the run-time block that catches an out-of-workspace `move_to` or an
//! over-force `grasp` before the effect leaves the box.

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
pub fn mediate_skill(actuation: &Actuation, skill: &str, args: &Value) -> SkillVerdict {
    if !actuation.allows(skill) {
        return SkillVerdict::Denied(format!("skill `{skill}` not in the grant"));
    }
    let num = |k: &str, default: f64| args.get(k).and_then(Value::as_f64).unwrap_or(default);
    match skill {
        "move_to" => {
            match actuation.check_move_to(num("x", 0.5), num("y", 0.5), num("z", 0.0)) {
                Ok(()) => SkillVerdict::Allowed,
                Err(e) => SkillVerdict::Denied(e),
            }
        }
        "grasp" => match actuation.check_grasp(num("force", 0.0)) {
            Ok(()) => SkillVerdict::Allowed,
            Err(e) => SkillVerdict::Denied(e),
        },
        _ => SkillVerdict::Allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lex_os_manifest::{ActuatorArm, ActuatorGripper, Range};
    use serde_json::json;

    fn act() -> Actuation {
        Actuation {
            skills: vec!["move_to".into(), "grasp".into(), "run_policy".into()],
            arm: ActuatorArm {
                workspace_m: [Range { min: 0.1, max: 0.5 },
                              Range { min: -0.3, max: 0.3 },
                              Range { min: 0.0, max: 0.4 }],
                max_velocity_mps: 0.25,
                max_force_n: 15.0,
            },
            gripper: ActuatorGripper { max_grip_force_n: 20.0 },
        }
    }

    #[test]
    fn ungranted_skill_denied() {
        assert!(matches!(mediate_skill(&act(), "connect_charger", &json!({})), SkillVerdict::Denied(_)));
    }
    #[test]
    fn in_workspace_move_allowed() {
        assert_eq!(mediate_skill(&act(), "move_to", &json!({"x":0.3,"y":0.0,"z":0.2})), SkillVerdict::Allowed);
    }
    #[test]
    fn out_of_workspace_move_denied() {
        assert!(matches!(mediate_skill(&act(), "move_to", &json!({"x":0.9,"y":0.0})), SkillVerdict::Denied(_)));
    }
    #[test]
    fn over_force_grasp_denied() {
        assert!(matches!(mediate_skill(&act(), "grasp", &json!({"force":50.0})), SkillVerdict::Denied(_)));
    }
    #[test]
    fn run_policy_passes_allowlist_gate() {
        assert_eq!(mediate_skill(&act(), "run_policy", &json!({"name":"x"})), SkillVerdict::Allowed);
    }
}
