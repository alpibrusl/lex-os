//! The robot half of the grant: which skills are allowed and the
//! kinematic/force bounds each actuating skill is held to. Optional on a
//! `Manifest` — absent means lex-os behaves exactly as before (generic
//! agent box). Present means the supervisor's `mediate_skill` checks every
//! skill argument against these bounds before the effect runs.

use serde::{Deserialize, Serialize};

/// A closed interval `[min, max]` in metres for one workspace axis.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Range {
    pub min: f64,
    pub max: f64,
}

impl Range {
    pub fn contains(&self, v: f64) -> bool {
        v >= self.min && v <= self.max
    }
}

/// Arm actuator bounds. `workspace_m` is `[x, y, z]` ranges in metres.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ActuatorArm {
    pub workspace_m: [Range; 3],
    pub max_velocity_mps: f64,
    pub max_force_n: f64,
}

/// Gripper actuator bounds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ActuatorGripper {
    pub max_grip_force_n: f64,
}

/// The actuation grant: allowed skills + per-actuator caps. Reversibility
/// per skill is carried as `(skill, class)` pairs so the supervisor can
/// reuse the existing `Reversibility` gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Actuation {
    pub skills: Vec<String>,
    pub arm: ActuatorArm,
    pub gripper: ActuatorGripper,
}

impl Actuation {
    /// Is `skill` named in the grant's allowlist?
    pub fn allows(&self, skill: &str) -> bool {
        self.skills.iter().any(|s| s == skill)
    }

    /// Check a `move_to` target `(x, y, z)` against the workspace box.
    /// Returns the offending axis name on failure.
    pub fn check_move_to(&self, x: f64, y: f64, z: f64) -> Result<(), String> {
        let axes = [("x", x, self.arm.workspace_m[0]),
                    ("y", y, self.arm.workspace_m[1]),
                    ("z", z, self.arm.workspace_m[2])];
        for (name, v, range) in axes {
            if !range.contains(v) {
                return Err(format!(
                    "{name}={v} outside workspace [{},{}]", range.min, range.max
                ));
            }
        }
        Ok(())
    }

    /// Check a grasp force against the gripper cap.
    pub fn check_grasp(&self, force_n: f64) -> Result<(), String> {
        if force_n > self.gripper.max_grip_force_n {
            return Err(format!(
                "force {force_n}N exceeds max_grip_force_n {}",
                self.gripper.max_grip_force_n
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Actuation {
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
    fn allows_only_listed_skills() {
        let a = sample();
        assert!(a.allows("move_to"));
        assert!(!a.allows("connect_charger"));
    }

    #[test]
    fn move_to_inside_workspace_ok() {
        assert!(sample().check_move_to(0.3, 0.0, 0.2).is_ok());
    }

    #[test]
    fn move_to_outside_workspace_denied() {
        let err = sample().check_move_to(0.9, 0.0, 0.2).unwrap_err();
        assert!(err.contains("x=0.9"));
    }

    #[test]
    fn grasp_over_force_denied() {
        assert!(sample().check_grasp(50.0).is_err());
        assert!(sample().check_grasp(10.0).is_ok());
    }
}
