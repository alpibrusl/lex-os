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

/// Mobile-base actuator bounds (e.g. the XLeRobot 0.4.0's differential base).
/// `floor_area_m` is `[x, y]` ranges in metres — the permitted floor area.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ActuatorBase {
    pub floor_area_m: [Range; 2],
    pub max_speed_mps: f64,
}

/// The actuation grant: the allowed-skills allowlist + per-actuator caps.
/// The supervisor's `mediate_skill` reads this to admit or deny each skill
/// request before the effect runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Actuation {
    pub skills: Vec<String>,
    pub arm: ActuatorArm,
    pub gripper: ActuatorGripper,
    /// Optional: absent means no mobile base is granted at all — a `move_base`
    /// request is then refused (never silently admitted). `skip_serializing_if`
    /// keeps the canonical JSON — and therefore the content id — of every
    /// existing base-less manifest unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<ActuatorBase>,
}

// `Manifest` derives `Eq` (the supervisor's `AgentAction` requires it via
// `ProposeChild(Box<Manifest>)`). These actuation types hold `f64`, so `Eq`
// cannot be derived, but a manifest grant never carries NaN, so the marker
// impls are sound in practice and keep `Manifest: Eq` intact.
impl Eq for Range {}
impl Eq for ActuatorArm {}
impl Eq for ActuatorGripper {}
impl Eq for ActuatorBase {}
impl Eq for Actuation {}

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

    /// Check a `move_base` target `(x, y)` against the granted floor area.
    /// A grant without a `base` block refuses every base move — the owner
    /// granted no base authority, so none exists (refuse, don't downgrade).
    pub fn check_move_base(&self, x: f64, y: f64) -> Result<(), String> {
        let Some(base) = &self.base else {
            return Err("no base actuation granted (manifest has no `base` block)".into());
        };
        let axes = [("x", x, base.floor_area_m[0]), ("y", y, base.floor_area_m[1])];
        for (name, v, range) in axes {
            if !range.contains(v) {
                return Err(format!(
                    "{name}={v} outside floor area [{},{}]", range.min, range.max
                ));
            }
        }
        Ok(())
    }

    /// Check a commanded base speed against `max_speed_mps` (magnitude).
    pub fn check_base_speed(&self, speed_mps: f64) -> Result<(), String> {
        let Some(base) = &self.base else {
            return Err("no base actuation granted (manifest has no `base` block)".into());
        };
        if speed_mps.abs() > base.max_speed_mps {
            return Err(format!(
                "speed {speed_mps} m/s exceeds max_speed_mps {}", base.max_speed_mps
            ));
        }
        Ok(())
    }

    /// Check a commanded arm velocity against `max_velocity_mps`. Negative
    /// (magnitude) speeds are compared by absolute value.
    pub fn check_velocity(&self, velocity_mps: f64) -> Result<(), String> {
        if velocity_mps.abs() > self.arm.max_velocity_mps {
            return Err(format!(
                "velocity {velocity_mps} m/s exceeds max_velocity_mps {}",
                self.arm.max_velocity_mps
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
            base: None,
        }
    }

    fn sample_with_base() -> Actuation {
        Actuation {
            base: Some(ActuatorBase {
                floor_area_m: [Range { min: 0.0, max: 4.0 }, Range { min: 0.0, max: 3.0 }],
                max_speed_mps: 0.5,
            }),
            ..sample()
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

    #[test]
    fn move_base_inside_floor_area_ok() {
        assert!(sample_with_base().check_move_base(2.5, 1.0).is_ok());
    }

    #[test]
    fn move_base_outside_floor_area_denied() {
        let err = sample_with_base().check_move_base(9.0, 1.5).unwrap_err();
        assert!(err.contains("x=9"));
    }

    #[test]
    fn base_speed_over_cap_denied() {
        assert!(sample_with_base().check_base_speed(2.0).is_err());
        assert!(sample_with_base().check_base_speed(0.4).is_ok());
    }

    #[test]
    fn no_base_block_refuses_base_moves() {
        // refuse, don't downgrade: a grant without a base block grants nothing.
        assert!(sample().check_move_base(1.0, 1.0).is_err());
        assert!(sample().check_base_speed(0.1).is_err());
    }

    #[test]
    fn absent_base_keeps_canonical_json_unchanged() {
        // content-address stability: a None base must not appear in the JSON.
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(!json.contains("base"));
        let round: Actuation = serde_json::from_str(&json).unwrap();
        assert_eq!(round, sample());
    }
}
