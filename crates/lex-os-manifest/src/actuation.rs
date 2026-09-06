//! The robot half of the grant: which skills are allowed and the
//! kinematic/force bounds each actuating skill is held to. Optional on a
//! `Manifest` — absent means lex-os behaves exactly as before (generic
//! agent box). Present means the supervisor's `mediate_skill` checks every
//! skill argument against these bounds before the effect runs.
//!
//! Actuator groups are **named and multi-valued** (`arms`/`grippers`/`bases`
//! are maps, not single fields) so a dual-arm robot like the XLeRobot can
//! grant its left and right arms independent workspace/force envelopes —
//! adding a second (or third) arm is a manifest edit, not a lex-os
//! recompile. A skill request that names an actuator (`{"arm": "left", ...}`)
//! resolves against that key; a request with no selector resolves only when
//! exactly one actuator of that kind is granted (never guessed among
//! several — refuse, don't downgrade).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::facet::{
    narrow_allowlist, narrow_cap, narrow_keyed, narrow_range, Facet, FacetError, AXES,
};

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

impl ActuatorArm {
    /// Check a `move_to`/`move_arm` target `(x, y, z)` against the workspace
    /// box. Returns the offending axis name on failure.
    pub fn check_move_to(&self, x: f64, y: f64, z: f64) -> Result<(), String> {
        let axes = [
            ("x", x, self.workspace_m[0]),
            ("y", y, self.workspace_m[1]),
            ("z", z, self.workspace_m[2]),
        ];
        for (name, v, range) in axes {
            if !range.contains(v) {
                return Err(format!(
                    "{name}={v} outside workspace [{},{}]",
                    range.min, range.max
                ));
            }
        }
        Ok(())
    }

    /// Check a commanded arm velocity against `max_velocity_mps`. Negative
    /// (magnitude) speeds are compared by absolute value.
    pub fn check_velocity(&self, velocity_mps: f64) -> Result<(), String> {
        if velocity_mps.abs() > self.max_velocity_mps {
            return Err(format!(
                "velocity {velocity_mps} m/s exceeds max_velocity_mps {}",
                self.max_velocity_mps
            ));
        }
        Ok(())
    }

    /// Check an insertion/contact force (e.g. `connect_charger`) against
    /// `max_force_n` — the transient-contact cap (ISO/TS 15066-derived in
    /// production grants).
    pub fn check_contact_force(&self, force_n: f64) -> Result<(), String> {
        if force_n > self.max_force_n {
            return Err(format!(
                "force {force_n}N exceeds max_force_n {}",
                self.max_force_n
            ));
        }
        Ok(())
    }
}

/// Gripper actuator bounds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ActuatorGripper {
    pub max_grip_force_n: f64,
}

impl ActuatorGripper {
    /// Check a grasp force against the gripper cap.
    pub fn check_grasp(&self, force_n: f64) -> Result<(), String> {
        if force_n > self.max_grip_force_n {
            return Err(format!(
                "force {force_n}N exceeds max_grip_force_n {}",
                self.max_grip_force_n
            ));
        }
        Ok(())
    }
}

/// Mobile-base actuator bounds (e.g. the XLeRobot 0.4.0's differential base).
/// `floor_area_m` is `[x, y]` ranges in metres — the permitted floor area.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ActuatorBase {
    pub floor_area_m: [Range; 2],
    pub max_speed_mps: f64,
}

impl ActuatorBase {
    /// Check a `move_base` target `(x, y)` against the granted floor area.
    pub fn check_move_base(&self, x: f64, y: f64) -> Result<(), String> {
        let axes = [
            ("x", x, self.floor_area_m[0]),
            ("y", y, self.floor_area_m[1]),
        ];
        for (name, v, range) in axes {
            if !range.contains(v) {
                return Err(format!(
                    "{name}={v} outside floor area [{},{}]",
                    range.min, range.max
                ));
            }
        }
        Ok(())
    }

    /// Check a commanded base speed against `max_speed_mps` (magnitude).
    pub fn check_speed(&self, speed_mps: f64) -> Result<(), String> {
        if speed_mps.abs() > self.max_speed_mps {
            return Err(format!(
                "speed {speed_mps} m/s exceeds max_speed_mps {}",
                self.max_speed_mps
            ));
        }
        Ok(())
    }
}

/// The actuation grant: the allowed-skills allowlist + per-actuator caps,
/// each actuator kind keyed by name (`"arm"` for a single-arm robot,
/// `"left_arm"`/`"right_arm"` for a dual-arm robot, etc.). `BTreeMap` (not
/// `HashMap`) so canonical JSON — and therefore the manifest's content id —
/// is deterministic across processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actuation {
    pub skills: Vec<String>,
    pub arms: BTreeMap<String, ActuatorArm>,
    pub grippers: BTreeMap<String, ActuatorGripper>,
    /// Optional: empty means no mobile base is granted at all — a `move_base`
    /// request is then refused (never silently admitted). `skip_serializing_if`
    /// keeps the canonical JSON — and therefore the content id — of every
    /// existing base-less manifest unchanged.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bases: BTreeMap<String, ActuatorBase>,
}

// `Manifest` derives `Eq` (the supervisor's `AgentAction` requires it via
// `ProposeChild(Box<Manifest>)`). These actuator types hold `f64`, so `Eq`
// cannot be derived on them individually, but a manifest grant never carries
// NaN, so the marker impls are sound in practice.
impl Eq for Range {}
impl Eq for ActuatorArm {}
impl Eq for ActuatorGripper {}
impl Eq for ActuatorBase {}

/// How a skill request selects among several actuators of the same kind:
/// named explicitly (`{"arm": "left", ...}`), or unambiguous because the
/// grant only names one.
fn resolve<'a, T>(
    map: &'a BTreeMap<String, T>,
    selector: Option<&str>,
    kind: &str,
) -> Result<&'a T, String> {
    match selector {
        Some(key) => map.get(key).ok_or_else(|| {
            let granted: Vec<&str> = map.keys().map(String::as_str).collect();
            format!("no `{key}` {kind} granted (granted: {granted:?})")
        }),
        None => match map.len() {
            0 => Err(format!("no {kind} actuation granted")),
            1 => Ok(map.values().next().expect("len checked")),
            _ => {
                let granted: Vec<&str> = map.keys().map(String::as_str).collect();
                Err(format!(
                    "multiple {kind}s granted ({granted:?}) — the request must name which one"
                ))
            }
        },
    }
}

impl Actuation {
    /// Is `skill` named in the grant's allowlist?
    pub fn allows(&self, skill: &str) -> bool {
        self.skills.iter().any(|s| s == skill)
    }

    /// Resolve which granted arm a request targets. `selector` is the
    /// request's `"arm"` argument, if any (`None` for single-arm skills like
    /// plain `move_to`/`connect_charger` that carry no selector).
    pub fn resolve_arm(&self, selector: Option<&str>) -> Result<&ActuatorArm, String> {
        resolve(&self.arms, selector, "arm")
    }

    /// Resolve which granted gripper a request targets, by the same
    /// selector convention as `resolve_arm`.
    pub fn resolve_gripper(&self, selector: Option<&str>) -> Result<&ActuatorGripper, String> {
        resolve(&self.grippers, selector, "gripper")
    }

    /// Resolve the granted base. There is no per-request base selector today
    /// (no skill carries a `"base"` argument) — a manifest that grants more
    /// than one base is therefore never resolvable and every base skill is
    /// refused, same as granting zero (refuse, don't downgrade).
    pub fn resolve_base(&self) -> Result<&ActuatorBase, String> {
        resolve(&self.bases, None, "base")
    }
}

/// The actuation grant narrows like any other facet (lex-os#66): a child
/// may drop skills and actuators and tighten every envelope, and may not
/// add a skill, name an actuator the parent never granted, or raise a cap.
///
/// Before this impl existed, `Manifest::validate_narrowing` checked the
/// grant, the egress allowlist and the budgets but *not* actuation — so a
/// child could hand itself a wider workspace box or a higher force ceiling
/// and the narrowing wall would pass it.
impl Facet for Actuation {
    const NAME: &'static str = "actuation";

    fn validate_narrowing(parent: &Self, child: &Self) -> Result<(), FacetError> {
        narrow_allowlist(
            Self::NAME,
            "skills",
            parent.skills.iter().map(String::as_str),
            child.skills.iter().map(String::as_str),
        )?;

        narrow_keyed(
            Self::NAME,
            "arms",
            &parent.arms,
            &child.arms,
            |key, parent_arm, child_arm| {
                for (axis, (p, c)) in AXES.iter().zip(
                    parent_arm
                        .workspace_m
                        .iter()
                        .zip(child_arm.workspace_m.iter()),
                ) {
                    narrow_range(
                        Self::NAME,
                        &format!("arms.{key}.workspace_m.{axis}"),
                        *p,
                        *c,
                    )?;
                }
                narrow_cap(
                    Self::NAME,
                    &format!("arms.{key}.max_velocity_mps"),
                    parent_arm.max_velocity_mps,
                    child_arm.max_velocity_mps,
                )?;
                narrow_cap(
                    Self::NAME,
                    &format!("arms.{key}.max_force_n"),
                    parent_arm.max_force_n,
                    child_arm.max_force_n,
                )
            },
        )?;

        narrow_keyed(
            Self::NAME,
            "grippers",
            &parent.grippers,
            &child.grippers,
            |key, parent_gripper, child_gripper| {
                narrow_cap(
                    Self::NAME,
                    &format!("grippers.{key}.max_grip_force_n"),
                    parent_gripper.max_grip_force_n,
                    child_gripper.max_grip_force_n,
                )
            },
        )?;

        narrow_keyed(
            Self::NAME,
            "bases",
            &parent.bases,
            &child.bases,
            |key, parent_base, child_base| {
                for (axis, (p, c)) in AXES.iter().zip(
                    parent_base
                        .floor_area_m
                        .iter()
                        .zip(child_base.floor_area_m.iter()),
                ) {
                    narrow_range(
                        Self::NAME,
                        &format!("bases.{key}.floor_area_m.{axis}"),
                        *p,
                        *c,
                    )?;
                }
                narrow_cap(
                    Self::NAME,
                    &format!("bases.{key}.max_speed_mps"),
                    parent_base.max_speed_mps,
                    child_base.max_speed_mps,
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn sample() -> Actuation {
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

    fn sample_dual_arm() -> Actuation {
        let mut left = arm();
        left.workspace_m[1] = Range { min: 0.0, max: 0.3 }; // left arm: +y half only
        let mut right = arm();
        right.workspace_m[1] = Range {
            min: -0.3,
            max: 0.0,
        }; // right arm: -y half only
        Actuation {
            skills: vec!["move_arm".into(), "grasp_arm".into()],
            arms: BTreeMap::from([("left".to_string(), left), ("right".to_string(), right)]),
            grippers: BTreeMap::from([
                (
                    "left".to_string(),
                    ActuatorGripper {
                        max_grip_force_n: 15.0,
                    },
                ),
                (
                    "right".to_string(),
                    ActuatorGripper {
                        max_grip_force_n: 15.0,
                    },
                ),
            ]),
            bases: BTreeMap::new(),
        }
    }

    // --- Facet narrowing (lex-os#66) ---------------------------------

    /// A child that drops skills and tightens every envelope is a valid
    /// narrowing — the ordinary case, and the one that must keep working.
    #[test]
    fn actuation_narrowing_accepts_a_tighter_child() {
        let parent = sample_with_base();
        let mut child = parent.clone();
        child.skills = vec!["move_to".into()]; // dropped grasp + run_policy
        child.arms.get_mut("arm").unwrap().max_force_n = 5.0; // 15 -> 5
        child.arms.get_mut("arm").unwrap().workspace_m[0] = Range { min: 0.2, max: 0.4 };
        child.grippers.get_mut("gripper").unwrap().max_grip_force_n = 1.0;
        child.bases.get_mut("base").unwrap().max_speed_mps = 0.1;
        assert!(Actuation::validate_narrowing(&parent, &child).is_ok());

        // Dropping an actuator kind entirely is narrowing too.
        child.bases.clear();
        assert!(Actuation::validate_narrowing(&parent, &child).is_ok());
    }

    /// The gap this facet closes: before lex-os#66 every one of these
    /// passed the narrowing wall untouched.
    #[test]
    fn actuation_narrowing_rejects_each_widening() {
        let parent = sample_with_base();

        // A skill the parent never granted.
        let mut extra_skill = parent.clone();
        extra_skill.skills.push("open_door".into());
        let err = Actuation::validate_narrowing(&parent, &extra_skill).unwrap_err();
        assert_eq!(err.facet, "actuation");
        assert!(err.detail.contains("open_door"), "{}", err.detail);

        // An arm the parent never granted.
        let mut extra_arm = parent.clone();
        extra_arm.arms.insert("third".into(), arm());
        assert!(Actuation::validate_narrowing(&parent, &extra_arm).is_err());

        // A workspace box reaching outside the parent's.
        let mut wider_box = parent.clone();
        wider_box.arms.get_mut("arm").unwrap().workspace_m[2] = Range { min: 0.0, max: 9.0 };
        let err = Actuation::validate_narrowing(&parent, &wider_box).unwrap_err();
        assert!(err.detail.contains("workspace_m.z"), "{}", err.detail);

        // A raised velocity cap.
        let mut faster = parent.clone();
        faster.arms.get_mut("arm").unwrap().max_velocity_mps = 2.0;
        assert!(Actuation::validate_narrowing(&parent, &faster).is_err());

        // A raised force cap — the one that hurts a human.
        let mut stronger = parent.clone();
        stronger.arms.get_mut("arm").unwrap().max_force_n = 500.0;
        let err = Actuation::validate_narrowing(&parent, &stronger).unwrap_err();
        assert!(err.detail.contains("max_force_n"), "{}", err.detail);

        // A raised grip force.
        let mut crushing = parent.clone();
        crushing
            .grippers
            .get_mut("gripper")
            .unwrap()
            .max_grip_force_n = 400.0;
        assert!(Actuation::validate_narrowing(&parent, &crushing).is_err());

        // A larger floor area and a faster base.
        let mut roaming = parent.clone();
        roaming.bases.get_mut("base").unwrap().floor_area_m[0] = Range {
            min: -50.0,
            max: 50.0,
        };
        assert!(Actuation::validate_narrowing(&parent, &roaming).is_err());
        let mut speeding = parent.clone();
        speeding.bases.get_mut("base").unwrap().max_speed_mps = 3.0;
        assert!(Actuation::validate_narrowing(&parent, &speeding).is_err());
    }

    /// NaN compares false against everything, so a naive `child > parent`
    /// check would admit it. Refuse, don't downgrade.
    #[test]
    fn actuation_narrowing_refuses_nan_caps() {
        let parent = sample();
        let mut nan_force = parent.clone();
        nan_force.arms.get_mut("arm").unwrap().max_force_n = f64::NAN;
        assert!(Actuation::validate_narrowing(&parent, &nan_force).is_err());

        let mut nan_box = parent.clone();
        nan_box.arms.get_mut("arm").unwrap().workspace_m[0] = Range {
            min: f64::NAN,
            max: f64::NAN,
        };
        assert!(Actuation::validate_narrowing(&parent, &nan_box).is_err());
    }

    /// Each named actuator carries its own envelope, so a dual-arm child
    /// cannot borrow the other arm's reach.
    #[test]
    fn actuation_narrowing_is_per_actuator() {
        let parent = sample_dual_arm();
        // The left arm claims the right arm's -y half.
        let mut swapped = parent.clone();
        swapped.arms.get_mut("left").unwrap().workspace_m[1] = Range {
            min: -0.3,
            max: 0.0,
        };
        let err = Actuation::validate_narrowing(&parent, &swapped).unwrap_err();
        assert!(err.detail.contains("arms.left"), "{}", err.detail);
    }

    fn sample_with_base() -> Actuation {
        Actuation {
            bases: BTreeMap::from([(
                "base".to_string(),
                ActuatorBase {
                    floor_area_m: [Range { min: 0.0, max: 4.0 }, Range { min: 0.0, max: 3.0 }],
                    max_speed_mps: 0.5,
                },
            )]),
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
    fn single_arm_resolves_without_selector() {
        assert!(sample().resolve_arm(None).is_ok());
    }

    #[test]
    fn single_arm_resolves_even_with_a_selector_naming_it() {
        assert!(sample().resolve_arm(Some("arm")).is_ok());
    }

    #[test]
    fn move_to_inside_workspace_ok() {
        let a = sample();
        assert!(a
            .resolve_arm(None)
            .unwrap()
            .check_move_to(0.3, 0.0, 0.2)
            .is_ok());
    }

    #[test]
    fn move_to_outside_workspace_denied() {
        let a = sample();
        let err = a
            .resolve_arm(None)
            .unwrap()
            .check_move_to(0.9, 0.0, 0.2)
            .unwrap_err();
        assert!(err.contains("x=0.9"));
    }

    #[test]
    fn grasp_over_force_denied() {
        let a = sample();
        let g = a.resolve_gripper(None).unwrap();
        assert!(g.check_grasp(50.0).is_err());
        assert!(g.check_grasp(10.0).is_ok());
    }

    #[test]
    fn dual_arm_requires_a_selector() {
        let a = sample_dual_arm();
        let err = a.resolve_arm(None).unwrap_err();
        assert!(err.contains("multiple arms granted"));
    }

    #[test]
    fn dual_arm_selector_resolves_the_named_arm() {
        let a = sample_dual_arm();
        assert!(a.resolve_arm(Some("left")).is_ok());
        assert!(a.resolve_arm(Some("right")).is_ok());
    }

    #[test]
    fn dual_arm_unknown_selector_denied() {
        let a = sample_dual_arm();
        let err = a.resolve_arm(Some("middle")).unwrap_err();
        assert!(err.contains("no `middle` arm granted"));
    }

    #[test]
    fn dual_arm_independent_workspaces_are_enforced_per_side() {
        let a = sample_dual_arm();
        // left arm is granted only the +y half; right only the -y half.
        assert!(a
            .resolve_arm(Some("left"))
            .unwrap()
            .check_move_to(0.3, 0.2, 0.2)
            .is_ok());
        assert!(a
            .resolve_arm(Some("left"))
            .unwrap()
            .check_move_to(0.3, -0.2, 0.2)
            .is_err());
        assert!(a
            .resolve_arm(Some("right"))
            .unwrap()
            .check_move_to(0.3, -0.2, 0.2)
            .is_ok());
        assert!(a
            .resolve_arm(Some("right"))
            .unwrap()
            .check_move_to(0.3, 0.2, 0.2)
            .is_err());
    }

    #[test]
    fn move_base_inside_floor_area_ok() {
        let a = sample_with_base();
        assert!(a.resolve_base().unwrap().check_move_base(2.5, 1.0).is_ok());
    }

    #[test]
    fn move_base_outside_floor_area_denied() {
        let a = sample_with_base();
        let err = a
            .resolve_base()
            .unwrap()
            .check_move_base(9.0, 1.5)
            .unwrap_err();
        assert!(err.contains("x=9"));
    }

    #[test]
    fn base_speed_over_cap_denied() {
        let a = sample_with_base();
        let b = a.resolve_base().unwrap();
        assert!(b.check_speed(2.0).is_err());
        assert!(b.check_speed(0.4).is_ok());
    }

    #[test]
    fn no_base_granted_refuses_base_moves() {
        // refuse, don't downgrade: an empty bases map grants nothing.
        assert!(sample().resolve_base().is_err());
    }

    #[test]
    fn absent_base_keeps_canonical_json_unchanged() {
        // content-address stability: an empty bases map must not appear in the JSON.
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(!json.contains("bases"));
        let round: Actuation = serde_json::from_str(&json).unwrap();
        assert_eq!(round, sample());
    }

    #[test]
    fn canonical_json_is_deterministic_across_key_insertion_order() {
        // BTreeMap sorts by key regardless of insertion order — required for
        // a stable content id across processes.
        let a = sample_dual_arm();
        let mut b_arms = BTreeMap::new();
        b_arms.insert("right".to_string(), *a.arms.get("right").unwrap());
        b_arms.insert("left".to_string(), *a.arms.get("left").unwrap());
        let b = Actuation {
            arms: b_arms,
            ..a.clone()
        };
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
