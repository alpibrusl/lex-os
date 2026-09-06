//! Manifest facets: authority domains that are *not* trust-lattice
//! dimensions (lex-os#66).
//!
//! [`Grant`](crate::Grant) is a fixed 3-tuple of ordered levels over
//! `{filesystem, network, exec}`, hashed into a `GrantId` and consumed by
//! the Lex type checker. A new authority domain — the robot's kinematic
//! envelope, an infrastructure provider surface, a pod's capabilities —
//! cannot be added there without changing what "trust" means to the
//! language and breaking hash stability. It becomes a **facet** on the
//! [`Manifest`](crate::Manifest) instead: same manifest, same
//! `ManifestId`, same narrowing wall.
//!
//! # A facet must be a lattice
//!
//! Narrowing has to be *decidable*, which constrains the shape a facet may
//! take. The helpers below are the permitted primitives:
//!
//! - [`narrow_allowlist`] — an allow-list narrows by subset (meet is
//!   intersection).
//! - [`narrow_cap`] — an ordered scalar ceiling narrows by `<=`.
//! - [`narrow_range`] — an interval narrows by containment.
//!
//! **There is deliberately no deny-list helper.** A deny list does not
//! narrow monotonically: a child that simply *omits* one of its parent's
//! deny entries has widened its own authority, which inverts the whole
//! invariant. A facet that wants prohibitions must express them as the
//! absence of an allow entry, or inherit-and-union them so a child can
//! only ever add. Encoding that here — rather than leaving it to each
//! facet's author — is the point of this module.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::{de::DeserializeOwned, Serialize};

/// Why a child manifest's facet was refused. Carries the facet name and a
/// human-legible reason so the supervisor can log a `[BLOCKED:narrowing]`
/// line naming the exact field that widened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("facet `{facet}` widens: {detail} (a child manifest may only narrow)")]
pub struct FacetError {
    /// The facet's name.
    ///
    /// `Cow` rather than `&'static str` because a facet name can arrive
    /// from a manifest's JSON, not only from a `Facet::NAME` constant.
    /// The borrowed case — every typed facet — still costs nothing; only
    /// a name read from input allocates. Interning those instead would
    /// leak once per distinct name, and manifests are external input, so
    /// a hostile one could leak without bound.
    pub facet: Cow<'static, str>,
    pub detail: String,
}

impl FacetError {
    pub fn new(facet: impl Into<Cow<'static, str>>, detail: impl Into<String>) -> Self {
        Self {
            facet: facet.into(),
            detail: detail.into(),
        }
    }
}

/// An authority domain carried on a [`Manifest`](crate::Manifest) outside
/// the trust lattice.
///
/// Implementors owe exactly one thing: a decision procedure for "is
/// `child` no wider than `parent`?", built from the lattice primitives in
/// this module. `NAME` is what appears in a refusal.
pub trait Facet: Sized {
    /// Stable identifier for this facet, used in errors and logs.
    const NAME: &'static str;

    /// Refuse if `child` grants any authority `parent` does not.
    fn validate_narrowing(parent: &Self, child: &Self) -> Result<(), FacetError>;
}

/// A validator for one facet, over its serialised form.
///
/// The slot on [`Manifest`](crate::Manifest) is type-erased — that is
/// the point, since lex-os must not learn what Terraform or Kubernetes
/// are — so narrowing a facet it does not know needs the *consumer* to
/// supply the decision procedure.
pub type FacetValidator = fn(&serde_json::Value, &serde_json::Value) -> Result<(), FacetError>;

/// Rebuild a typed facet from both sides and delegate to its own rule.
fn typed_validator<F: Facet + DeserializeOwned>(
    parent: &serde_json::Value,
    child: &serde_json::Value,
) -> Result<(), FacetError> {
    let parent: F = serde_json::from_value(parent.clone())
        .map_err(|e| FacetError::new(F::NAME, format!("parent facet does not parse: {e}")))?;
    let child: F = serde_json::from_value(child.clone())
        .map_err(|e| FacetError::new(F::NAME, format!("child facet does not parse: {e}")))?;
    F::validate_narrowing(&parent, &child)
}

/// Which facets a narrowing check knows how to compare.
///
/// A facet that is **not** registered is not thereby waved through: the
/// wall requires it to be byte-identical between parent and child, so it
/// can be carried or dropped but never tightened-in-a-way-nobody-checked
/// and never widened. Refuse, don't downgrade — applied to the gap in
/// our own knowledge rather than to the input.
#[derive(Default, Clone)]
pub struct FacetRegistry {
    validators: BTreeMap<&'static str, FacetValidator>,
}

impl FacetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Teach the registry how to narrow `F`.
    pub fn with<F: Facet + DeserializeOwned>(mut self) -> Self {
        self.validators.insert(F::NAME, typed_validator::<F>);
        self
    }

    pub fn get(&self, name: &str) -> Option<FacetValidator> {
        self.validators.get(name).copied()
    }

    pub fn knows(&self, name: &str) -> bool {
        self.validators.contains_key(name)
    }
}

/// Narrow the type-erased facet slot.
///
/// Three rules, in the order they matter:
///
/// 1. A facet key in the child that the parent does not carry is
///    refused — authority cannot appear from nowhere. (Same asymmetry as
///    [`validate_optional`].)
/// 2. A registered facet is delegated to its own rule.
/// 3. An unregistered facet must be byte-identical. Anything else would
///    mean accepting a change we have no procedure to judge.
pub fn validate_slot(
    parent: &BTreeMap<String, serde_json::Value>,
    child: &BTreeMap<String, serde_json::Value>,
    registry: &FacetRegistry,
) -> Result<(), FacetError> {
    for (name, child_value) in child {
        let Some(parent_value) = parent.get(name) else {
            return Err(FacetError::new(
                name.clone(),
                "the parent manifest carries no such facet, so a child cannot claim one",
            ));
        };
        match registry.get(name) {
            Some(validate) => validate(parent_value, child_value)?,
            None if parent_value == child_value => {}
            None => {
                return Err(FacetError::new(
                    name.clone(),
                    "facet differs from the parent's and no validator is registered for it, \
                     so the narrowing cannot be checked — register one, or carry the \
                     parent's value unchanged",
                ))
            }
        }
    }
    Ok(())
}

/// Serialise a facet for storage in the slot.
pub fn to_value<F: Facet + Serialize>(facet: &F) -> Result<serde_json::Value, FacetError> {
    serde_json::to_value(facet)
        .map_err(|e| FacetError::new(F::NAME, format!("facet does not serialise: {e}")))
}

/// Narrowing over an *optional* facet, which is how facets sit on a
/// manifest (absent means "this manifest grants nothing in that domain").
///
/// The asymmetry is the point:
///
/// | parent | child | verdict |
/// | ------ | ----- | ------- |
/// | absent | absent | ok — neither holds authority here |
/// | present | absent | ok — the child dropped the facet entirely |
/// | absent | present | **refused** — the parent holds nothing to hand down |
/// | present | present | delegated to [`Facet::validate_narrowing`] |
///
/// The third row is the one that matters: authority a parent never held
/// cannot appear in a child. Refuse, don't downgrade.
pub fn validate_optional<F: Facet>(
    parent: Option<&F>,
    child: Option<&F>,
) -> Result<(), FacetError> {
    match (parent, child) {
        (_, None) => Ok(()),
        (None, Some(_)) => Err(FacetError::new(
            F::NAME,
            "the parent manifest grants no authority in this domain, so a child cannot claim any",
        )),
        (Some(p), Some(c)) => F::validate_narrowing(p, c),
    }
}

/// An allow-list narrows by subset: every entry the child claims must
/// already be granted by the parent.
pub fn narrow_allowlist<'a>(
    facet: &'static str,
    field: &str,
    parent: impl IntoIterator<Item = &'a str>,
    child: impl IntoIterator<Item = &'a str>,
) -> Result<(), FacetError> {
    let allowed: Vec<&str> = parent.into_iter().collect();
    for entry in child {
        if !allowed.contains(&entry) {
            return Err(FacetError::new(
                facet,
                format!("{field}: child claims `{entry}`, which the parent does not grant"),
            ));
        }
    }
    Ok(())
}

/// Every key in `child` must already exist in `parent`, and the values at
/// the shared keys must themselves narrow. Used for the named-actuator
/// maps, where both the *set* of actuators and each actuator's envelope
/// are authority.
pub fn narrow_keyed<T, F>(
    facet: &'static str,
    field: &str,
    parent: &BTreeMap<String, T>,
    child: &BTreeMap<String, T>,
    mut narrow_value: F,
) -> Result<(), FacetError>
where
    F: FnMut(&str, &T, &T) -> Result<(), FacetError>,
{
    for (key, child_value) in child {
        let parent_value = parent.get(key).ok_or_else(|| {
            let granted: Vec<&str> = parent.keys().map(String::as_str).collect();
            FacetError::new(
                facet,
                format!("{field}: child claims `{key}`, which the parent does not grant (parent grants {granted:?})"),
            )
        })?;
        narrow_value(key, parent_value, child_value)?;
    }
    Ok(())
}

/// `a <= b`, where an *incomparable* pair (either side NaN) answers
/// `false` rather than propagating.
///
/// The direction matters: every caller uses this to ask "is the child
/// provably within the parent's bound?", so an unprovable answer must
/// read as "no". Written with `partial_cmp` rather than `!(a > b)` so the
/// incomparable case is visible instead of hiding in a negation. A
/// manifest should never carry NaN; if one arrives, refuse it.
fn within(a: f64, b: f64) -> bool {
    matches!(
        a.partial_cmp(&b),
        Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
    )
}

/// An ordered ceiling narrows by `<=`. NaN on either side is refused.
pub fn narrow_cap(
    facet: &'static str,
    field: &str,
    parent: f64,
    child: f64,
) -> Result<(), FacetError> {
    if !within(child, parent) {
        return Err(FacetError::new(
            facet,
            format!("{field}: child requests {child} but the parent caps it at {parent}"),
        ));
    }
    Ok(())
}

/// A closed interval narrows by containment: the child's interval must sit
/// entirely inside the parent's. NaN is refused, per [`narrow_cap`].
pub fn narrow_range(
    facet: &'static str,
    field: &str,
    parent: crate::Range,
    child: crate::Range,
) -> Result<(), FacetError> {
    if !(within(parent.min, child.min) && within(child.max, parent.max)) {
        return Err(FacetError::new(
            facet,
            format!(
                "{field}: child requests [{}, {}] which is not inside the parent's [{}, {}]",
                child.min, child.max, parent.min, parent.max
            ),
        ));
    }
    Ok(())
}

/// Axis names for the workspace / floor-area errors, so a refusal reads
/// `workspace_m.y` rather than `workspace_m[1]`.
pub(crate) const AXES: [&str; 3] = ["x", "y", "z"];
