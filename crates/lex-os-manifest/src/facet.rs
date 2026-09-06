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

use std::collections::BTreeMap;

/// Why a child manifest's facet was refused. Carries the facet name and a
/// human-legible reason so the supervisor can log a `[BLOCKED:narrowing]`
/// line naming the exact field that widened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("facet `{facet}` widens: {detail} (a child manifest may only narrow)")]
pub struct FacetError {
    pub facet: &'static str,
    pub detail: String,
}

impl FacetError {
    pub fn new(facet: &'static str, detail: impl Into<String>) -> Self {
        Self {
            facet,
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
