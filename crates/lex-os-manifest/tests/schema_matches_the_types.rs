//! `schema/manifest.schema.json` is the artifact a manifest author
//! writes against. Under this project's own premise nobody reads the
//! Rust types to check it — so a schema that has quietly drifted from
//! them is worse than no schema, because it is trusted.
//!
//! These tests hold the two together without a code-generation
//! dependency: the schema's property names must be exactly the struct's
//! serialised keys, and its enum lists must be exactly the variants.
//! Add, rename or remove a field and this file fails until the schema
//! is updated (lex-os#101).

use std::collections::BTreeSet;

use lex_os_manifest::{Actuation, Budget, Goal, Grant, IsolationFloor, Level, Manifest};
use serde_json::Value;

fn schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/lex-os-manifest -> repo root")
        .join("schema/manifest.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} is missing: {e}", path.display()));
    serde_json::from_str(&text).expect("the schema must be valid JSON")
}

/// Property names declared for an object, at a `$defs` name or the root.
fn declared(s: &Value, def: Option<&str>) -> BTreeSet<String> {
    let node = match def {
        Some(d) => &s["$defs"][d],
        None => s,
    };
    node["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("no properties on {def:?}"))
        .keys()
        .cloned()
        .collect()
}

/// The keys serde actually emits, from a value with every optional
/// field populated — otherwise `skip_serializing_if` hides them and the
/// comparison silently passes on a field the schema forgot.
fn emitted<T: serde::Serialize>(v: &T) -> BTreeSet<String> {
    serde_json::to_value(v)
        .expect("serialisable")
        .as_object()
        .expect("a struct serialises to an object")
        .keys()
        .cloned()
        .collect()
}

fn fully_populated() -> Manifest {
    let mut m = Manifest::new(
        Goal::new("x").with_done_signal("DONE"),
        Grant::new(Level::ReadWrite, Level::Allowlist, Level::Sandboxed),
        Budget::research_default(),
    );
    m.egress = vec!["a.example:443".into()];
    m.comment = Some(Value::String("note".into()));
    m.facets
        .insert("infra".into(), serde_json::json!({"aws": []}));
    m.actuation = Some(Actuation {
        skills: vec!["grasp".into()],
        arms: Default::default(),
        grippers: Default::default(),
        bases: Default::default(),
    });
    m
}

#[test]
fn the_root_properties_are_exactly_the_manifest_fields() {
    let m = fully_populated();
    assert_eq!(
        declared(&schema(), None),
        emitted(&m),
        "schema/manifest.schema.json has drifted from `Manifest`"
    );
}

#[test]
fn the_goal_properties_are_exactly_the_goal_fields() {
    let g = Goal::new("x").with_done_signal("DONE");
    assert_eq!(declared(&schema(), Some("Goal")), emitted(&g));
}

#[test]
fn the_budget_properties_are_exactly_the_budget_fields() {
    assert_eq!(
        declared(&schema(), Some("Budget")),
        emitted(&Budget::research_default()),
        "the budget's four fields are the whole budget; the schema must say so"
    );
}

#[test]
fn the_grant_properties_are_exactly_the_grant_fields() {
    let g = Grant::new(Level::ReadOnly, Level::Allowlist, Level::None);
    assert_eq!(declared(&schema(), Some("Grant")), emitted(&g));
}

/// An enum the schema under-lists silently refuses a legal manifest; one
/// it over-lists advertises a level that does not exist. Both are the
/// schema lying, so both fail here.
#[test]
fn the_level_enum_is_exactly_the_variants() {
    let all = [
        Level::None,
        Level::ReadOnly,
        Level::Sandboxed,
        Level::Loopback,
        Level::ReadWrite,
        Level::Allowlist,
        Level::Full,
    ];
    let real: BTreeSet<String> = all
        .iter()
        .map(|l| {
            serde_json::to_value(l)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();

    let s = schema();
    let listed: BTreeSet<String> = s["$defs"]["Level"]["enum"]
        .as_array()
        .expect("Level must declare an enum")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert_eq!(listed, real, "the schema's Level list has drifted");
}

#[test]
fn the_isolation_floor_enum_is_exactly_the_variants() {
    let real: BTreeSet<String> = [
        IsolationFloor::Namespace,
        IsolationFloor::Gvisor,
        IsolationFloor::MicroVm,
    ]
    .iter()
    .map(|f| {
        serde_json::to_value(f)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    })
    .collect();

    let s = schema();
    let listed: BTreeSet<String> = s["$defs"]["IsolationFloor"]["enum"]
        .as_array()
        .expect("IsolationFloor must declare an enum")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert_eq!(listed, real);
}

/// The schema must mirror `deny_unknown_fields`, or an author writing
/// against it would be told an invented field is fine and only find out
/// at the parser.
#[test]
fn every_object_in_the_schema_is_closed() {
    let s = schema();
    assert_eq!(
        s["additionalProperties"],
        Value::Bool(false),
        "the root must refuse unknown fields, as `Manifest` does"
    );

    for (name, def) in s["$defs"].as_object().expect("$defs").iter() {
        if def["type"] != Value::String("object".into()) {
            continue; // enums and scalars
        }
        // `facets` is deliberately open — the whole point is that
        // lex-os does not model a downstream gate's vocabulary.
        assert_eq!(
            def["additionalProperties"],
            Value::Bool(false),
            "$defs/{name} must be closed"
        );
    }
}

/// The required list cannot name a field that does not exist, or an
/// author is asked for something they cannot supply.
#[test]
fn required_names_only_real_properties() {
    let s = schema();
    let check = |node: &Value, what: &str| {
        let props: BTreeSet<String> = node["properties"]
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        if let Some(req) = node["required"].as_array() {
            for r in req {
                let r = r.as_str().unwrap();
                assert!(
                    props.contains(r),
                    "{what} requires `{r}`, which it does not define"
                );
            }
        }
    };
    check(&s, "the root");
    for (name, def) in s["$defs"].as_object().expect("$defs").iter() {
        check(def, name);
    }
}
