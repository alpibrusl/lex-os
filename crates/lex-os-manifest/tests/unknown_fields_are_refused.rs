//! A manifest is the whole safety declaration, and nobody reads it
//! line-by-line — that is the point of the design. So the parser is the
//! only thing standing between an invented field and a ceiling that
//! silently does not exist (lex-os#101).
//!
//! Every fixture below is a *real* invention. Two independent agents
//! were asked to write a manifest for these services from the READMEs
//! alone (lex-os#89); neither converged on the schema, and they did not
//! converge on the same wrong one either. What each produced is pinned
//! here, because a test built from something someone actually wrote
//! keeps failing for the right reason.

use lex_os_manifest::{Budget, Goal, Grant, Level, Manifest};

/// The shape a correct manifest has, for the fixtures to deviate from.
const VALID: &str = r#"{
  "goal": { "description": "serve the thing", "done_signal": "DONE" },
  "grant": { "filesystem": "ReadOnly", "network": "Allowlist", "exec": "None" },
  "budget": { "wall_clock_secs": 600, "max_commands": 200,
              "max_money_cents": 100, "max_api_calls": 50 },
  "isolation_floor": "MicroVm",
  "egress": ["a.example:443"]
}"#;

fn parse(s: &str) -> Result<Manifest, serde_json::Error> {
    serde_json::from_str::<Manifest>(s)
}

#[test]
fn the_valid_shape_still_parses() {
    // The negative control for every test below: if this ever fails,
    // the others are refusing for the wrong reason.
    let m = parse(VALID).expect("the canonical shape must parse");
    assert_eq!(m.budget.max_money_cents, 100);
    assert_eq!(m.grant.exec, Level::None);
}

/// The finding that prompted this file.
///
/// A second cold-read participant wrote `max_cpu_millicores` and
/// `max_memory_mb`, which are not budget fields. Before #101 this
/// parsed, produced a `Budget` carrying neither, and left an author
/// believing they had capped CPU and memory. Every downstream record —
/// the audit chain, the decision, the approval — then agreed with that
/// mistaken belief, because by then the fields no longer existed.
///
/// This is the failure that fails *open*, which is why it is first.
#[test]
fn an_invented_budget_ceiling_is_refused_rather_than_dropped() {
    let with_invented_ceilings = VALID.replace(
        r#""max_api_calls": 50 }"#,
        r#""max_api_calls": 50, "max_cpu_millicores": 500, "max_memory_mb": 1024 }"#,
    );
    assert_ne!(with_invented_ceilings, VALID, "the fixture must differ");

    let err = parse(&with_invented_ceilings)
        .expect_err("an invented ceiling must be refused, never silently dropped");

    // The message has to name the field. "Invalid manifest" would leave
    // an author guessing which of six fields was wrong — and an author
    // that guesses is how the invention got here.
    let msg = err.to_string();
    assert!(
        msg.contains("max_cpu_millicores"),
        "the refusal must name the offending field, got: {msg}"
    );
}

/// The same class one level up: a whole section nobody defined.
#[test]
fn an_invented_top_level_section_is_refused() {
    let with_section = VALID.replace(
        r#""egress": ["a.example:443"]"#,
        r#""egress": ["a.example:443"], "resources": {"cpu": "500m"}"#,
    );
    let err = parse(&with_section).expect_err("an unknown top-level key must be refused");
    assert!(err.to_string().contains("resources"), "{err}");
}

/// The first participant's inventions were *structural* rather than
/// extra keys: a path-based filesystem grant and an ingress/egress
/// network object, where both are a `Level`. Those already failed on
/// type, and must keep failing — this pins that the type error is not
/// quietly relaxed while making room for `_comment`.
#[test]
fn a_structurally_invented_grant_is_still_refused() {
    let invented = r#"{
      "goal": "Deploy lex-oms with access to its dependencies",
      "grant": {
        "filesystem": { "read": ["/etc/lex-oms/config"], "write": ["/var/log/lex-oms"] },
        "network": { "egress": ["db.lex.internal:5432"], "ingress": { "ports": [8080] } },
        "exec": "Sandboxed"
      },
      "budget": { "max_cpu_millicores": 500, "max_memory_mb": 1024, "max_money_cents": 50 },
      "isolation_floor": "Namespace"
    }"#;
    assert!(
        parse(invented).is_err(),
        "a manifest inventing its own grant shape must not parse"
    );
}

/// `goal` is a struct. Both participants wrote it as a string, which is
/// the single most likely first mistake, so it gets its own test rather
/// than hiding inside the one above.
#[test]
fn a_goal_written_as_a_string_is_refused() {
    let s = VALID.replace(
        r#""goal": { "description": "serve the thing", "done_signal": "DONE" }"#,
        r#""goal": "serve the thing""#,
    );
    assert!(parse(&s).is_err(), "goal is a struct, not a string");
}

/// The escape hatch that keeps `deny_unknown_fields` from making
/// manifests unable to explain themselves. JSON has no comments and
/// these carry real reasoning.
#[test]
fn the_reserved_comment_key_is_accepted() {
    let with_comment = VALID.replace(
        r#""goal":"#,
        r#""_comment": ["why this grant is what it is"], "goal":"#,
    );
    let m = parse(&with_comment).expect("_comment is the one reserved key");
    assert!(m.comment.is_some());
}

/// A note must not re-identify a manifest, or annotating one would
/// invalidate every record naming it — and nobody would annotate.
#[test]
fn a_comment_does_not_change_the_content_id() {
    let plain = parse(VALID).unwrap();
    let annotated =
        parse(&VALID.replace(r#""goal":"#, r#""_comment": "any text at all", "goal":"#)).unwrap();

    assert_ne!(plain.comment, annotated.comment, "the fixtures must differ");
    assert_eq!(
        plain.content_id(),
        annotated.content_id(),
        "a comment must be invisible to the content address"
    );
}

/// `_comment` is exactly one key, not a prefix. Allowing `_comment_foo`
/// would reopen the hole a wide one: every invented field could hide
/// behind the prefix.
#[test]
fn a_comment_like_key_is_not_a_comment() {
    let s = VALID.replace(r#""goal":"#, r#""_comment_notes": "x", "goal":"#);
    assert!(
        parse(&s).is_err(),
        "only the exact key `_comment` is reserved"
    );
}

/// Every manifest committed to this repository must parse. This is the
/// test that would have caught `deny_unknown_fields` breaking the demos.
#[test]
fn every_committed_manifest_still_parses() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/lex-os-manifest -> repo root")
        .to_path_buf();

    let mut checked = 0;
    for dir in ["demo", "demo/attacks", "examples"] {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // Only files that are actually manifests.
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            if v.get("grant").is_none() || v.get("budget").is_none() {
                continue;
            }
            parse(&text).unwrap_or_else(|e| panic!("{} no longer parses: {e}", path.display()));
            checked += 1;
        }
    }
    assert!(
        checked >= 7,
        "expected to find the committed manifests, found {checked}"
    );
}

/// Round-tripping must survive the new field, or `reprovision` — which
/// rebuilds a box from a stored manifest — would start refusing its own
/// output.
#[test]
fn a_serialised_manifest_parses_back() {
    let m = Manifest::new(
        Goal::new("x"),
        Grant::new(Level::ReadOnly, Level::Allowlist, Level::None),
        Budget::research_default(),
    );
    let json = serde_json::to_string(&m).unwrap();
    let back = parse(&json).expect("our own output must satisfy deny_unknown_fields");
    assert_eq!(m, back);
}
