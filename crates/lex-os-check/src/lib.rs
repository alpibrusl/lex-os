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

/// Lower-level entry: check against an explicit grant + egress allowlist.
pub fn check_source_against_grant(
    src: &str,
    grant: &Grant,
    egress: &[String],
) -> Result<CheckReport, CheckError> {
    // 1. Parse.
    let program = lex_syntax::parse_source(src).map_err(|e| CheckError::Parse(format!("{e:?}")))?;

    // 2. Canonicalize to typed-AST stages.
    let stages = lex_ast::canonicalize_program(&program);

    // 3. Type-check — rejects dishonest effect rows (a `[io]` signature
    //    hiding a `[net]` call), exactly as the toolchain would.
    lex_types::check_program(&stages)
        .map_err(|errs| CheckError::TypeCheck(format!("{} error(s): {:?}", errs.len(), errs)))?;

    // 4. Collect the program's declared effects.
    let effects = collect_effects(&stages);

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

fn report(effects: &EffectSet) -> CheckReport {
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
