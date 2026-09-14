//! The `authority` subcommand: *the sandbox is compiled, not configured.*
//!
//! `lex-os check` asks whether a program fits a grant a human wrote.
//! This asks the two questions that need an effect system to answer at
//! all — what is the least authority the code provably needs, and what
//! did this change do to it — and turns them into a reviewable gate:
//!
//! ```text
//! authority derive prog.lex                  # least grant the code needs
//! authority diff --base old.lex --head new.lex
//!                                            # the delta, classified
//! authority gate --grant m.json prog.lex     # CI verdict + the over-grant
//! authority narrow --grant m.json prog.lex   # shed the over-grant
//! ```
//!
//! Every refusal here is a [`ExitCode::PreconditionFailed`], the same
//! code `check` uses: a wall is a wall wherever it stands.

use std::path::{Path, PathBuf};
use std::time::Instant;

use acli::{emit, success_envelope, ExitCode, OutputFormat};
use clap::{Subcommand, ValueEnum};
use serde_json::json;

use lex_os_authority::{
    derive, diff, gate, narrow_manifest, Authority, AuthorityDiff, GateReport, Verdict,
};
use lex_os_manifest::Manifest;

use crate::{emit_err, VERSION};

#[derive(Subcommand)]
pub enum AuthorityCmd {
    /// Derive the least grant a program provably needs, with the
    /// evidence that it is tight.
    Derive {
        /// The `.lex` program to derive authority from.
        program: PathBuf,
    },
    /// Diff the authority of two versions of a program — the artifact a
    /// reviewer reads next to the source diff.
    Diff {
        /// The previously approved version.
        #[arg(long)]
        base: PathBuf,
        /// The proposed version.
        #[arg(long)]
        head: PathBuf,
        /// Exit non-zero on a delta at or above this severity. The CI
        /// gate: `--fail-on widening` refuses only new reach;
        /// `--fail-on any` pins authority exactly.
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
    },
    /// Check derived authority against the grant a human approved, and
    /// report the authority that grant hands over unused.
    Gate {
        /// Manifest JSON carrying the approved grant + egress allowlist.
        #[arg(long)]
        grant: PathBuf,
        /// The `.lex` program to gate.
        program: PathBuf,
    },
    /// Rewrite a manifest down to the authority the code provably needs.
    /// Narrowing only — this can never hand a program more than the
    /// manifest already approved.
    Narrow {
        /// Manifest JSON to tighten.
        #[arg(long)]
        grant: PathBuf,
        /// The `.lex` program whose derivation sets the new floor.
        program: PathBuf,
        /// Where to write the narrowed manifest. Defaults to stdout.
        /// (`--out`, not `-o`: the global `--output` selects the acli
        /// output format.)
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

/// How strict [`AuthorityCmd::Diff`]'s gate is.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum FailOn {
    /// Refuse only a delta that reaches somewhere new.
    Widening,
    /// Refuse any movement at all, narrowing included — for code whose
    /// authority is pinned by an external approval.
    Any,
}

pub fn cmd_authority(fmt: &OutputFormat, what: AuthorityCmd) -> ExitCode {
    match what {
        AuthorityCmd::Derive { program } => run_derive(fmt, &program),
        AuthorityCmd::Diff {
            base,
            head,
            fail_on,
        } => run_diff(fmt, &base, &head, fail_on),
        AuthorityCmd::Gate { grant, program } => run_gate(fmt, &grant, &program),
        AuthorityCmd::Narrow {
            grant,
            program,
            out,
        } => run_narrow(fmt, &grant, &program, out.as_deref()),
    }
}

// ------------------------------------------------------------- derive

fn run_derive(fmt: &OutputFormat, program: &Path) -> ExitCode {
    let start = Instant::now();
    let src = match read(fmt, "authority.derive", program) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let (authority, effects) = match derive(&src) {
        Ok(a) => a,
        Err(e) => {
            return emit_err(
                fmt,
                "authority.derive",
                ExitCode::InvalidArgs,
                &e.to_string(),
            )
        }
    };
    let witness = authority.minimality_witness(&effects);

    if matches!(fmt, OutputFormat::Text) {
        println!("derived authority — {}", program.display());
        print_authority(&authority);
        if witness.is_empty() {
            println!("  minimal      yes — this program needs no authority at all");
        } else {
            println!("  minimal      yes — tight on every dimension it uses:");
            for w in &witness {
                println!(
                    "                 {} at `{}`: lowering to `{}` rejects `{}`",
                    w.dimension, w.level, w.lowered_to, w.rejected_effect
                );
            }
        }
        return ExitCode::Success;
    }

    emit(
        &success_envelope(
            "authority.derive",
            json!({
                "program": program.display().to_string(),
                "authority": authority,
                "authority_id": authority.grant_id().0,
                "grant_pretty": authority.grant.pretty(),
                "minimality_witness": witness,
            }),
            VERSION,
            Some(start),
            None,
        ),
        fmt,
    );
    ExitCode::Success
}

// --------------------------------------------------------------- diff

fn run_diff(fmt: &OutputFormat, base: &Path, head: &Path, fail_on: Option<FailOn>) -> ExitCode {
    let start = Instant::now();
    let (base_auth, head_auth) = match (derive_file(fmt, base), derive_file(fmt, head)) {
        (Ok(b), Ok(h)) => (b, h),
        (Err(c), _) | (_, Err(c)) => return c,
    };
    let delta = diff(&base_auth, &head_auth);

    let refuse = match fail_on {
        Some(FailOn::Widening) => delta.verdict == Verdict::Widening,
        Some(FailOn::Any) => delta.verdict != Verdict::Unchanged,
        None => false,
    };

    if matches!(fmt, OutputFormat::Text) {
        println!("authority delta — {} → {}", base.display(), head.display());
        print_diff(&delta);
        println!("verdict: {}", verdict_line(delta.verdict));
        if refuse {
            return ExitCode::PreconditionFailed;
        }
        return ExitCode::Success;
    }

    let data = json!({
        "base": base.display().to_string(),
        "head": head.display().to_string(),
        "base_authority": base_auth,
        "head_authority": head_auth,
        "delta": delta,
        "verdict": delta.verdict.as_str(),
    });
    if refuse {
        emit(
            &success_envelope("authority.diff", data, VERSION, Some(start), None),
            fmt,
        );
        return ExitCode::PreconditionFailed;
    }
    emit(
        &success_envelope("authority.diff", data, VERSION, Some(start), None),
        fmt,
    );
    ExitCode::Success
}

// --------------------------------------------------------------- gate

fn run_gate(fmt: &OutputFormat, grant: &Path, program: &Path) -> ExitCode {
    let start = Instant::now();
    let manifest = match read_manifest(fmt, "authority.gate", grant) {
        Ok(m) => m,
        Err(code) => return code,
    };
    let authority = match derive_file(fmt, program) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let report = gate(&manifest.grant, &manifest.egress, &authority);

    if matches!(fmt, OutputFormat::Text) {
        print_gate(&authority, &report, grant, program);
        return if report.allowed {
            ExitCode::Success
        } else {
            ExitCode::PreconditionFailed
        };
    }

    let data = json!({
        "program": program.display().to_string(),
        "manifest": grant.display().to_string(),
        "approved_grant": manifest.grant.pretty(),
        "derived": authority,
        "authority_id": authority.grant_id().0,
        "report": report,
    });
    emit(
        &success_envelope("authority.gate", data, VERSION, Some(start), None),
        fmt,
    );
    if report.allowed {
        ExitCode::Success
    } else {
        ExitCode::PreconditionFailed
    }
}

// ------------------------------------------------------------- narrow

fn run_narrow(fmt: &OutputFormat, grant: &Path, program: &Path, output: Option<&Path>) -> ExitCode {
    let start = Instant::now();
    let manifest = match read_manifest(fmt, "authority.narrow", grant) {
        Ok(m) => m,
        Err(code) => return code,
    };
    let authority = match derive_file(fmt, program) {
        Ok(a) => a,
        Err(code) => return code,
    };
    // Narrowing a manifest the code does not even fit would produce a
    // box that cannot run it. Refuse first, for the same reason the
    // resolver does: refuse, don't downgrade.
    let report = gate(&manifest.grant, &manifest.egress, &authority);
    if !report.allowed {
        return emit_err(
            fmt,
            "authority.narrow",
            ExitCode::PreconditionFailed,
            &format!(
                "the program exceeds this manifest's grant, so there is nothing to narrow: {}",
                report.violations.join("; ")
            ),
        );
    }
    let narrowed = match narrow_manifest(&manifest, &authority) {
        Ok(m) => m,
        Err(e) => {
            return emit_err(
                fmt,
                "authority.narrow",
                ExitCode::GeneralError,
                &e.to_string(),
            )
        }
    };
    let json_text = match serde_json::to_string_pretty(&narrowed) {
        Ok(t) => t,
        Err(e) => {
            return emit_err(
                fmt,
                "authority.narrow",
                ExitCode::GeneralError,
                &e.to_string(),
            )
        }
    };
    if let Some(path) = output {
        if let Err(e) = std::fs::write(path, format!("{json_text}\n")) {
            return emit_err(
                fmt,
                "authority.narrow",
                ExitCode::GeneralError,
                &e.to_string(),
            );
        }
    }

    if matches!(fmt, OutputFormat::Text) {
        println!("narrowed manifest — {}", grant.display());
        println!("  before       {}", manifest.grant.pretty());
        println!("  after        {}", narrowed.grant.pretty());
        if manifest.egress != narrowed.egress {
            println!(
                "  egress       {:?} → {:?}",
                manifest.egress, narrowed.egress
            );
        }
        match output {
            Some(p) => println!("  written      {}", p.display()),
            None => println!("\n{json_text}"),
        }
        return ExitCode::Success;
    }

    emit(
        &success_envelope(
            "authority.narrow",
            json!({
                "manifest": grant.display().to_string(),
                "program": program.display().to_string(),
                "before": manifest.grant.pretty(),
                "after": narrowed.grant.pretty(),
                "egress_before": manifest.egress,
                "egress_after": narrowed.egress,
                "written": output.map(|p| p.display().to_string()),
                "narrowed": narrowed,
            }),
            VERSION,
            Some(start),
            None,
        ),
        fmt,
    );
    ExitCode::Success
}

// ------------------------------------------------------------ helpers

fn read(fmt: &OutputFormat, cmd: &str, path: &Path) -> Result<String, ExitCode> {
    std::fs::read_to_string(path).map_err(|e| {
        emit_err(
            fmt,
            cmd,
            ExitCode::NotFound,
            &format!("{}: {e}", path.display()),
        )
    })
}

fn read_manifest(fmt: &OutputFormat, cmd: &str, path: &Path) -> Result<Manifest, ExitCode> {
    let text = read(fmt, cmd, path)?;
    Manifest::from_json(&text).map_err(|e| {
        emit_err(
            fmt,
            cmd,
            ExitCode::InvalidArgs,
            &format!("bad manifest: {e}"),
        )
    })
}

fn derive_file(fmt: &OutputFormat, path: &Path) -> Result<Authority, ExitCode> {
    let src = read(fmt, "authority", path)?;
    derive(&src).map(|(a, _)| a).map_err(|e| {
        emit_err(
            fmt,
            "authority",
            ExitCode::InvalidArgs,
            &format!("{}: {e}", path.display()),
        )
    })
}

fn print_authority(a: &Authority) {
    println!("  grant        {}", a.grant.pretty());
    println!("  authority-id {}", a.grant_id());
    if !a.egress.is_empty() {
        println!("  egress       {}", a.egress.join(", "));
    }
    if !a.fs_read.is_empty() {
        println!("  fs read      {}", a.fs_read.join(", "));
    }
    if !a.fs_write.is_empty() {
        println!("  fs write     {}", a.fs_write.join(", "));
    }
    if !a.effects.is_empty() {
        println!("  effects      {}", a.effects.join(", "));
    }
    if !a.off_lattice.is_empty() {
        println!(
            "  off-lattice  {} (no grant refuses these — review them by eye)",
            a.off_lattice.join(", ")
        );
    }
    if a.unscoped_net {
        println!("  net scope    partial — a bare [net] is present, so *which* host is a perimeter question");
    }
}

fn print_diff(d: &AuthorityDiff) {
    for dim in &d.dimensions {
        println!(
            "  {:<12} {} → {}{}",
            dim.dimension.to_string(),
            dim.from,
            dim.to,
            if dim.widens() {
                "   WIDENS"
            } else {
                "   narrows"
            }
        );
    }
    print_list("egress", "+", &d.egress_added);
    print_list("egress", "-", &d.egress_removed);
    print_list("fs read", "+", &d.fs_read_added);
    print_list("fs read", "-", &d.fs_read_removed);
    print_list("fs write", "+", &d.fs_write_added);
    print_list("fs write", "-", &d.fs_write_removed);
    print_list("off-lattice", "+", &d.off_lattice_added);
    print_list("off-lattice", "-", &d.off_lattice_removed);
    if d.lost_net_precision {
        println!("  net scope    host-scoped → bare [net]   WIDENS (the static host is gone)");
    }
    if d.is_empty() {
        println!("  (nothing moved)");
    }
}

fn print_list(label: &str, sign: &str, items: &[String]) {
    for item in items {
        println!("  {label:<12} {sign} {item}");
    }
}

fn verdict_line(v: Verdict) -> &'static str {
    match v {
        Verdict::Unchanged => "UNCHANGED — this change reaches nowhere new",
        Verdict::Narrowing => {
            "NARROWING — the code proves it no longer needs some authority; safe to apply"
        }
        Verdict::Widening => {
            "WIDENING — this change reaches somewhere new; a human must approve it"
        }
    }
}

fn print_gate(a: &Authority, r: &GateReport, grant: &Path, program: &Path) {
    if r.allowed {
        println!("ALLOWED — {} fits {}", program.display(), grant.display());
    } else {
        println!(
            "REFUSED — {} exceeds {}",
            program.display(),
            grant.display()
        );
        for v in &r.violations {
            println!("  {v}");
        }
    }
    println!("  needs        {}", a.grant.pretty());
    println!("  authority-id {}", a.grant_id());
    if !r.slack.is_empty() {
        println!("\nover-grant — authority this manifest hands over and the code never uses:");
        for dim in &r.slack.dimensions {
            println!(
                "  {:<12} {} → {}",
                dim.dimension.to_string(),
                dim.from,
                dim.to
            );
        }
        for host in &r.slack.unused_egress {
            println!("  {:<12} {}", "egress", host);
        }
        println!(
            "  shed it:     lex-os authority narrow --grant {} {} --out narrowed.json",
            grant.display(),
            program.display()
        );
    }
}
