//! The CLI is a contract, and these tests keep the docs honest about it.
//!
//! Three guards, all sourced from the *real* binary so they cannot drift
//! from it (this is lex-os#22 — the README audit that motivated it found a
//! `check` invocation that didn't run and several undocumented commands):
//!
//!  1. **Golden CLI reference.** A snapshot of clap's own `--help` across
//!     the whole command tree. clap generates this text from the command
//!     definitions, so adding / removing / renaming a command or flag
//!     changes the snapshot and fails CI until `docs/CLI.md`-equivalent
//!     (`tests/cli-reference.txt`) is regenerated. Regenerate with
//!     `UPDATE_CLI_REF=1 cargo test -p lex-os --test cli_contract`.
//!  2. **README commands are real.** Every `lex-os` invocation shown in the
//!     README must resolve to a subcommand the binary actually accepts.
//!  3. **Documented exit codes hold.** A curated set of self-contained
//!     commands is run for real and checked against the semantic exit code
//!     the README promises (e.g. the type-check wall returns 8).

use std::path::PathBuf;
use std::process::Command;

/// Path to the built `lex-os` binary under test.
const BIN: &str = env!("CARGO_BIN_EXE_lex-os");

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/lex-os; the repo root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Run the binary with `args`; return (stdout+stderr, exit code).
fn run(args: &[&str]) -> (String, i32) {
    let out = Command::new(BIN)
        .args(args)
        // Detach from any inherited terminal width so clap's help wrapping
        // is the deterministic non-tty default in every environment.
        .env_remove("COLUMNS")
        .current_dir(repo_root())
        .output()
        .expect("spawn lex-os");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (s, out.status.code().unwrap_or(-1))
}

/// The command tree to snapshot. Each entry is an argument path whose
/// `--help` is captured. A new command/flag that isn't reflected here (or
/// in the captured text) breaks the golden test.
const HELP_PATHS: &[&[&str]] = &[
    &[],
    &["run"],
    &["resolve"],
    &["manifest"],
    &["manifest", "sample"],
    &["manifest", "hash"],
    &["manifest", "narrow"],
    &["audit"],
    &["audit", "verify"],
    &["audit", "render"],
    &["audit", "tail"],
    &["check"],
    &["capsule"],
    &["capsule", "keygen"],
    &["capsule", "sign"],
    &["capsule", "verify"],
    &["capsule", "install"],
    &["introspect"],
];

fn render_reference() -> String {
    let mut out = String::new();
    out.push_str("# lex-os CLI reference (generated from `--help`; do not edit by hand)\n");
    out.push_str("# Regenerate: UPDATE_CLI_REF=1 cargo test -p lex-os --test cli_contract\n");
    for path in HELP_PATHS {
        let mut args = path.to_vec();
        args.push("--help");
        let (help, code) = run(&args);
        assert_eq!(code, 0, "`{} --help` exited {code}", path.join(" "));
        let title = if path.is_empty() {
            "lex-os".to_string()
        } else {
            format!("lex-os {}", path.join(" "))
        };
        out.push_str("\n===== ");
        out.push_str(&title);
        out.push_str(" =====\n");
        out.push_str(help.trim_end());
        out.push('\n');
    }
    out
}

fn reference_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/cli-reference.txt")
}

#[test]
fn cli_reference_is_in_sync() {
    let current = render_reference();
    let path = reference_path();
    if std::env::var_os("UPDATE_CLI_REF").is_some() {
        std::fs::write(&path, &current).expect("write reference");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        current, committed,
        "CLI help has drifted from tests/cli-reference.txt.\n\
         Regenerate with: UPDATE_CLI_REF=1 cargo test -p lex-os --test cli_contract"
    );
}

/// Pull every `lex-os` subcommand path the README invokes. Returns the
/// argument paths (e.g. `["manifest", "sample"]`), skipping feature-gated
/// commands (`box-smoke`) that aren't built into the default binary.
fn readme_command_paths() -> Vec<Vec<String>> {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("read README");
    let mut paths = Vec::new();

    // Top-level commands and which take a sub-subcommand.
    let groups = ["manifest", "audit"];
    let leaves = ["run", "resolve", "check", "introspect"];

    for raw in readme.lines() {
        // Two invocation forms appear: runnable `cargo run -p lex-os -- …`
        // and inline prose `` `lex-os …` ``.
        let rest = if let Some(i) = raw.find("cargo run -p lex-os -- ") {
            &raw[i + "cargo run -p lex-os -- ".len()..]
        } else if let Some(i) = raw.find("`lex-os ") {
            &raw[i + "`lex-os ".len()..]
        } else {
            continue;
        };
        // Stop at a comment, redirection, backtick, or line-continuation.
        let rest = rest
            .split(['#', '>', '`', '\\'])
            .next()
            .unwrap_or("")
            .trim();

        let mut toks = rest.split_whitespace().peekable();
        // Skip a leading global option group (`--output json`).
        while let Some(t) = toks.peek() {
            if *t == "--output" {
                toks.next();
                toks.next(); // its value
            } else if t.starts_with('-') {
                toks.next();
            } else {
                break;
            }
        }
        let Some(first) = toks.next() else { continue };
        if first == "box-smoke" {
            continue; // firecracker-gated; not in the default binary
        }
        let mut path = vec![first.to_string()];
        if groups.contains(&first) {
            if let Some(sub) = toks.peek() {
                if !sub.starts_with('-') {
                    path.push(toks.next().unwrap().to_string());
                }
            }
        } else if !leaves.contains(&first) {
            // An unknown top-level token — keep it so the assertion below
            // flags a command the README invented.
        }
        paths.push(path);
    }
    paths
}

#[test]
fn every_readme_command_is_real() {
    let paths = readme_command_paths();
    assert!(
        paths.len() >= 8,
        "expected to extract several README commands, got {}",
        paths.len()
    );
    for path in &paths {
        let refs: Vec<&str> = path.iter().map(String::as_str).collect();
        let mut args = refs.clone();
        args.push("--help");
        let (out, code) = run(&args);
        assert_eq!(
            code,
            0,
            "README invokes `lex-os {}`, but the binary doesn't accept it:\n{out}",
            path.join(" ")
        );
    }
}

#[test]
fn documented_exit_codes_hold() {
    let analyze = repo_root().join("examples/analyze.json");
    let over_reach = repo_root().join("examples/agent-programs/submit_report.lex");
    let honest = repo_root().join("examples/agent-programs/analyze_only.lex");
    let analyze = analyze.to_str().unwrap();

    // Read-only / self-contained commands the README shows: all succeed.
    for args in [
        vec!["introspect"],
        vec!["manifest", "sample"],
        vec!["resolve"],
    ] {
        let (_out, code) = run(&args);
        assert_eq!(code, 0, "`lex-os {}` should exit 0", args.join(" "));
    }

    // The type-check wall: a `[net]` program under a `network: none` grant
    // is refused *before it runs* with PreconditionFailed (exit 8) — the
    // exact claim the README makes for `lex-os check`.
    let (out, code) = run(&["check", "--grant", analyze, over_reach.to_str().unwrap()]);
    assert_eq!(
        code, 8,
        "over-reaching program should be refused (exit 8):\n{out}"
    );

    // …and an honest program within the grant passes the wall.
    let (out, code) = run(&["check", "--grant", analyze, honest.to_str().unwrap()]);
    assert_eq!(
        code, 0,
        "honest program should pass the type-check wall:\n{out}"
    );
}
