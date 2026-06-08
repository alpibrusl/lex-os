//! The simulated perimeter must never be mistaken for a real boundary
//! (toward lex-os#23). Every `run` declares the boundary it was actually
//! enforced behind — in machine output and with a loud human warning — so
//! a portable, in-process run can't be confused with a sealed microVM.
//!
//! The real Firecracker box is now the default, so the simulator is an explicit
//! `--simulated` opt-in. This test exercises that opt-in (no KVM needed) and
//! asserts the disclosure still says "not a boundary". The real path flips
//! `security_boundary` to true and is exercised by the KVM-gated CI workflow.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_lex-os");

#[test]
fn run_discloses_the_simulated_perimeter() {
    let out = Command::new(BIN)
        .args(["--output", "json", "run", "--simulated"])
        .output()
        .expect("spawn lex-os");

    assert!(
        out.status.success(),
        "demo run should reach a terminal outcome"
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Machine-readable: the run output declares the (non-)boundary.
    assert!(
        stdout.contains("\"security_boundary\": false"),
        "run JSON must report security_boundary=false on the simulated build:\n{stdout}"
    );
    assert!(
        stdout.contains("\"perimeter\": \"simulated\""),
        "run JSON must name the simulated perimeter:\n{stdout}"
    );

    // Human-readable: a loud warning that this is not a real boundary.
    assert!(
        stderr.contains("SIMULATED PERIMETER") && stderr.contains("NOT a security boundary"),
        "a simulated run must warn loudly on stderr:\n{stderr}"
    );

    // Sanity: the demo still reaches GoalMet, so the disclosure rides on a
    // working run rather than masking a failure.
    assert!(
        stdout.contains("\"outcome\": \"GoalMet\""),
        "demo should reach GoalMet:\n{stdout}"
    );
}

/// Refuse, don't downgrade: where the real perimeter is unavailable, a bare
/// `run` (no `--simulated`) must error and point at the opt-in — never silently
/// fall back to a non-boundary. Only asserted when `/dev/kvm` is absent; on a
/// KVM host the default `run` would try to boot a real box, which a unit test
/// must not do.
#[test]
fn run_refuses_to_downgrade_without_an_explicit_opt_in() {
    if std::path::Path::new("/dev/kvm").exists() {
        return; // real perimeter available here — skip (don't boot a VM in a test)
    }
    let out = Command::new(BIN)
        .args(["--output", "json", "run"])
        .output()
        .expect("spawn lex-os");

    assert!(
        !out.status.success(),
        "without --simulated and no /dev/kvm, run must refuse rather than downgrade"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("--simulated"),
        "the refusal must point the user at --simulated:\n{combined}"
    );
}
