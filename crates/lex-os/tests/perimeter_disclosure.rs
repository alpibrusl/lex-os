//! The simulated perimeter must never be mistaken for a real boundary
//! (toward lex-os#23). Every `run` declares the boundary it was actually
//! enforced behind — in machine output and with a loud human warning — so
//! a portable, in-process run can't be confused with a sealed microVM.
//!
//! This binary is built without the `firecracker` feature (the default),
//! so the perimeter is simulated and the disclosure must say so. The
//! firecracker build flips `security_boundary` to true; that path needs a
//! KVM host and is exercised by the KVM-gated CI workflow, not here.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_lex-os");

#[test]
fn run_discloses_the_simulated_perimeter() {
    let out = Command::new(BIN)
        .args(["--output", "json", "run"])
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
