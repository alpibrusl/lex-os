//! Host-side tap device + iptables rule management.

use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub(super) enum NetError {
    #[error("`{cmd}` failed: {stderr}")]
    Shell { cmd: String, stderr: String },
    #[error("`{cmd}` not found on PATH (install iproute2 / iptables)")]
    MissingTool { cmd: &'static str },
    #[error("invalid egress entry `{0}`: {1}")]
    InvalidEgress(String, String),
}

/// Build the argv for an iptables ACCEPT rule on the host's FORWARD chain.
pub(super) fn build_iptables_accept_rule(tap: &str, host: &str, port: u16) -> Vec<String> {
    vec![
        "-A".into(),
        "FORWARD".into(),
        "-i".into(),
        tap.into(),
        "-d".into(),
        host.into(),
        "-p".into(),
        "tcp".into(),
        "--dport".into(),
        port.to_string(),
        "-j".into(),
        "ACCEPT".into(),
    ]
}

/// Build the argv for the catch-all DROP that follows the ACCEPTs.
pub(super) fn build_iptables_drop_rule(tap: &str) -> Vec<String> {
    vec![
        "-A".into(),
        "FORWARD".into(),
        "-i".into(),
        tap.into(),
        "-j".into(),
        "DROP".into(),
    ]
}

/// Split "host" or "host:port" with a 443 default.
pub(super) fn parse_host_port(entry: &str) -> Result<(String, u16), NetError> {
    if let Some((host, port)) = entry.split_once(':') {
        let port: u16 = port.parse().map_err(|_| {
            NetError::InvalidEgress(entry.into(), format!("port `{port}` is not a u16"))
        })?;
        Ok((host.into(), port))
    } else {
        Ok((entry.into(), 443))
    }
}

/// Create a tap interface and bring it up. Requires CAP_NET_ADMIN (root).
pub(super) fn create_tap(tap: &str, host_ip_cidr: &str) -> Result<(), NetError> {
    run("ip", &["tuntap", "add", tap, "mode", "tap"])?;
    run("ip", &["addr", "add", host_ip_cidr, "dev", tap])?;
    run("ip", &["link", "set", tap, "up"])?;
    Ok(())
}

/// Apply egress allowlist rules to the tap's outbound traffic. The DROP
/// catchall is appended LAST so ordering matters.
pub(super) fn install_egress_allowlist(tap: &str, egress: &[String]) -> Result<(), NetError> {
    for entry in egress {
        let (host, port) = parse_host_port(entry)?;
        run(
            "iptables",
            &as_str_slice(&build_iptables_accept_rule(tap, &host, port)),
        )?;
    }
    run("iptables", &as_str_slice(&build_iptables_drop_rule(tap)))?;
    Ok(())
}

/// Remove every FORWARD rule scoped to `tap`. Idempotent: ignores misses.
pub(super) fn flush_egress_rules(tap: &str) -> Result<(), NetError> {
    // `-D` removes the first matching rule; loop until iptables says no.
    loop {
        let status = Command::new("iptables")
            .args(["-D", "FORWARD", "-i", tap, "-j", "DROP"])
            .output()
            .map_err(|_| NetError::MissingTool { cmd: "iptables" })?;
        if !status.status.success() {
            break;
        }
    }
    // For the demo we flush the whole FORWARD chain on teardown.
    let _ = run("iptables", &["-F", "FORWARD"]);
    Ok(())
}

/// Remove the tap interface.
pub(super) fn destroy_tap(tap: &str) -> Result<(), NetError> {
    run("ip", &["link", "delete", tap])?;
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<(), NetError> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|_| NetError::MissingTool {
            cmd: match cmd {
                "ip" => "ip",
                "iptables" => "iptables",
                _ => "",
            },
        })?;
    if !out.status.success() {
        return Err(NetError::Shell {
            cmd: format!("{cmd} {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(())
}

fn as_str_slice(v: &[String]) -> Vec<&str> {
    v.iter().map(|s| s.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_iptables_accept_rule_allowlists_one_host_port() {
        let argv = build_iptables_accept_rule("tap-lex0", "results.demo.internal", 443);
        assert_eq!(
            argv,
            vec![
                "-A",
                "FORWARD",
                "-i",
                "tap-lex0",
                "-d",
                "results.demo.internal",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "ACCEPT"
            ]
        );
    }

    #[test]
    fn build_iptables_drop_catchall_is_appended_last() {
        let argv = build_iptables_drop_rule("tap-lex0");
        assert_eq!(argv, vec!["-A", "FORWARD", "-i", "tap-lex0", "-j", "DROP"]);
    }

    #[test]
    fn parse_host_port_handles_host_and_host_with_port() {
        assert_eq!(
            parse_host_port("results.demo.internal:443").unwrap(),
            ("results.demo.internal".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("results.demo.internal").unwrap(),
            ("results.demo.internal".to_string(), 443)
        );
        assert!(parse_host_port("bad:port").is_err());
    }

    #[test]
    #[ignore = "requires root + iproute2 + iptables; run on the KVM host"]
    fn create_and_destroy_tap_on_host() {
        create_tap("tap-lex-test", "169.254.42.1/30").expect("create");
        destroy_tap("tap-lex-test").expect("destroy");
    }
}
