//! Host-side tap device + iptables rule management.

use std::net::ToSocketAddrs;
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
        // Resolve to an IP ourselves and pin the rule to it. Letting iptables
        // resolve `-d <name>` is brittle (it fails the whole insert if the name
        // is unknown on the host) and ambiguous (it may differ from what the
        // guest dials). If a host does not resolve, skip its ACCEPT and warn —
        // the box simply can't reach it (fail-closed), which never widens the
        // grant, so provisioning still proceeds.
        match resolve_host(&host, port) {
            Some(ip) => {
                let ip = ip.to_string();
                run(
                    "iptables",
                    &as_str_slice(&build_iptables_accept_rule(tap, &ip, port)),
                )?;
            }
            None => {
                eprintln!(
                    "lex-os perimeter: egress host `{host}:{port}` does not resolve on this host; \
                     the box cannot reach it (ACCEPT skipped, fail-closed)"
                );
            }
        }
    }
    run("iptables", &as_str_slice(&build_iptables_drop_rule(tap)))?;
    Ok(())
}

/// Make allowlisted egress actually round-trip: accept return traffic to the
/// guest, and masquerade the guest's private source out to the LAN/WAN. The
/// FORWARD ACCEPT only lets the SYN out (`-i tap`); replies arrive on `-o tap`
/// and the guest's `169.254.x` source needs NAT to come back. This does NOT
/// widen the wall — non-allowlisted destinations still hit the `-i tap` DROP.
pub(super) fn install_nat(tap: &str, guest_cidr: &str) -> Result<(), NetError> {
    run(
        "iptables",
        &[
            "-A",
            "FORWARD",
            "-o",
            tap,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )?;
    // iptables masks `-s host/prefix` to the network, so passing the host CIDR
    // (e.g. 169.254.42.1/30) masquerades the whole guest subnet.
    run(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            guest_cidr,
            "-j",
            "MASQUERADE",
        ],
    )?;
    Ok(())
}

/// Remove the NAT/return rules added by [`install_nat`]. Idempotent: loops
/// until iptables reports the rule is gone, and never flushes whole chains.
pub(super) fn flush_nat(tap: &str, guest_cidr: &str) {
    let del_return = [
        "-D",
        "FORWARD",
        "-o",
        tap,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ];
    while Command::new("iptables")
        .args(del_return)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {}
    let del_masq = [
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        guest_cidr,
        "-j",
        "MASQUERADE",
    ];
    while Command::new("iptables")
        .args(del_masq)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {}
}

/// Resolve `host:port` to a single IP, or `None` if it does not resolve.
fn resolve_host(host: &str, port: u16) -> Option<std::net::IpAddr> {
    (host, port)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|sa| sa.ip())
}

/// Remove only the FORWARD rules this backend added (scoped to `tap`).
/// Reads the live chain and deletes our rules one by one. It deliberately
/// does NOT flush the chain: the host may carry Docker / libvirt / VPN rules
/// on FORWARD that must survive a box teardown. Idempotent: ignores misses.
pub(super) fn flush_egress_rules(tap: &str) -> Result<(), NetError> {
    let listing = Command::new("iptables")
        .args(["-S", "FORWARD"])
        .output()
        .map_err(|_| NetError::MissingTool { cmd: "iptables" })?;
    if !listing.status.success() {
        // Can't enumerate — bail rather than risk a blunt flush.
        return Ok(());
    }
    let text = String::from_utf8_lossy(&listing.stdout);
    for args in scoped_delete_args(&text, tap) {
        let _ = run("iptables", &as_str_slice(&args));
    }
    Ok(())
}

/// Given `iptables -S FORWARD` output, build the argv for each `-D` that
/// removes a rule scoped to `tap` — and only those. Every other rule
/// (Docker, libvirt, VPN) is left untouched. Each result is the args that
/// follow `iptables`.
pub(super) fn scoped_delete_args(forward_listing: &str, tap: &str) -> Vec<Vec<String>> {
    let needle = format!("-i {tap} ");
    forward_listing
        .lines()
        .filter(|l| l.starts_with("-A ") && l.contains(&needle))
        .map(|l| {
            let mut args = vec!["-D".to_string()];
            args.extend(
                l.trim_start_matches("-A ")
                    .split_whitespace()
                    .map(String::from),
            );
            args
        })
        .collect()
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
    fn scoped_delete_removes_only_our_tap_rules_not_docker_or_vpn() {
        // A realistic FORWARD chain with Docker, libvirt and our two rules.
        let listing = "\
-P FORWARD DROP
-A FORWARD -j DOCKER-USER
-A FORWARD -i docker0 -o eth0 -j ACCEPT
-A FORWARD -i tap-lex0 -d 169.254.42.1/32 -p tcp -m tcp --dport 443 -j ACCEPT
-A FORWARD -i virbr0 -j ACCEPT
-A FORWARD -i tap-lex0 -j DROP";
        let dels = scoped_delete_args(listing, "tap-lex0");
        // Exactly our two rules, transformed -A -> -D; nothing else.
        assert_eq!(dels.len(), 2);
        assert_eq!(
            dels[0],
            vec![
                "-D",
                "FORWARD",
                "-i",
                "tap-lex0",
                "-d",
                "169.254.42.1/32",
                "-p",
                "tcp",
                "-m",
                "tcp",
                "--dport",
                "443",
                "-j",
                "ACCEPT"
            ]
        );
        assert_eq!(
            dels[1],
            vec!["-D", "FORWARD", "-i", "tap-lex0", "-j", "DROP"]
        );
        // Sanity: a different tap name matches none of these.
        assert!(scoped_delete_args(listing, "tap-other").is_empty());
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
