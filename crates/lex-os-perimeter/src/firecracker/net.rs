//! Host-side tap device + iptables rule management.
//!
//! # The wall runs before DNAT, and that is the whole design (#79)
//!
//! The first real `wall2.sh` run on a KVM host found the box reaching a
//! host service the grant never allowlisted. The rules were right; the
//! *hook* was wrong. Netfilter's path is:
//!
//! ```text
//! raw/PREROUTING → conntrack → mangle/PREROUTING → nat/PREROUTING
//!     → [routing decision] → INPUT or FORWARD → filter rules
//! ```
//!
//! The wall used to live in filter/FORWARD and filter/INPUT — after the
//! routing decision. Docker puts this in nat/PREROUTING:
//!
//! ```text
//! -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
//! ```
//!
//! The tap gateway is a LOCAL address, so a guest packet aimed at it is
//! DNAT'd to a container before any filter rule runs. That rewrites the
//! destination (so `-d` allowlist matches compare against an address the
//! guest never named) *and* changes the routing decision (so host-local
//! traffic goes to FORWARD, not INPUT, and the INPUT fence never sees
//! it). No ordering of filter rules can fix either.
//!
//! So the wall lives in **mangle/PREROUTING**, in a private chain jumped
//! to from position 1. There the original destination is intact and no
//! other subsystem has had a say. A private chain also means teardown is
//! a flush, not a scoped hunt through rules other tools own.
//!
//! The filter-table ACCEPTs remain, and are not the wall: they exist so
//! allowlisted traffic still passes on hosts whose FORWARD or INPUT
//! policy is DROP. The catch-alls that used to sit beside them are gone,
//! because a wall that cannot be made correct is worse than no wall — it
//! reads as protection.

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

/// The private chain holding the egress wall.
///
/// One name for every tap: a host runs one box at a time here, and the
/// jump rule is what scopes the chain to an interface. A per-tap name
/// would leak chains on every crashed run.
pub(super) const EGRESS_CHAIN: &str = "LEX_OS_EGRESS";

/// `-t mangle`, as argv. Every rule of the wall carries it.
fn mangle(rest: &[&str]) -> Vec<String> {
    let mut v = vec!["-t".to_string(), "mangle".to_string()];
    v.extend(rest.iter().map(|s| s.to_string()));
    v
}

/// Jump into the wall from **position 1** of mangle/PREROUTING.
///
/// Inserted, never appended. Appending puts the wall after whatever
/// Docker, libvirt or a VPN already installed, and on a host with any
/// pre-existing ACCEPT that is the same as having no wall at all — which
/// is exactly how #79 stayed invisible.
pub(super) fn build_mangle_jump_rule(tap: &str) -> Vec<String> {
    mangle(&["-I", "PREROUTING", "1", "-i", tap, "-j", EGRESS_CHAIN])
}

/// The same rule, as a delete.
pub(super) fn build_mangle_unjump_rule(tap: &str) -> Vec<String> {
    mangle(&["-D", "PREROUTING", "-i", tap, "-j", EGRESS_CHAIN])
}

/// Let the rest of an already-permitted flow through without re-matching
/// the allowlist. `RETURN` rather than `ACCEPT`: it hands the packet back
/// to PREROUTING so anything another tool installs later still runs.
/// `ACCEPT` here would silently skip the rest of the table.
pub(super) fn build_mangle_established_rule() -> Vec<String> {
    mangle(&[
        "-A",
        EGRESS_CHAIN,
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "RETURN",
    ])
}

/// One allowlisted destination, matched on the address the guest
/// actually dialled — which is only true before nat/PREROUTING.
pub(super) fn build_mangle_accept_rule(host: &str, port: u16) -> Vec<String> {
    mangle(&[
        "-A",
        EGRESS_CHAIN,
        "-d",
        host,
        "-p",
        "tcp",
        "--dport",
        &port.to_string(),
        "-j",
        "RETURN",
    ])
}

/// The catch-all. Last in the chain, and the chain is entered from
/// position 1, so nothing on the host can preempt it.
pub(super) fn build_mangle_drop_rule() -> Vec<String> {
    mangle(&["-A", EGRESS_CHAIN, "-j", "DROP"])
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

/// Build an INPUT-chain ACCEPT for an allowlisted host:port. Traffic the box
/// sends to a *host-local* address (e.g. the tap-gateway results-stub) is
/// delivered locally via INPUT, not FORWARD, so the grant's allowlist must be
/// mirrored here for those targets to be reachable.
pub(super) fn build_iptables_input_accept_rule(tap: &str, host: &str, port: u16) -> Vec<String> {
    vec![
        "-A".into(),
        "INPUT".into(),
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

/// Accept replies on flows the box already opened to an allowlisted host-local
/// target (conntrack ESTABLISHED,RELATED), so multi-packet exchanges complete.
pub(super) fn build_iptables_input_established_rule(tap: &str) -> Vec<String> {
    vec![
        "-A".into(),
        "INPUT".into(),
        "-i".into(),
        tap.into(),
        "-m".into(),
        "conntrack".into(),
        "--ctstate".into(),
        "ESTABLISHED,RELATED".into(),
        "-j".into(),
        "ACCEPT".into(),
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
/// Create the host tap. When `owner` is `Some((uid, gid))` the tap is created
/// owned by that uid/gid so a privilege-dropped (jailed) firecracker can open
/// it — without it, only root could attach the device. The host keeps the .1 of
/// the /30 and stays able to administer the interface either way.
pub(super) fn create_tap(
    tap: &str,
    host_ip_cidr: &str,
    owner: Option<(u32, u32)>,
) -> Result<(), NetError> {
    let mut add = vec![
        "tuntap".to_string(),
        "add".into(),
        tap.into(),
        "mode".into(),
        "tap".into(),
    ];
    if let Some((uid, gid)) = owner {
        add.extend([
            "user".into(),
            uid.to_string(),
            "group".into(),
            gid.to_string(),
        ]);
    }
    run("ip", &as_str_slice(&add))?;
    run("ip", &["addr", "add", host_ip_cidr, "dev", tap])?;
    run("ip", &["link", "set", tap, "up"])?;
    Ok(())
}

/// Apply the egress wall.
///
/// The wall itself is the private mangle chain (#79); the filter-table
/// ACCEPTs that follow are **not** part of it. They exist so allowlisted
/// traffic still passes on a host whose FORWARD or INPUT policy is DROP,
/// and they can only ever permit what the wall already let past.
pub(super) fn install_egress_allowlist(tap: &str, egress: &[String]) -> Result<(), NetError> {
    // A private chain, rebuilt from empty. A crashed run may have left
    // one behind, and a wall inheriting half of a previous grant's
    // allowlist is a wall nobody can reason about.
    let _ = run("iptables", &as_str_slice(&mangle(&["-N", EGRESS_CHAIN])));
    run("iptables", &as_str_slice(&mangle(&["-F", EGRESS_CHAIN])))?;
    run("iptables", &as_str_slice(&build_mangle_established_rule()))?;

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
                    &as_str_slice(&build_mangle_accept_rule(&ip, port)),
                )?;
                // Permissive helpers on the filter table, for hosts whose
                // policy is DROP. Harmless where it is ACCEPT.
                run(
                    "iptables",
                    &as_str_slice(&build_iptables_accept_rule(tap, &ip, port)),
                )?;
                run(
                    "iptables",
                    &as_str_slice(&build_iptables_input_accept_rule(tap, &ip, port)),
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

    // The catch-all, then the jump. In that order: a chain reachable
    // before it is fail-closed would pass whatever arrived in between.
    run("iptables", &as_str_slice(&build_mangle_drop_rule()))?;
    run(
        "iptables",
        &as_str_slice(&build_iptables_input_established_rule(tap)),
    )?;
    // Idempotent: drop any jump left by a crashed run before adding ours,
    // or PREROUTING accumulates duplicates.
    let _ = run("iptables", &as_str_slice(&build_mangle_unjump_rule(tap)));
    run("iptables", &as_str_slice(&build_mangle_jump_rule(tap)))?;
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
    // The wall first (#79). Unjump before flushing, so there is never an
    // instant where PREROUTING points at an empty — therefore permissive
    // — chain. Every step is best-effort: teardown runs on the failure
    // path too, and a box that cannot be cleaned up is worse than a rule
    // that outlives it.
    let _ = run("iptables", &as_str_slice(&build_mangle_unjump_rule(tap)));
    let _ = run("iptables", &as_str_slice(&mangle(&["-F", EGRESS_CHAIN])));
    let _ = run("iptables", &as_str_slice(&mangle(&["-X", EGRESS_CHAIN])));

    // Then the permissive filter-table helpers. These are ACCEPTs rather
    // than the wall, but they are still ours and still scoped to the tap.
    // Deliberately NOT a flush: the host may carry Docker / libvirt / VPN
    // rules on these chains that must survive a box teardown.
    for chain in ["FORWARD", "INPUT"] {
        let listing = Command::new("iptables")
            .args(["-S", chain])
            .output()
            .map_err(|_| NetError::MissingTool { cmd: "iptables" })?;
        if !listing.status.success() {
            // Can't enumerate — skip this chain rather than risk a blunt flush.
            continue;
        }
        let text = String::from_utf8_lossy(&listing.stdout);
        for args in scoped_delete_args(&text, tap) {
            let _ = run("iptables", &as_str_slice(&args));
        }
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

    /// The wall is entered from **position 1** of mangle/PREROUTING.
    ///
    /// This is the fix for #79 in one assertion. Appending put the wall
    /// after Docker's rules, where a pre-existing ACCEPT made it
    /// decorative; and mangle/PREROUTING runs *before* nat, so the
    /// destination the guest dialled is still the destination being
    /// matched.
    #[test]
    fn the_wall_is_entered_from_position_one_of_mangle_prerouting() {
        let argv = build_mangle_jump_rule("tap-lex0");
        assert_eq!(
            argv,
            vec![
                "-t",
                "mangle",
                "-I",
                "PREROUTING",
                "1",
                "-i",
                "tap-lex0",
                "-j",
                "LEX_OS_EGRESS"
            ]
        );
        // `-A` would reintroduce #79 exactly.
        assert!(!argv.contains(&"-A".to_string()));
    }

    /// The unjump must match the jump, or teardown leaves a chain nobody
    /// can enter and a PREROUTING rule pointing at it.
    #[test]
    fn the_unjump_matches_the_jump() {
        let up = build_mangle_jump_rule("tap-lex0");
        let down = build_mangle_unjump_rule("tap-lex0");
        assert_eq!(down[0..2], ["-t", "mangle"]);
        assert_eq!(down[2], "-D");
        // Same interface and same target, so it deletes the rule we added.
        assert!(down.contains(&"tap-lex0".to_string()));
        assert!(down.contains(&"LEX_OS_EGRESS".to_string()));
        assert!(up.contains(&"LEX_OS_EGRESS".to_string()));
    }

    /// The catch-all lives in the private chain and drops. Nothing on the
    /// host can precede it, because the chain is entered at position 1.
    #[test]
    fn the_catchall_drops_inside_the_private_chain() {
        assert_eq!(
            build_mangle_drop_rule(),
            vec!["-t", "mangle", "-A", "LEX_OS_EGRESS", "-j", "DROP"]
        );
    }

    /// An allowlisted destination returns to PREROUTING rather than
    /// ACCEPTing, so rules another tool installs later still run.
    #[test]
    fn an_allowlisted_destination_returns_rather_than_accepts() {
        let argv = build_mangle_accept_rule("169.254.42.1", 8080);
        assert_eq!(
            argv,
            vec![
                "-t",
                "mangle",
                "-A",
                "LEX_OS_EGRESS",
                "-d",
                "169.254.42.1",
                "-p",
                "tcp",
                "--dport",
                "8080",
                "-j",
                "RETURN"
            ]
        );
        assert!(!argv.contains(&"ACCEPT".to_string()));
    }

    #[test]
    fn input_accept_mirrors_the_allowlist_on_the_input_chain() {
        // Host-local targets (the tap-gateway results-stub) arrive via INPUT, so
        // the same grant entry must produce an INPUT ACCEPT, not only FORWARD.
        let argv = build_iptables_input_accept_rule("tap-lex0", "169.254.42.1", 443);
        assert_eq!(
            argv,
            vec![
                "-A",
                "INPUT",
                "-i",
                "tap-lex0",
                "-d",
                "169.254.42.1",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "ACCEPT"
            ]
        );
    }

    /// #79's regression test, at the level a unit test can reach: the
    /// wall must not be built out of filter-table rules at all.
    ///
    /// A packet DNAT'd by Docker has already had its destination
    /// rewritten and its chain reassigned by the time filter runs, so a
    /// DROP there is unreachable for exactly the traffic it was written
    /// to stop. Whatever else changes, the catch-all belongs in mangle.
    #[test]
    fn the_catchall_is_not_in_the_filter_table() {
        let drop = build_mangle_drop_rule();
        assert_eq!(drop[0..2], ["-t", "mangle"]);
        assert!(!drop.contains(&"FORWARD".to_string()));
        assert!(!drop.contains(&"INPUT".to_string()));
    }

    #[test]
    fn input_established_accept_lets_allowed_flows_complete() {
        let argv = build_iptables_input_established_rule("tap-lex0");
        assert_eq!(
            argv,
            vec![
                "-A",
                "INPUT",
                "-i",
                "tap-lex0",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT"
            ]
        );
    }

    #[test]
    fn scoped_delete_cleans_our_input_rules_too() {
        // The INPUT chain also carries host-local accept/established/drop rules;
        // teardown must remove exactly ours (keeping any host INPUT policy).
        let listing = "\
-P INPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -i tap-lex0 -d 169.254.42.1/32 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -i tap-lex0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i tap-lex0 -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
";
        let dels = scoped_delete_args(listing, "tap-lex0");
        assert_eq!(dels.len(), 3, "exactly our three tap INPUT rules");
        assert!(dels.iter().all(|d| d[0] == "-D" && d[1] == "INPUT"));
        // The host's lo and ssh rules are untouched.
        assert!(dels.iter().all(|d| !d.contains(&"lo".to_string())));
        assert!(dels.iter().all(|d| !d.contains(&"22".to_string())));
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
        create_tap("tap-lex-test", "169.254.42.1/30", None).expect("create");
        destroy_tap("tap-lex-test").expect("destroy");
    }
}
