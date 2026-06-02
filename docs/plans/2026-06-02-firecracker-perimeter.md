# Firecracker microVM Perimeter — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the in-process `FirecrackerPerimeter` skeleton with a real microVM backend that (a) boots a Firecracker VM via its HTTP API, (b) wires a tap device under host-side iptables matching the grant's egress allowlist, and (c) tears down cleanly. This makes Wall 2 of the lex-os demo (`curl evil.com` dies at the kernel) materially true.

**Architecture:** A hand-rolled HTTP/1.1 client over `UnixStream` talks to Firecracker's `--api-sock`. Tap-device and iptables management is delegated to `ip`/`iptables` shell-outs (CAP_NET_ADMIN required). The supervisor spawns Firecracker as a child process; `provision` boots it and installs egress rules on the host's tap interface; `destroy` SIGKILLs the child and cleans up rules + tap. The agent inside the VM is root on a writable rootfs; the egress allowlist is enforced on the host, on a tap device the guest does not own.

**Tech Stack:** Rust (std-only — no new workspace deps), `iproute2` (`ip` command), `iptables`, Firecracker v1.9+ binary, an x86_64 guest kernel (`vmlinux`), and an ext4 rootfs.

**Resolved design choices** (from planning conversation):
- **Firewall:** `iptables` (more docs, friendlier for live debugging).
- **TLS for `results.demo.internal`:** none. The kernel-egress wall fires on dst IP+port; TLS layer is irrelevant. The agent's curls use `http://`.
- **Privileges:** `lex-os` runs as **root** on the demo host. One process owns tap creation, iptables, Firecracker spawn, and teardown.
- **VM-internal execution:** init-script-on-boot (rootfs `/sbin/init` runs the attack script, output to console captured by Firecracker stdout). SSH-into-VM is a follow-up.

**Sandbox limits:** Tasks marked **⚠ KVM-only** require `/dev/kvm` and cannot be validated in the current development sandbox. Everything else (refactor, HTTP client, command-builders, unit tests) is sandbox-friendly.

---

## File Structure

**New:**
- `crates/lex-os-perimeter/src/firecracker/mod.rs` — top-level `FirecrackerPerimeter`, replaces the current single-file `firecracker.rs`.
- `crates/lex-os-perimeter/src/firecracker/api.rs` — hand-rolled HTTP/1.1 client over `UnixStream`.
- `crates/lex-os-perimeter/src/firecracker/net.rs` — tap device + iptables rule management.
- `crates/lex-os-perimeter/src/firecracker/vm.rs` — Firecracker child-process lifecycle.
- `demo/setup-assets.sh` — fetch firecracker binary + guest kernel + rootfs into `demo/assets/`.
- `demo/assets/.gitignore` — ignore the binary blobs.
- `demo/host-check.sh` — verify `/dev/kvm`, `ip`, `iptables`, `curl` are all available.
- `demo/init-attack.sh` — the rootfs `/sbin/init` script that runs `attacks/02_curl_evil.sh` and halts.

**Modified:**
- `crates/lex-os-perimeter/src/lib.rs` — change `mod firecracker;` reference (no other change).
- `crates/lex-os-perimeter/Cargo.toml` — no new deps; `firecracker` feature stays empty.
- `demo/run.sh` — pass `--features firecracker` to cargo, run host-check pre-flight.
- `demo/scenario.md` — update setup section, Wall 2 commands, "when the demo will break".
- `demo/attacks/02_curl_evil.sh` — refresh: this script now executes inside the VM (no longer a placeholder).

**Deleted:**
- `crates/lex-os-perimeter/src/firecracker.rs` — replaced by the new `firecracker/` directory module.

---

## Task 1: Refactor `firecracker.rs` → `firecracker/` module (sandbox-friendly)

Move the existing skeleton into a directory module with sibling files for `api`, `net`, `vm`. Keeps later tasks small.

**Files:**
- Delete: `crates/lex-os-perimeter/src/firecracker.rs`
- Create: `crates/lex-os-perimeter/src/firecracker/mod.rs` (moved content)
- Create: `crates/lex-os-perimeter/src/firecracker/api.rs` (placeholder)
- Create: `crates/lex-os-perimeter/src/firecracker/net.rs` (placeholder)
- Create: `crates/lex-os-perimeter/src/firecracker/vm.rs` (placeholder)

- [ ] **Step 1: Create empty siblings**

```rust
// crates/lex-os-perimeter/src/firecracker/api.rs
//! HTTP/1.1 client over `UnixStream` for the Firecracker management API.
```

```rust
// crates/lex-os-perimeter/src/firecracker/net.rs
//! Host-side tap device + iptables rule management.
```

```rust
// crates/lex-os-perimeter/src/firecracker/vm.rs
//! Firecracker child-process lifecycle (spawn + wait-for-socket + SIGKILL).
```

- [ ] **Step 2: Move firecracker.rs to firecracker/mod.rs**

```bash
git mv crates/lex-os-perimeter/src/firecracker.rs crates/lex-os-perimeter/src/firecracker/mod.rs
```

- [ ] **Step 3: Declare the new submodules from mod.rs**

Insert at the top of `crates/lex-os-perimeter/src/firecracker/mod.rs`, after the existing `//!` doc:

```rust
mod api;
mod net;
mod vm;
```

- [ ] **Step 4: Verify everything still compiles and tests pass**

Run:
```bash
cargo build --features firecracker
cargo test --features firecracker
cargo clippy --all-targets --all-features
```

Expected: build/clippy clean. Three `#[ignore]` tests skipped; everything else green.

- [ ] **Step 5: Commit**

```bash
git add crates/lex-os-perimeter/src/firecracker/
git commit -m "refactor(perimeter): split firecracker.rs into a module (#14)"
```

---

## Task 2: Hand-rolled HTTP/1.1 client over `UnixStream` (sandbox-friendly)

Firecracker's API is a tiny set of `PUT`/`POST` requests with JSON bodies. We use std only — no `hyper`, no `ureq`, no async.

**Files:**
- Modify: `crates/lex-os-perimeter/src/firecracker/api.rs`

- [ ] **Step 1: Write the failing test (round-trip a request through a paired UnixStream)**

```rust
// in crates/lex-os-perimeter/src/firecracker/api.rs

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn put_serializes_a_well_formed_http_request_with_body() {
        let (mut server, client) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            put_json(&client, "/boot-source", "{\"kernel_image_path\":\"/k\"}").unwrap();
        });
        let mut received = Vec::new();
        // 100ms is enough for the in-process write.
        server.set_read_timeout(Some(std::time::Duration::from_millis(100))).unwrap();
        let _ = server.read_to_end(&mut received);
        let text = String::from_utf8_lossy(&received);
        assert!(text.starts_with("PUT /boot-source HTTP/1.1\r\n"), "got: {text}");
        assert!(text.contains("Content-Length: 31\r\n"), "got: {text}");
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("Host: localhost\r\n"));
        assert!(text.ends_with("{\"kernel_image_path\":\"/k\"}"), "got: {text}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --features firecracker -p lex-os-perimeter put_serializes_a_well_formed
```

Expected: FAIL — `put_json` not defined.

- [ ] **Step 3: Implement `put_json` + `post_json` + `wait_for_socket`**

```rust
// crates/lex-os-perimeter/src/firecracker/api.rs

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub(super) enum ApiError {
    #[error("api io: {0}")]
    Io(#[from] std::io::Error),
    #[error("api timeout waiting for {0}")]
    Timeout(String),
    #[error("firecracker returned {status} {reason}: {body}")]
    HttpError { status: u16, reason: String, body: String },
}

/// PUT a JSON body to `path` on the Firecracker socket.
pub(super) fn put_json<S: Write>(stream: &S, path: &str, body: &str) -> Result<(), ApiError>
where
    for<'a> &'a S: Write,
{
    request_json(stream, "PUT", path, body)
}

/// POST a JSON body to `path` on the Firecracker socket.
pub(super) fn post_json<S: Write>(stream: &S, path: &str, body: &str) -> Result<(), ApiError>
where
    for<'a> &'a S: Write,
{
    request_json(stream, "POST", path, body)
}

fn request_json<S: Write>(stream: &S, method: &str, path: &str, body: &str) -> Result<(), ApiError>
where
    for<'a> &'a S: Write,
{
    let mut w = stream;
    write!(
        w,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(())
}

/// Open a connection to the Firecracker socket and apply `f`. The Firecracker
/// API closes the connection after each request, so callers open a fresh one
/// per call.
pub(super) fn with_socket<P, F, T>(sock: P, f: F) -> Result<T, ApiError>
where
    P: AsRef<Path>,
    F: FnOnce(&UnixStream) -> Result<T, ApiError>,
{
    let stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let out = f(&stream)?;
    read_and_check_response(&stream)?;
    Ok(out)
}

fn read_and_check_response(stream: &UnixStream) -> Result<(), ApiError> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let (status, reason) = parse_status_line(&status_line)?;
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    if !(200..300).contains(&status) {
        return Err(ApiError::HttpError {
            status,
            reason,
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    Ok(())
}

fn parse_status_line(line: &str) -> Result<(u16, String), ApiError> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.splitn(3, ' ');
    let _ver = parts.next();
    let status = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let reason = parts.next().unwrap_or("").to_string();
    Ok((status, reason))
}

/// Poll until the socket exists and accepts connections (Firecracker creates
/// it asynchronously on startup).
pub(super) fn wait_for_socket(sock: &Path, timeout: Duration) -> Result<(), ApiError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if sock.exists() {
            if UnixStream::connect(sock).is_ok() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(ApiError::Timeout(format!("{}", sock.display())))
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test --features firecracker -p lex-os-perimeter put_serializes_a_well_formed
```

Expected: PASS.

- [ ] **Step 5: Add a status-line parser test**

```rust
#[test]
fn parse_status_line_extracts_code_and_reason() {
    assert_eq!(parse_status_line("HTTP/1.1 204 No Content\r\n").unwrap(), (204, "No Content".into()));
    assert_eq!(parse_status_line("HTTP/1.1 400 Bad Request\r\n").unwrap(), (400, "Bad Request".into()));
}
```

Run:
```bash
cargo test --features firecracker -p lex-os-perimeter parse_status_line
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/lex-os-perimeter/src/firecracker/api.rs
git commit -m "feat(perimeter): hand-rolled HTTP/1.1 client over UnixStream for Firecracker API (#14)"
```

---

## Task 3: Network helpers — tap device + iptables (sandbox-friendly compile, KVM-only smoke)

Tap device creation and the per-host egress allowlist as iptables rules. Each function is a thin shell-out via `std::process::Command` with explicit error mapping.

**Files:**
- Modify: `crates/lex-os-perimeter/src/firecracker/net.rs`

- [ ] **Step 1: Write the failing test (CommandBuilder shape)**

The shell-outs themselves require root + `ip`/`iptables` so we can't unit-test them in CI. Instead we test the *command construction* via a pure `build_iptables_rule(...)` function that returns the argv.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_iptables_accept_rule_allowlists_one_host_port() {
        let argv = build_iptables_accept_rule("tap-lex0", "results.demo.internal", 443);
        assert_eq!(
            argv,
            vec!["-A", "FORWARD", "-i", "tap-lex0", "-d", "results.demo.internal", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"]
        );
    }

    #[test]
    fn build_iptables_drop_catchall_is_appended_last() {
        let argv = build_iptables_drop_rule("tap-lex0");
        assert_eq!(argv, vec!["-A", "FORWARD", "-i", "tap-lex0", "-j", "DROP"]);
    }

    #[test]
    fn parse_host_port_handles_host_and_host_with_port() {
        assert_eq!(parse_host_port("results.demo.internal:443"), Ok(("results.demo.internal".into(), 443)));
        assert_eq!(parse_host_port("results.demo.internal"), Ok(("results.demo.internal".into(), 443)));
        assert!(parse_host_port("bad:port").is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --features firecracker -p lex-os-perimeter -- net::tests
```

Expected: FAIL — functions undefined.

- [ ] **Step 3: Implement the helpers**

```rust
// crates/lex-os-perimeter/src/firecracker/net.rs

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
        "-A".into(), "FORWARD".into(),
        "-i".into(), tap.into(),
        "-d".into(), host.into(),
        "-p".into(), "tcp".into(),
        "--dport".into(), port.to_string(),
        "-j".into(), "ACCEPT".into(),
    ]
}

/// Build the argv for the catch-all DROP that follows the ACCEPTs.
pub(super) fn build_iptables_drop_rule(tap: &str) -> Vec<String> {
    vec![
        "-A".into(), "FORWARD".into(),
        "-i".into(), tap.into(),
        "-j".into(), "DROP".into(),
    ]
}

/// Split "host" or "host:port" with a 443 default.
pub(super) fn parse_host_port(entry: &str) -> Result<(String, u16), NetError> {
    if let Some((host, port)) = entry.split_once(':') {
        let port: u16 = port
            .parse()
            .map_err(|_| NetError::InvalidEgress(entry.into(), format!("port `{port}` is not a u16")))?;
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
        run("iptables", &as_str_slice(&build_iptables_accept_rule(tap, &host, port)))?;
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
    // Same loop shape isn't possible for ACCEPT rules without knowing each
    // (host, port) again — callers pass the original allowlist when they
    // want explicit removal. For the demo we just flush the whole chain on
    // teardown:
    let _ = run("iptables", &["-F", "FORWARD"]);
    Ok(())
}

/// Remove the tap interface.
pub(super) fn destroy_tap(tap: &str) -> Result<(), NetError> {
    run("ip", &["link", "delete", tap])?;
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<(), NetError> {
    let out = Command::new(cmd).args(args).output().map_err(|_| {
        NetError::MissingTool {
            cmd: match cmd { "ip" => "ip", "iptables" => "iptables", _ => "" },
        }
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
```

- [ ] **Step 4: Run all net tests**

```bash
cargo test --features firecracker -p lex-os-perimeter -- net::tests
```

Expected: PASS (3 tests).

- [ ] **Step 5: Add an ignored integration test for the real shell-outs**

```rust
#[test]
#[ignore = "requires root + iproute2 + iptables; run on the KVM host"]
fn create_and_destroy_tap_on_host() {
    create_tap("tap-lex-test", "169.254.42.1/30").expect("create");
    destroy_tap("tap-lex-test").expect("destroy");
}
```

Run:
```bash
cargo test --features firecracker -p lex-os-perimeter -- net::tests --ignored
```

Expected: ignored in sandbox (no root). On KVM host, PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/lex-os-perimeter/src/firecracker/net.rs
git commit -m "feat(perimeter): tap + iptables helpers for the firecracker backend (#14)"
```

---

## Task 4: Firecracker child-process lifecycle (sandbox-friendly compile)

Spawn `firecracker --api-sock <path>`, capture stdout for the console-attack-output, kill on destroy.

**Files:**
- Modify: `crates/lex-os-perimeter/src/firecracker/vm.rs`

- [ ] **Step 1: Write the failing test (spawn-args shape)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_firecracker_argv_uses_the_api_sock() {
        let argv = build_firecracker_argv(&PathBuf::from("/tmp/fc.sock"));
        assert_eq!(argv, vec!["--api-sock".to_string(), "/tmp/fc.sock".to_string()]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --features firecracker -p lex-os-perimeter -- vm::tests
```

Expected: FAIL.

- [ ] **Step 3: Implement the VM child-process wrapper**

```rust
// crates/lex-os-perimeter/src/firecracker/vm.rs

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use super::api::ApiError;

#[derive(Debug, thiserror::Error)]
pub(super) enum VmError {
    #[error("spawn firecracker: {0}")]
    Spawn(std::io::Error),
    #[error("firecracker binary not found on PATH")]
    MissingBinary,
    #[error("api: {0}")]
    Api(#[from] ApiError),
}

pub(super) struct FirecrackerVm {
    pub(super) sock: PathBuf,
    pub(super) child: Child,
}

impl FirecrackerVm {
    pub(super) fn spawn(sock: PathBuf) -> Result<Self, VmError> {
        if Command::new("firecracker").arg("--version").output().is_err() {
            return Err(VmError::MissingBinary);
        }
        let argv = build_firecracker_argv(&sock);
        let child = Command::new("firecracker")
            .args(&argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(VmError::Spawn)?;
        Ok(Self { sock, child })
    }

    pub(super) fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(super) fn build_firecracker_argv(sock: &Path) -> Vec<String> {
    vec!["--api-sock".to_string(), sock.display().to_string()]
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test --features firecracker -p lex-os-perimeter -- vm::tests
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/lex-os-perimeter/src/firecracker/vm.rs
git commit -m "feat(perimeter): firecracker child-process wrapper (#14)"
```

---

## Task 5: Wire `FirecrackerPerimeter::provision` against the real backend (sandbox-friendly compile)

Replace the stub body with: spawn FC → wait for socket → PUT boot-source → PUT drive → PUT network-iface → create tap → install egress allowlist → POST InstanceStart.

**Files:**
- Modify: `crates/lex-os-perimeter/src/firecracker/mod.rs`

- [ ] **Step 1: Add asset/config constants and a `FirecrackerAssets` struct**

```rust
// at the top of crates/lex-os-perimeter/src/firecracker/mod.rs, after `use` lines

use std::path::PathBuf;
use std::time::Duration;

use api::{post_json, put_json, wait_for_socket, with_socket};
use net::{create_tap, destroy_tap, flush_egress_rules, install_egress_allowlist};
use vm::FirecrackerVm;

/// Paths the perimeter needs to find at runtime. Override per-instance for
/// tests; the defaults match what `demo/setup-assets.sh` produces.
pub struct FirecrackerAssets {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub socket: PathBuf,
    pub tap: String,
    /// Host IP on the tap, CIDR form. The guest gets the .2 address.
    pub host_ip_cidr: String,
}

impl Default for FirecrackerAssets {
    fn default() -> Self {
        Self {
            kernel: PathBuf::from("demo/assets/vmlinux"),
            rootfs: PathBuf::from("demo/assets/rootfs.ext4"),
            socket: PathBuf::from("/tmp/firecracker-lex-os.sock"),
            tap: "tap-lex0".into(),
            host_ip_cidr: "169.254.42.1/30".into(),
        }
    }
}
```

- [ ] **Step 2: Extend the struct to carry the running VM handle**

```rust
pub struct FirecrackerPerimeter {
    policy: Option<SandboxPolicy>,
    state: BoxState,
    assets: FirecrackerAssets,
    vm: Option<FirecrackerVm>,
}

impl FirecrackerPerimeter {
    pub fn new() -> Self {
        Self::with_assets(FirecrackerAssets::default())
    }

    pub fn with_assets(assets: FirecrackerAssets) -> Self {
        Self {
            policy: None,
            state: BoxState::Dead,
            assets,
            vm: None,
        }
    }
}
```

- [ ] **Step 3: Replace the stub `provision` body**

```rust
fn provision(&mut self, policy: SandboxPolicy) -> Result<(), PerimeterError> {
    if policy.required_floor > self.max_floor() {
        return Err(PerimeterError::FloorUnavailable {
            required: policy.required_floor.as_str(),
            available: self.max_floor().as_str(),
        });
    }

    // 1. Clean any stale socket from a previous crashed run.
    let _ = std::fs::remove_file(&self.assets.socket);

    // 2. Spawn firecracker; wait for the API socket to accept connections.
    let vm = FirecrackerVm::spawn(self.assets.socket.clone()).map_err(perimeter_err)?;
    wait_for_socket(&self.assets.socket, Duration::from_secs(2)).map_err(perimeter_err)?;

    // 3. Configure the boot source.
    let boot = format!(
        r#"{{"kernel_image_path":"{}","boot_args":"console=ttyS0 reboot=k panic=1 pci=off"}}"#,
        self.assets.kernel.display()
    );
    with_socket(&self.assets.socket, |s| put_json(s, "/boot-source", &boot))
        .map_err(perimeter_err)?;

    // 4. Configure the rootfs drive (writable; the agent is root inside).
    let drive = format!(
        r#"{{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":false}}"#,
        self.assets.rootfs.display()
    );
    with_socket(&self.assets.socket, |s| put_json(s, "/drives/rootfs", &drive))
        .map_err(perimeter_err)?;

    // 5. Configure the network interface (host_dev_name must already exist;
    //    we create it next).
    let net = format!(
        r#"{{"iface_id":"eth0","host_dev_name":"{}"}}"#,
        self.assets.tap
    );
    with_socket(&self.assets.socket, |s| put_json(s, "/network-interfaces/eth0", &net))
        .map_err(perimeter_err)?;

    // 6. Create the tap on the host and install the egress allowlist.
    create_tap(&self.assets.tap, &self.assets.host_ip_cidr).map_err(perimeter_err)?;
    install_egress_allowlist(&self.assets.tap, &policy.egress).map_err(perimeter_err)?;

    // 7. Start the VM.
    with_socket(&self.assets.socket, |s| {
        post_json(s, "/actions", r#"{"action_type":"InstanceStart"}"#)
    })
    .map_err(perimeter_err)?;

    self.policy = Some(policy);
    self.state = BoxState::Alive;
    self.vm = Some(vm);
    Ok(())
}
```

- [ ] **Step 4: Add the error-conversion helper**

```rust
fn perimeter_err<E: std::fmt::Display>(e: E) -> PerimeterError {
    PerimeterError::Blocked(format!("firecracker backend: {e}"))
}
```

- [ ] **Step 5: Compile-check (cannot run provision without KVM)**

```bash
cargo build --features firecracker
cargo clippy --features firecracker --all-targets
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/lex-os-perimeter/src/firecracker/mod.rs
git commit -m "feat(perimeter): real provision() against Firecracker HTTP API (#14)"
```

---

## Task 6: Wire `FirecrackerPerimeter::destroy` (sandbox-friendly compile)

SIGKILL → flush iptables → destroy tap → forget VM handle.

**Files:**
- Modify: `crates/lex-os-perimeter/src/firecracker/mod.rs`

- [ ] **Step 1: Replace the stub destroy body**

```rust
fn destroy(&mut self, _reason: &str) {
    if let Some(mut vm) = self.vm.take() {
        vm.kill();
    }
    let _ = flush_egress_rules(&self.assets.tap);
    let _ = destroy_tap(&self.assets.tap);
    let _ = std::fs::remove_file(&self.assets.socket);
    self.state = BoxState::Dead;
}
```

- [ ] **Step 2: Compile-check**

```bash
cargo build --features firecracker
cargo clippy --features firecracker --all-targets
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/lex-os-perimeter/src/firecracker/mod.rs
git commit -m "feat(perimeter): real destroy() — SIGKILL + flush rules + remove tap (#14)"
```

---

## Task 7: Asset distribution script (sandbox-friendly, network)

Pull Firecracker v1.9.1 + the documented quickstart kernel + rootfs into `demo/assets/`.

**Files:**
- Create: `demo/setup-assets.sh`
- Create: `demo/assets/.gitignore`

- [ ] **Step 1: Create `demo/assets/.gitignore`**

```gitignore
# Binary assets fetched by setup-assets.sh; do not commit.
*
!.gitignore
```

- [ ] **Step 2: Create `demo/setup-assets.sh`**

```bash
#!/usr/bin/env bash
# Fetch the binary assets the Firecracker perimeter needs. ~50 MB total.
# Idempotent: skips files already present.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/assets"

FC_VERSION=v1.9.1
KERNEL_URL=https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
ROOTFS_URL=https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4

if ! command -v firecracker >/dev/null 2>&1; then
  echo "+ fetching firecracker $FC_VERSION"
  curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-x86_64.tgz" \
    | tar xz --strip-components=1
  install -m 0755 release-${FC_VERSION}-x86_64/firecracker-${FC_VERSION}-x86_64 ./firecracker
  rm -rf release-${FC_VERSION}-x86_64
  echo "+ installing firecracker to /usr/local/bin (needs sudo)"
  sudo install -m 0755 ./firecracker /usr/local/bin/firecracker
fi

[ -f vmlinux ] || { echo "+ fetching guest kernel"; curl -fsSL -o vmlinux "$KERNEL_URL"; }
[ -f rootfs.ext4 ] || { echo "+ fetching guest rootfs"; curl -fsSL -o rootfs.ext4 "$ROOTFS_URL"; }

echo "+ assets in $(pwd)"
ls -lh vmlinux rootfs.ext4
firecracker --version
```

- [ ] **Step 3: Make it executable**

```bash
chmod +x demo/setup-assets.sh
```

- [ ] **Step 4: Commit**

```bash
git add demo/setup-assets.sh demo/assets/.gitignore
git commit -m "feat(demo): one-shot asset fetcher for the Firecracker perimeter (#14)"
```

---

## Task 8: Host-check script (sandbox-friendly)

Verify the demo can actually run before paying for a Hetzner box.

**Files:**
- Create: `demo/host-check.sh`

- [ ] **Step 1: Create `demo/host-check.sh`**

```bash
#!/usr/bin/env bash
# Print whether this host can run the lex-os Firecracker demo. Exits non-zero
# if any check fails so it slots into demo/run.sh's pre-flight.

set -u

ok=0
fail=0

check() {
  local label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "  ✓ $label"
    ok=$((ok + 1))
  else
    echo "  ✗ $label"
    fail=$((fail + 1))
  fi
}

echo "+ host checks"
check "running as root"                       test "$(id -u)" -eq 0
check "/dev/kvm present"                      test -e /dev/kvm
check "x86_64 virtualization available"       sh -c 'grep -qE "vmx|svm" /proc/cpuinfo'
check "firecracker on PATH"                   command -v firecracker
check "ip (iproute2) on PATH"                 command -v ip
check "iptables on PATH"                      command -v iptables
check "guest kernel present"                  test -f demo/assets/vmlinux
check "guest rootfs present"                  test -f demo/assets/rootfs.ext4

echo "+ summary: $ok ok / $fail failed"
[ "$fail" -eq 0 ]
```

- [ ] **Step 2: Make executable**

```bash
chmod +x demo/host-check.sh
```

- [ ] **Step 3: Commit**

```bash
git add demo/host-check.sh
git commit -m "feat(demo): host-check.sh — verify the demo host before running (#14)"
```

---

## Task 9: VM-internal attack init script (sandbox-friendly)

Inject the curls into the rootfs as `/sbin/init` (or as a systemd unit if the rootfs uses systemd). The simplest path is a small custom init that the kernel cmdline points to.

**Files:**
- Create: `demo/init-attack.sh`

- [ ] **Step 1: Create the init script**

```bash
#!/bin/sh
# /sbin/init.demo — runs inside the microVM, output goes to ttyS0 which
# Firecracker pipes to its own stdout. Halts the VM at the end so the
# supervisor sees the box die (issue #7 wires that to reprovision).

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
ifconfig eth0 169.254.42.2 netmask 255.255.255.252 up

echo "[guest] uname: $(uname -a)"
echo "[guest] id: $(id)"

echo "--- allowed (the legitimate target) ---"
if wget -qT 5 -O - http://169.254.42.1/healthz; then
  echo " → 200 OK (egress allowed)"
else
  echo " → unexpected: allowed target failed"
fi

echo "--- denied: named host outside the allowlist ---"
if wget -qT 5 -O - http://evil.com; then
  echo " → unexpected: evil.com succeeded — wall did not fire"
else
  echo " → blocked (no route)"
fi

echo "--- denied: raw IP, no DNS involved ---"
if wget -qT 5 -O - http://8.8.8.8; then
  echo " → unexpected: 8.8.8.8 succeeded — wall did not fire"
else
  echo " → blocked (no route)"
fi

echo "--- done ---"
poweroff -f
```

- [ ] **Step 2: Document how to inject it**

Append to `demo/setup-assets.sh` after the existing fetch logic:

```bash
echo "+ injecting init-attack.sh into the rootfs"
sudo mkdir -p /mnt/lex-rootfs
sudo mount -o loop rootfs.ext4 /mnt/lex-rootfs
sudo install -m 0755 ../init-attack.sh /mnt/lex-rootfs/sbin/init.demo
sudo umount /mnt/lex-rootfs
sudo rmdir /mnt/lex-rootfs
```

And update the boot-args in `firecracker/mod.rs` Step 3 of Task 5:

```rust
"boot_args":"console=ttyS0 reboot=k panic=1 pci=off init=/sbin/init.demo"
```

- [ ] **Step 3: Make executable + commit**

```bash
chmod +x demo/init-attack.sh
git add demo/init-attack.sh demo/setup-assets.sh
git commit -m "feat(demo): guest-side init script that exercises Wall 2 (#14)"
```

---

## Task 10: Update `demo/run.sh` and `demo/scenario.md` (sandbox-friendly)

Have run.sh actually use the `firecracker` feature once assets exist, and update the runbook to reflect what Wall 2 looks like now.

**Files:**
- Modify: `demo/run.sh`
- Modify: `demo/scenario.md`
- Modify: `demo/attacks/02_curl_evil.sh` (rewrite — it is now the canonical init script content)

- [ ] **Step 1: Edit `demo/run.sh` pre-flight to call host-check and pass --features firecracker**

Replace the existing `Pre-flight: build` block with:

```bash
say "Pre-flight: host check"
if ! bash demo/host-check.sh; then
  echo "demo: host-check failed; cannot proceed with Wall 2" >&2
  exit 1
fi

say "Pre-flight: build"
cargo build --quiet --features firecracker -p lex-os -p results-stub
```

And the Scene 3 run line becomes:

```bash
cargo run --quiet --features firecracker -p lex-os -- run --manifest "$MANIFEST" --audit-out "$AUDIT_LOG"
```

- [ ] **Step 2: Replace `demo/attacks/02_curl_evil.sh` with a thin pointer**

```bash
#!/usr/bin/env sh
# Attack #2 — kernel egress wall (issue #14).
#
# This attack runs *inside* the provisioned microVM. The canonical script
# lives at demo/init-attack.sh and is installed into the rootfs by
# demo/setup-assets.sh. It is invoked by the guest kernel as
# /sbin/init.demo when Firecracker passes init=/sbin/init.demo on the
# kernel cmdline (configured in crates/lex-os-perimeter/src/firecracker/mod.rs).
#
# Output goes to the guest's ttyS0, which Firecracker pipes to its own
# stdout. The supervisor captures that stdout and includes it in the
# audit log entry for the run.
echo "see demo/init-attack.sh — this attack runs inside the microVM"
exit 0
```

- [ ] **Step 3: Update `demo/scenario.md`** Wall-2 section to point at `init-attack.sh` and to drop the "placeholder" framing in the script output

In `demo/scenario.md`, replace the existing Wall 2 block:

```markdown
### Wall 2 — kernel egress (inside the running microVM)

```sh
sudo demo/setup-assets.sh                 # one-time; ~50 MB
sudo bash demo/run.sh                     # the full continuous run

# Inside Scene 3 you'll see the guest's console output:
#   --- allowed (the legitimate target) ---
#     → 200 OK (egress allowed)
#   --- denied: named host outside the allowlist ---
#     → blocked (no route)
#   --- denied: raw IP, no DNS involved ---
#     → blocked (no route)
```

The wall is enforced by `iptables` rules installed on the host's tap
device by `crates/lex-os-perimeter/src/firecracker/net.rs`. The agent
is root inside the VM but cannot reach those rules — the tap device,
and the chain those rules live on, are on the host.
```

- [ ] **Step 4: Run the script end-to-end on the sandbox (it should bail at host-check)**

```bash
bash demo/run.sh
```

Expected: host-check fails (sandbox has no `/dev/kvm`), exit 1. This confirms the gate works without breaking anything.

- [ ] **Step 5: Commit**

```bash
git add demo/run.sh demo/attacks/02_curl_evil.sh demo/scenario.md
git commit -m "feat(demo): wire run.sh + scenario.md to the real Firecracker backend (#14)"
```

---

## Task 11: ⚠ KVM-only — full smoke test on Hetzner

Cannot be done in the sandbox; document the steps so whoever has KVM access can run them.

**Files:** none (operational task).

- [ ] **Step 1: Provision Hetzner AX41 (or any KVM-capable Linux box)**

```bash
# On the host, as root:
apt-get update && apt-get install -y curl iproute2 iptables build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. ~/.cargo/env
git clone https://github.com/alpibrusl/lex-os.git
cd lex-os
git clone https://github.com/alpibrusl/lex-lang.git ../lex-lang
git clone https://github.com/alpibrusl/acli.git ../acli
sudo bash demo/setup-assets.sh
sudo bash demo/host-check.sh   # all checks must pass
```

- [ ] **Step 2: Run the full demo**

```bash
sudo bash demo/run.sh
```

Expected:
- Scene 1: Wall 1 fires (exit 8 in the script's assertion).
- Scene 2: results-stub binds.
- Scene 3: guest console prints the three curl outcomes — allowed succeeds, evil.com fails, 8.8.8.8 fails. Then guest poweroff. Then supervisor reprovisions and the mediation loop runs to `outcome: GoalMet`.
- Scene 4: audit hash verified; `narrowing_blocked` event present.

- [ ] **Step 3: Run the integration tests**

```bash
cargo test --features firecracker -p lex-os-perimeter -- --ignored
```

Expected: the three pre-existing `firecracker_*` tests + the new `create_and_destroy_tap_on_host` all pass.

- [ ] **Step 4: Record the demo**

`asciinema rec demo.cast bash demo/run.sh` then upload + link from issue #10.

- [ ] **Step 5: Close issue #14 with a link to the recording**

```bash
gh issue close 14 --repo alpibrusl/lex-os \
  --comment "Implemented in Tasks 1-10 of docs/plans/2026-06-02-firecracker-perimeter.md. Smoke-test recording: <asciinema URL>."
```

---

## Self-Review (against issue #14)

**Spec coverage** (each work item from #14 mapped to a task):

| #14 work item | Task |
|---|---|
| Firecracker binary + jailer install | Task 7 |
| Guest kernel (vmlinux), Alpine rootfs | Task 7 |
| Replace `provision` stub | Task 5 |
| Tap device creation | Task 3 |
| Firecracker HTTP API calls | Task 2 + Task 5 |
| Host iptables rules from `policy.egress` | Task 3 + Task 5 |
| `destroy` SIGKILL + flush rules | Task 6 |
| Un-ignore the three KVM tests | Task 11 Step 3 |
| End-to-end smoke (curl evil.com fails) | Task 9 + Task 11 |

**Out of scope** (acknowledged, not blocking #14 closure):
- Per-VM tap naming + multi-tenant isolation (Hetzner is single-tenant for the demo).
- `jailer` for capability dropping (resolved choice: lex-os runs as root).
- TLS for `results.demo.internal` (resolved choice: plain HTTP, kernel-egress fires on IP+port).
- Cargo.lock / external dep changes (resolved choice: std-only, no new deps).

**Placeholder scan:** none — all code blocks contain real Rust/shell with no TODOs.

**Type consistency:** `FirecrackerAssets` (Task 5 Step 1) used in Task 5 Steps 2-3 + Task 6; `FirecrackerVm`/`vm.kill()` introduced in Task 4 used in Tasks 5-6; `parse_host_port`/`install_egress_allowlist` introduced in Task 3 used in Task 5.
