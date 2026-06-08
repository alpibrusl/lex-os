# Self-hosted KVM CI runner

The real Firecracker perimeter — the part that makes "sealed at the edge" true
rather than simulated — can only be exercised on a host with `/dev/kvm` and
root. The default GitHub-hosted runners have neither, so the
[`firecracker (KVM)`](../.github/workflows/firecracker.yml) workflow targets a
**self-hosted runner labelled `kvm`**. Standing that runner up and getting the
workflow green is the gate (lex-os#27, Task 3) that must pass before the
Firecracker backend can become the default.

This runbook registers a Linux KVM host as that runner.

## What the job runs

`firecracker (KVM)` (`workflow_dispatch` + nightly cron, **never** on
`pull_request`) does, on `runs-on: [self-hosted, kvm]`:

1. `cargo build -p lex-os --features firecracker`
2. `sudo bash demo/setup-assets.sh` — fetch firecracker + jailer + kernel + rootfs
3. `sudo bash demo/wall2.sh` — boot a real (jailed) microVM and assert the
   kernel egress wall drops a non-allowlisted host

So the runner needs `/dev/kvm`, **passwordless sudo**, a Rust toolchain, and the
usual networking tools. Nothing lex-os-specific beyond the `kvm` label.

> **Why this is safe on a public repo.** Self-hosted runners must never run
> untrusted code. This workflow has **no `pull_request` trigger** — a fork PR
> cannot start it. It runs only when a maintainer dispatches it or on the cron,
> i.e. always against code already on a branch you control. Keep it that way: do
> not add `pull_request` to this workflow, and in **Settings → Actions → General**
> require approval for outside collaborators.

## Prerequisites

On the KVM host (the machine you've been running the demos on already satisfies
all of these). Verify:

```sh
test -e /dev/kvm && echo "kvm ok"            # hardware virtualization present
getent group kvm                              # the kvm group exists (gid used by the jailer)
command -v cargo && cargo --version           # Rust toolchain (rustup recommended)
rustup target add x86_64-unknown-linux-musl   # for the in-VM guest build (wall2 doesn't need it, agent demos do)
command -v ip iptables curl tar               # iproute2 / iptables / curl / tar
```

The runner's OS user does **not** need to be in the `kvm` group: the demos run
firecracker under the jailer via `sudo`, and the jailer sets up `/dev/kvm` inside
the chroot with the `kvm` gid.

## 1. Passwordless sudo (required)

CI is non-interactive and the job calls `sudo`. Grant the **runner's** user
passwordless sudo (replace `RUNUSER` with the account that will run the runner):

```sh
echo "RUNUSER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/lexos-kvm-runner
sudo chmod 0440 /etc/sudoers.d/lexos-kvm-runner
sudo visudo -c            # sanity-check sudoers syntax
```

(You can tighten this later to just the demo scripts, but they call `ip`,
`iptables`, `jailer`, `mount`, and file installs, so start broad.)

## 2. Register the runner

Get a registration token and the download line from **repo → Settings → Actions
→ Runners → New self-hosted runner (Linux x64)**, or mint a token from the CLI:

```sh
gh api -X POST repos/alpibrusl/lex-os/actions/runners/registration-token \
  --jq .token
```

Then, as `RUNUSER`, in a dedicated directory:

```sh
mkdir -p ~/actions-runner && cd ~/actions-runner
# Use the latest runner version from the Settings page download command:
curl -fsSL -o runner.tar.gz \
  https://github.com/actions/runner/releases/download/v2.XXX.X/actions-runner-linux-x64-2.XXX.X.tar.gz
tar xzf runner.tar.gz

./config.sh \
  --url https://github.com/alpibrusl/lex-os \
  --token <TOKEN> \
  --labels kvm \
  --name "$(hostname)-kvm" \
  --unattended
```

The `self-hosted` label is added automatically; `--labels kvm` is what matches
the workflow's `runs-on: [self-hosted, kvm]`.

## 3. Start it

Test in the foreground first:

```sh
./run.sh
```

Once it connects (shows "Listening for Jobs"), install it as a service so it
survives reboots and the nightly cron can reach it:

```sh
sudo ./svc.sh install RUNUSER
sudo ./svc.sh start
sudo ./svc.sh status
```

## 4. Verify the gate is green

Trigger the workflow and watch it:

```sh
gh workflow run "firecracker (KVM)"
gh run watch
# or: gh run list --workflow "firecracker (KVM)" -L 1
```

Green means: the real perimeter built, assets fetched, and a jailed microVM
booted with the egress wall holding — the gate for flipping the default is met.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `sudo: a password is required` | Step 1 not applied to the **runner's** user, or wrong username in the sudoers file. |
| `/dev/kvm: permission denied` / boot fails | Host virtualization off in BIOS, or `/dev/kvm` missing. Confirm `test -e /dev/kvm` and `grep -E 'vmx|svm' /proc/cpuinfo`. |
| jailer: `cgroup ... already exists` / cgroup errors | Stale jail from a killed run. `sudo rm -rf /srv/jailer/firecracker/*` and `sudo rmdir /sys/fs/cgroup/firecracker/* 2>/dev/null`. The host is cgroup v2 (the perimeter passes `--cgroup-version 2`). |
| `ip tuntap add ... Device or resource busy` | A leftover `tap-lex0` from a crashed run. `sudo ip link delete tap-lex0`. |
| musl build warning in setup-assets | `rustup target add x86_64-unknown-linux-musl`. Not needed for `wall2`, but the agent demos inject the guest binary. |
| Runner offline for the nightly cron | Install it as a service (Step 3), not just `./run.sh`. |

## Then: flip the default (Task 3, code half)

Once this workflow is reliably green, the Firecracker backend can become the
default: make `firecracker` a default cargo feature (or auto-select it when
`/dev/kvm` is present), demote the simulated perimeter to an explicit
`--simulated` / `LEX_OS_SIMULATED=1` opt-in, and — on a KVM host — **refuse,
don't downgrade** if the real perimeter is unavailable, keeping the
`security_boundary: false` + loud-warning disclosure for the opt-in.
