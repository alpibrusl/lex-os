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

## The guest kernel

`setup-assets.sh` fetches Firecracker's CI kernel (6.1.102 by default,
`KERNEL_VERSION=` to override) rather than the quickstart 4.14 image,
because only the former carries `CONFIG_HW_RANDOM_VIRTIO`. Without it a
guest never gets past `random: fast init done`, `getrandom(2)` blocks,
and anything wanting entropy early — Go binaries, TLS handshakes — hangs
(lex-os#82). The script replaces a kernel that lacks the driver rather
than merely a missing one.

## Architecture

**x86_64 and aarch64 both work.** `demo/setup-assets.sh` reads `uname -m` and
fetches the matching Firecracker release and guest images; the perimeter picks
the right serial console (`ttyS0` on x86, `ttyAMA0` on ARM — see `GUEST_CONSOLE`).
Anything else is refused by name rather than fetched wrongly.

That makes an ARM board a legitimate runner. A Raspberry Pi 5 has native KVM and
its GIC-400 is a GICv2, which the pinned Firecracker still supports — so a board
on a desk can stand in for a rented x86 server. It has not been run yet; the
first host to try either architecture is also the first to validate the pin
(#76).

## Prerequisites

On the KVM host (the machine you've been running the demos on already satisfies
all of these). Verify:

```sh
test -e /dev/kvm && echo "kvm ok"            # hardware virtualization present
getent group kvm                              # the kvm group exists (gid used by the jailer)
command -v cargo && cargo --version           # Rust toolchain (rustup recommended)
rustup target add "$(uname -m)-unknown-linux-musl"   # in-VM guest build (wall2 doesn't need it; agent demos do)
command -v ip iptables curl tar               # iproute2 / iptables / curl / tar
```

The runner's OS user does **not** need to be in the `kvm` group: the demos run
firecracker under the jailer via `sudo`, and the jailer sets up `/dev/kvm` inside
the chroot with the `kvm` gid.

## 0. Use a dedicated account, not your own

Everything below says `RUNUSER`. Make that a **service account whose home is
not under `/home/<a person's name>`** — say `ghrunner`, with `/opt/ghrunner`.

This is not tidiness. The runner writes its working directory into the log of
every job, some fifty lines a run, and on a public repository those logs are
public:

```
Working directory is '/home/RUNUSER/actions-runner/_work/lex-os/lex-os'
```

That was true of this project's own runner for its first eight runs, because
this runbook said `RUNUSER` and meant "you". No workflow file can suppress it
— the runner emits it during `Set up job`, before any step of ours runs — so
the account name is the only place to fix it.

The runner also prints `Machine name: '<hostname>'` from the host's hostname.
If that name is one you would rather not publish, give the *service* a private
one instead of renaming the machine (systemd ≥ 258):

```sh
sudo systemctl edit actions.runner.<owner>-<repo>.<name>.service
# [Service]
# ProtectHostname=yes:kvm-runner
```

That is a private UTS namespace for the unit alone. Deleting the drop-in
reverts it.

## 1. Passwordless sudo (required)

CI is non-interactive and the job calls `sudo`. Grant the **runner's** user
passwordless sudo (replace `RUNUSER` with the account from step 0):

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

Then, as `RUNUSER` (the service account from step 0), in a dedicated directory:

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
  --name kvm-1 \
  --unattended
```

**Do not name the runner after the machine.** On a public repository every
workflow run page is readable without authentication, and the log opens
with `Runner name: '<name>'`. `--name "$(hostname)-kvm"` — which this
runbook used to suggest — therefore publishes the hostname of a machine
somebody owns, next to a document explaining that it has passwordless
sudo. `kvm-1` says everything the workflow needs to know.

### Cleaning up logs that already leaked

Deleting a run's logs keeps the run itself — the green tick and its timing
stay, which matters when those runs are the evidence the perimeter works:

```sh
gh api -X DELETE repos/alpibrusl/lex-os/actions/runs/<id>/logs
```

**Verify against the API, not against `gh run view --log`.** `gh` caches
downloaded logs under `~/.cache/gh`, and a cached copy reads back
identically after the server has already dropped it — which looks exactly
like a deletion that silently failed. `rm -rf ~/.cache/gh` first, or ask
the endpoint directly and expect a 404:

```sh
gh api repos/alpibrusl/lex-os/actions/runs/<id>/logs -i --silent | head -1
```

The same logs carry the runner's working directory, so the account name
appears in every path. If that matters to you, run the runner as a
dedicated service account rather than a personal login; the runbook does
not assume one either way, but the choice is visible forever once a run
is published.

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

## What "green" means, and what it used to mean

The job asserts, it does not merely run. Until #54 `wall2.sh` exited 0
whenever the microVM booted and tore down: the guest's probes printed to
the console and nothing read them, so the nightly job stayed green
through the entire life of the egress-wall bypass in #79, with
`UNEXPECTED: host-local :8080 succeeded` on screen the whole time.

`demo/assert-wall.sh` now decides, from the run's log:

1. **No probe reached anything the grant does not allow** — the guest
   says `UNEXPECTED`, and that word fails the job.
2. **Every denial probe actually ran.** A guest that never booted far
   enough to probe prints none of them, and three absences must not read
   as three passes.
3. **The wall discriminated.** This is the one that never existed. All
   three denial probes pass just as well against a wall that refuses
   *every* packet, so the denials alone say nothing about the allowlist.
   The kernel's own counters settle it — RETURN rules carrying traffic
   mean something was permitted, DROP carrying traffic means something
   was refused, and both must hold.

A passing run ends with, e.g.:

```
wall assertions passed: 5 packet(s) permitted, 40 refused
```

Both numbers matter. A zero on the left is a wall that let nothing
through, which is not a working wall — it is a broken one that happens
to pass every denial probe.

Because that decision is a function of a log rather than of a live box,
it is tested on ordinary CI with no `/dev/kvm`: `demo/fixtures/` carries
a passing run, the real captured output of the broken wall, and an
all-drop wall, and the `ci` workflow asserts the first passes and the
other two are refused.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `sudo: a password is required` | Step 1 not applied to the **runner's** user, or wrong username in the sudoers file. |
| `/dev/kvm: permission denied` / boot fails | Host virtualization off in BIOS, or `/dev/kvm` missing. Confirm `test -e /dev/kvm` and `grep -E 'vmx|svm' /proc/cpuinfo`. |
| jailer: `cgroup ... already exists` / cgroup errors | Stale jail from a killed run. `sudo rm -rf /srv/jailer/firecracker/*` and `sudo rmdir /sys/fs/cgroup/firecracker/* 2>/dev/null`. The host is cgroup v2 (the perimeter passes `--cgroup-version 2`). |
| `ip tuntap add ... Device or resource busy` | A leftover `tap-lex0` from a crashed run. `sudo ip link delete tap-lex0`. |
| musl build warning in setup-assets | `rustup target add "$(uname -m)-unknown-linux-musl"`. Not needed for `wall2`, but the agent demos inject the guest binary. |
| Runner offline for the nightly cron | Install it as a service (Step 3), not just `./run.sh`. |

## What runs it automatically, and what must not

The job runs on `workflow_dispatch`, on the nightly cron, and on any
**push** touching `crates/lex-os-perimeter/`, `lex-os-proto`,
`lex-os-guest`, `demo/`, or the workflow itself. A change to the sandbox
boundary therefore gets a real boot behind it without anyone remembering
to dispatch this (#54).

`push` is safe here for one specific reason: only people who can push to
this repository can start it. That is the whole property, and the next
section is about the trigger that would destroy it.

## Do not add a `pull_request` trigger

Said in the box at the top and worth repeating at the bottom, because it
is the one change that would turn this runner into a liability.

**lex-os is a public repository.** A `pull_request` trigger on a
self-hosted runner lets anyone who forks the repo execute code on the
runner host — which, per section 1, has passwordless sudo. lex-os#54 asks
for this job to be a required PR check; that wording predates the runner
existing and should not be followed literally on a persistent host you
care about.

Making it PR-blocking safely needs an **ephemeral, isolated** runner: a
VM created per run and destroyed after, so there is no persistent host to
compromise. That also solves the duller problem — a required check whose
runner is asleep does not fail, it hangs, and blocks every merge.

## Historical: flipping the default (Task 3, code half)

Once this workflow is reliably green, the Firecracker backend can become the
default: make `firecracker` a default cargo feature (or auto-select it when
`/dev/kvm` is present), demote the simulated perimeter to an explicit
`--simulated` / `LEX_OS_SIMULATED=1` opt-in, and — on a KVM host — **refuse,
don't downgrade** if the real perimeter is unavailable, keeping the
`security_boundary: false` + loud-warning disclosure for the opt-in.
