#!/usr/bin/env bash
# Move a self-hosted runner off a personal account onto a service one.
#
# Why this exists, and why it is a script rather than a paragraph in the
# runbook: the runner writes its working directory into the log of every
# job — around fifty lines a run — and on a public repository those logs
# are public. If the account is a person's, so is every one of those
# lines. See docs/self-hosted-kvm-runner.md § 0.
#
# `::add-mask::` in the KVM workflow already turns those lines into `***`,
# but masking is a layer, not the fix: it cannot reach the `Set up job`
# group, where the runner prints `Machine name:` before any step of ours
# exists. This is the fix.
#
# Nothing here is specific to one host. The current account and the
# runner's location are read from the environment, so the script carries
# no username, no hostname, and nothing else that would be awkward to
# have in a public repository — which is the same property it exists to
# give the logs.
#
#   bash scripts/migrate-runner-account.sh
#   NEW_USER=ci-runner NEW_HOME=/opt/ci bash scripts/migrate-runner-account.sh
#
# Requires: passwordless sudo, an authenticated `gh`, and systemd.
set -euo pipefail

REPO=${REPO:-alpibrusl/lex-os}
NEW_USER=${NEW_USER:-ghrunner}
NEW_HOME=${NEW_HOME:-/opt/$NEW_USER}
NEW_DIR="$NEW_HOME/actions-runner"
# The runner's name as GitHub shows it. Deliberately not the hostname:
# `--name "$(hostname)-kvm"` is how this leak started.
RUNNER_NAME=${RUNNER_NAME:-kvm-1}
RUNNER_LABELS=${RUNNER_LABELS:-kvm}
# A neutral hostname for the service's own UTS namespace. The machine is
# not renamed; only this unit sees it.
PRIVATE_HOSTNAME=${PRIVATE_HOSTNAME:-kvm-runner}

OLD_USER=$(id -un)
OLD_DIR=${OLD_DIR:-$HOME/actions-runner}

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }

# ---- preflight, all of it before anything changes -------------------------
[ -d "$OLD_DIR" ] || die "no runner at $OLD_DIR — set OLD_DIR= if it lives elsewhere"
[ "$OLD_USER" != "$NEW_USER" ] || die "already running as $NEW_USER; nothing to do"
sudo -n true 2>/dev/null || die "passwordless sudo is required (see the runbook, step 1)"
command -v gh >/dev/null || die "gh is not installed"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated"
command -v systemctl >/dev/null || die "this script assumes systemd"
pgrep -f 'Runner.Worker' >/dev/null && die "a job is running right now; wait for it to finish"

SYSTEMD_MAJOR=$(systemctl --version | head -1 | awk '{print $2}')
if [ "${SYSTEMD_MAJOR:-0}" -lt 258 ]; then
  echo "note: systemd $SYSTEMD_MAJOR predates ProtectHostname=yes:<name>, so the"
  echo "      \`Machine name:\` line will still show the real hostname. Everything"
  echo "      else in this script still applies."
  PRIVATE_HOSTNAME=""
fi

cat <<SUMMARY

This will, on this machine:

  move the runner   $OLD_DIR  ($OLD_USER)
               ->   $NEW_DIR  ($NEW_USER, home $NEW_HOME)
  deregister and re-register it with $REPO as "$RUNNER_NAME"
  grant $NEW_USER passwordless sudo (the demos need ip/iptables/jailer/mount)
  install the service${PRIVATE_HOSTNAME:+ with a private hostname "$PRIVATE_HOSTNAME"}

The old directory is left in place. Nothing is deleted.

SUMMARY
read -r -p "Proceed? [y/N] " ok
[ "$ok" = y ] || [ "$ok" = Y ] || die "aborted"

# ---- 1. the account ------------------------------------------------------
say "1/7  Service account $NEW_USER, home $NEW_HOME"
if id "$NEW_USER" >/dev/null 2>&1; then
  echo "already exists, leaving it alone"
else
  sudo useradd --system --create-home --home-dir "$NEW_HOME" --shell /bin/bash "$NEW_USER"
fi
sudo install -d -o "$NEW_USER" -g "$NEW_USER" -m 0755 "$NEW_HOME"

say "2/7  Passwordless sudo for $NEW_USER"
# The demos call ip, iptables, jailer, mount and file installs, so this
# starts as broad as the old account's. Tighten later if you like.
printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$NEW_USER" \
  | sudo tee "/etc/sudoers.d/runner-$NEW_USER" >/dev/null
sudo chmod 0440 "/etc/sudoers.d/runner-$NEW_USER"
sudo visudo -c >/dev/null

# ---- 3. the toolchain ---------------------------------------------------
say "3/7  Rust toolchain for $NEW_USER"
# /usr/bin/cargo is often a system rustup shim while the toolchains live
# per-user, so a fresh account has none and `cargo build` fails with "no
# default toolchain". Nothing in the workflow would say why.
if command -v rustup >/dev/null; then
  sudo -u "$NEW_USER" -H bash -lc 'rustup default stable' || \
    echo "note: rustup default failed; install a toolchain for $NEW_USER before the next run"
  sudo -u "$NEW_USER" -H bash -lc \
    "rustup target add \$(uname -m)-unknown-linux-musl" || true
  sudo -u "$NEW_USER" -H bash -lc 'cargo --version' || true
else
  echo "note: no rustup on PATH; make sure $NEW_USER can run cargo"
fi

# ---- 4. retire the old runner -------------------------------------------
say "4/7  Retiring the runner registered under $OLD_USER"
# Deregister before uninstalling: a runner removed from GitHub's side
# while its service still runs reconnects and re-registers itself.
REMOVE_TOKEN=$(gh api -X POST "repos/$REPO/actions/runners/remove-token" -q .token)
sudo "$OLD_DIR/svc.sh" stop || true
sudo "$OLD_DIR/svc.sh" uninstall || true
( cd "$OLD_DIR" && ./config.sh remove --token "$REMOVE_TOKEN" )

# ---- 5. install under the new account -----------------------------------
say "5/7  Installing under $NEW_USER"
# Copy the installation already present rather than re-downloading: same
# bytes, already trusted. _work and _diag are deliberately not copied —
# the build cache in _work bakes in the old absolute paths, which is the
# thing being moved away from.
sudo rm -rf "$NEW_DIR"
sudo cp -a "$OLD_DIR" "$NEW_DIR"
sudo rm -rf "$NEW_DIR/_work" "$NEW_DIR/_diag" "$NEW_DIR/.runner" \
            "$NEW_DIR/.credentials" "$NEW_DIR/.credentials_rsaparams" "$NEW_DIR/.service"
sudo chown -R "$NEW_USER:$NEW_USER" "$NEW_HOME"

REG_TOKEN=$(gh api -X POST "repos/$REPO/actions/runners/registration-token" -q .token)
sudo -u "$NEW_USER" -H bash -lc "cd '$NEW_DIR' && ./config.sh \
  --url 'https://github.com/$REPO' \
  --token '$REG_TOKEN' \
  --labels '$RUNNER_LABELS' \
  --name '$RUNNER_NAME' \
  --work _work \
  --unattended --replace"

# ---- 6. the service -----------------------------------------------------
say "6/7  Installing the service"
sudo "$NEW_DIR/svc.sh" install "$NEW_USER"
UNIT=$(basename "$(sudo find /etc/systemd/system -maxdepth 1 -name 'actions.runner.*.service' | head -1)")
[ -n "$UNIT" ] || die "could not find the installed unit under /etc/systemd/system"

if [ -n "$PRIVATE_HOSTNAME" ]; then
  sudo mkdir -p "/etc/systemd/system/$UNIT.d"
  sudo tee "/etc/systemd/system/$UNIT.d/hostname.conf" >/dev/null <<EOF
# The runner prints "Machine name: <hostname>" into every job log, from
# the \`Set up job\` group — before any step exists, so no workflow can
# mask it. A private UTS namespace gives this service a neutral name
# instead. The machine's own hostname is untouched; delete this file to
# revert.
[Service]
ProtectHostname=yes:$PRIVATE_HOSTNAME
EOF
  sudo systemctl daemon-reload
fi
sudo "$NEW_DIR/svc.sh" start
sleep 3
sudo systemctl --no-pager --full status "$UNIT" | head -8 || true

# ---- 7. what to check ---------------------------------------------------
say "7/7  Done"
cat <<EOF

unit: $UNIT
home: $(getent passwd "$NEW_USER" | cut -d: -f6)

Dispatch a run and confirm the log is clean:

    gh workflow run "firecracker (KVM)" -R $REPO
    gh run list -R $REPO --workflow "firecracker (KVM)" -L 1

Then, against that run id — both should be 0:

    rm -rf ~/.cache/gh   # it serves stale logs, and will show the old text
    gh run view <id> -R $REPO --log | grep -c "\$(hostname)"
    gh run view <id> -R $REPO --log | grep -c "$HOME"

The old directory is still at $OLD_DIR. Remove it once a run is green:

    sudo rm -rf $OLD_DIR
EOF
