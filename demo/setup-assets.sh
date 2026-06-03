#!/usr/bin/env bash
# Fetch the binary assets the Firecracker perimeter needs (~330 MB total).
# Idempotent: skips files already present. Only the final binary install to
# /usr/local/bin needs sudo; everything else lands in demo/assets/.
#
#   bash demo/setup-assets.sh    # fetch into demo/assets/
#   sudo bash demo/setup-assets.sh   # ...and install firecracker to PATH

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/assets"

FC_VERSION=v1.9.1
FC_TGZ="firecracker-${FC_VERSION}-x86_64.tgz"
FC_REL="release-${FC_VERSION}-x86_64"
KERNEL_URL=https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin
ROOTFS_URL=https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4

# 1. Firecracker + jailer binaries, staged in demo/assets/.
if [ ! -x ./firecracker ]; then
  echo "+ fetching firecracker $FC_VERSION"
  curl -fsSL -o "$FC_TGZ" \
    "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/${FC_TGZ}"
  # The tarball keeps everything under release-<ver>-x86_64/; extract just the
  # two binaries we use (do NOT --strip-components, it breaks the paths below).
  tar xzf "$FC_TGZ" \
    "${FC_REL}/firecracker-${FC_VERSION}-x86_64" \
    "${FC_REL}/jailer-${FC_VERSION}-x86_64"
  install -m 0755 "${FC_REL}/firecracker-${FC_VERSION}-x86_64" ./firecracker
  install -m 0755 "${FC_REL}/jailer-${FC_VERSION}-x86_64"      ./jailer
  rm -rf "$FC_REL" "$FC_TGZ"
fi

# 2. Install firecracker onto PATH so vm.rs can spawn it (needs root).
if ! command -v firecracker >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then
    echo "+ installing firecracker to /usr/local/bin"
    install -m 0755 ./firecracker /usr/local/bin/firecracker
  else
    echo "! firecracker not on PATH; re-run with sudo, or:"
    echo "    sudo install -m 0755 $(pwd)/firecracker /usr/local/bin/firecracker"
  fi
fi

# 3. Guest kernel + rootfs.
[ -f vmlinux ]     || { echo "+ fetching guest kernel"; curl -fsSL -o vmlinux "$KERNEL_URL"; }
[ -f rootfs.ext4 ] || { echo "+ fetching guest rootfs"; curl -fsSL -o rootfs.ext4 "$ROOTFS_URL"; }

# 4. Build the in-VM agent binary (static musl, with the vsock transport) so
#    it can be injected into the rootfs. Build as the invoking user — root has
#    no rustup toolchain. Skipped if the musl target isn't installed.
REPO_ROOT="$(cd ../.. && pwd)"
GUEST_BIN="$REPO_ROOT/target/x86_64-unknown-linux-musl/release/lex-os-guest"
build_as=(cargo)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  build_as=(sudo -u "$SUDO_USER" -H -- cargo)
fi
echo "+ building static musl agent binary (lex-os-guest, --features vsock)"
( cd "$REPO_ROOT" && "${build_as[@]}" build --release \
    --target x86_64-unknown-linux-musl -p lex-os-guest --features vsock ) \
  || echo "! musl build failed (need: rustup target add x86_64-unknown-linux-musl); agent not injected"

# 5. Inject the guest inits + agent binary into the rootfs. Needs root to
#    loop-mount. /sbin/init.demo = attack-probe demo (init-attack.sh);
#    /sbin/init.agent = real in-VM agent (init-agent.sh) which execs
#    /usr/bin/lex-os-guest. The perimeter picks one via the kernel cmdline.
if [ "$(id -u)" -eq 0 ]; then
  echo "+ injecting inits + agent binary into the rootfs"
  mnt="$(mktemp -d)"
  mount -o loop rootfs.ext4 "$mnt"
  install -m 0755 ../init-attack.sh "$mnt/sbin/init.demo"
  install -m 0755 ../init-agent.sh  "$mnt/sbin/init.agent"
  [ -f "$GUEST_BIN" ] && install -m 0755 "$GUEST_BIN" "$mnt/usr/bin/lex-os-guest"
  umount "$mnt"
  rmdir "$mnt"
else
  echo "! skipping rootfs injection (needs root); re-run with sudo"
fi

echo "+ assets in $(pwd)"
ls -lh firecracker jailer vmlinux rootfs.ext4
./firecracker --version | head -1
