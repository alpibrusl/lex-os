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

# 4. Inject the guest-side attack init (attack #2) into the rootfs as
#    /sbin/init.demo. The perimeter boots it via init=/sbin/init.demo (see
#    FirecrackerAssets::default in firecracker/mod.rs). Needs root to loop-mount.
if [ "$(id -u)" -eq 0 ]; then
  echo "+ injecting init-attack.sh into the rootfs (/sbin/init.demo)"
  mnt="$(mktemp -d)"
  mount -o loop rootfs.ext4 "$mnt"
  install -m 0755 ../init-attack.sh "$mnt/sbin/init.demo"
  umount "$mnt"
  rmdir "$mnt"
else
  echo "! skipping rootfs init injection (needs root); re-run with sudo to enable attack #2"
fi

echo "+ assets in $(pwd)"
ls -lh firecracker jailer vmlinux rootfs.ext4
./firecracker --version | head -1
