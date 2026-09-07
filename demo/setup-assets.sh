#!/usr/bin/env bash
# Fetch the binary assets the Firecracker perimeter needs (~330 MB total).
# Idempotent: skips files already present. Only the final binary install to
# /usr/local/bin needs sudo; everything else lands in demo/assets/.
#
#   bash demo/setup-assets.sh    # fetch into demo/assets/
#   sudo bash demo/setup-assets.sh   # ...and install firecracker to PATH

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/assets"

FC_VERSION=v1.16.1

# Firecracker does not emulate a foreign ISA, so the guest architecture is
# the host's. `uname -m` spells it the same way Firecracker's release
# tarballs and the quickstart bucket do, which is why nothing is mapped
# here — anything else is a host this script has never been run on, and
# saying so beats fetching an x86 kernel onto an ARM box and watching a
# microVM fail to boot for reasons nobody will guess.
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|aarch64) ;;
  *)
    echo "! unsupported architecture: $ARCH" >&2
    echo "  Firecracker publishes x86_64 and aarch64 builds only." >&2
    exit 1
    ;;
esac
# The Rust target for the in-VM agent, which has no such convention.
MUSL_TARGET="${ARCH}-unknown-linux-musl"

FC_TGZ="firecracker-${FC_VERSION}-${ARCH}.tgz"
FC_REL="release-${FC_VERSION}-${ARCH}"
# The guest kernel, from Firecracker's CI bucket rather than the
# quickstart one (#82).
#
# The quickstart kernel is 4.14.174, built in 2021, and has **no
# virtio-rng driver**. A microVM boots with almost no entropy and
# `getrandom(2)` blocks until the pool is *fully* seeded — not merely
# "fast init done", which is all a bare box reaches — so anything wanting
# randomness early hangs. Go's runtime, Rust's `getrandom` and every TLS
# handshake sit behind that call, which ruled out most real workloads in
# a box whose entire purpose is running them.
#
# The CI kernels carry CONFIG_HW_RANDOM_VIRTIO=y, so the entropy device
# the perimeter now asks for has a driver to bind to.
KERNEL_VERSION=${KERNEL_VERSION:-6.1.102}
KERNEL_URL=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.11/${ARCH}/vmlinux-${KERNEL_VERSION}
ROOTFS_URL=https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/${ARCH}/rootfs/bionic.rootfs.ext4

# 1. Firecracker + jailer binaries, staged in demo/assets/.
if [ ! -x ./firecracker ]; then
  echo "+ fetching firecracker $FC_VERSION ($ARCH)"
  curl -fsSL -o "$FC_TGZ" \
    "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/${FC_TGZ}"
  # The tarball keeps everything under release-<ver>-<arch>/; extract just the
  # two binaries we use (do NOT --strip-components, it breaks the paths below).
  tar xzf "$FC_TGZ" \
    "${FC_REL}/firecracker-${FC_VERSION}-${ARCH}" \
    "${FC_REL}/jailer-${FC_VERSION}-${ARCH}"
  install -m 0755 "${FC_REL}/firecracker-${FC_VERSION}-${ARCH}" ./firecracker
  install -m 0755 "${FC_REL}/jailer-${FC_VERSION}-${ARCH}"      ./jailer
  rm -rf "$FC_REL" "$FC_TGZ"
fi

# 2. Install firecracker + jailer onto PATH (needs root). vm.rs spawns
#    firecracker directly (unjailed) or via jailer (the hardened, non-root path).
#
#    Version-aware, deliberately. The earlier `command -v firecracker ||
#    install` skipped the install whenever *any* firecracker was already on
#    PATH — so bumping FC_VERSION here changed what got downloaded into
#    demo/assets/ and left the host running the old binary, with nothing
#    saying so. A pin that does not reach the machine is not a pin.
install_if_stale() {
  tool="$1"
  want="${FC_VERSION#v}"
  have="$("$tool" --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  if [ "$have" = "$want" ]; then
    echo "+ $tool $have already on PATH"
    return 0
  fi
  if [ "$(id -u)" -eq 0 ]; then
    echo "+ installing $tool ${have:+$have -> }$want to /usr/local/bin"
    install -m 0755 "./$tool" "/usr/local/bin/$tool"
  else
    echo "! $tool on PATH is ${have:-absent}, want $want; re-run with sudo, or:"
    echo "    sudo install -m 0755 $(pwd)/$tool /usr/local/bin/$tool"
  fi
}
install_if_stale firecracker
install_if_stale jailer

# 3. Guest kernel + rootfs.
# Replace a kernel that cannot drive the entropy device, not merely a
# missing one. A host that ran an older setup-assets has a 4.14 vmlinux
# sitting here, and "the file exists" would keep it — the same shape of
# bug that let the firecracker pin go stale on a machine that already had
# one. Detected by content: the driver's name is in the image or it is
# not.
# `grep -c`, not `grep -q`. Under `set -o pipefail` a `grep -q` exits on
# the first match, SIGPIPEs `strings`, and the pipeline reports 141 — so
# the test says "no driver" about a kernel that has one, and the fetch
# repeats on every run. `-c` reads to EOF and has no such opinion.
has_virtio_rng() {
  [ -f "$1" ] || return 1
  [ "$(strings "$1" 2>/dev/null | grep -icE 'virtio_rng|virtio-rng')" -gt 0 ]
}

if has_virtio_rng vmlinux; then
  echo "+ guest kernel already has virtio-rng"
else
  [ -f vmlinux ] && echo "+ replacing a guest kernel with no virtio-rng (#82)"
  echo "+ fetching guest kernel $KERNEL_VERSION ($ARCH)"
  curl -fsSL -o vmlinux "$KERNEL_URL"
  has_virtio_rng vmlinux || {
    echo "! the fetched kernel has no virtio-rng; anything calling getrandom(2)" >&2
    echo "  early will block in the box (see lex-os#82)" >&2
  }
fi
[ -f rootfs.ext4 ] || { echo "+ fetching guest rootfs"; curl -fsSL -o rootfs.ext4 "$ROOTFS_URL"; }

# 4. Build the in-VM agent binary (static musl, with the vsock transport) so
#    it can be injected into the rootfs. Build as the invoking user — root has
#    no rustup toolchain. Skipped if the musl target isn't installed.
REPO_ROOT="$(cd ../.. && pwd)"
GUEST_BIN="$REPO_ROOT/target/${MUSL_TARGET}/release/lex-os-guest"
build_as=(cargo)
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  build_as=(sudo -u "$SUDO_USER" -H -- cargo)
fi
echo "+ building static musl agent binary (lex-os-guest, --features vsock, $MUSL_TARGET)"
( cd "$REPO_ROOT" && "${build_as[@]}" build --release \
    --target "$MUSL_TARGET" -p lex-os-guest --features vsock ) \
  || echo "! musl build failed (need: rustup target add $MUSL_TARGET); agent not injected"

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

echo "+ assets in $(pwd) ($ARCH)"
ls -lh firecracker jailer vmlinux rootfs.ext4
./firecracker --version | head -1
