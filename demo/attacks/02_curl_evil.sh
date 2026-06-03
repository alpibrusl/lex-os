#!/usr/bin/env sh
# Attack #2 — kernel egress wall (issue #14 "Attempt 2").
#
# This attack now runs *inside* the provisioned microVM. The canonical,
# executed script is demo/init-attack.sh, which demo/setup-assets.sh
# installs into the guest rootfs as /sbin/init.demo. Firecracker boots it
# via init=/sbin/init.demo (FirecrackerAssets::default in
# crates/lex-os-perimeter/src/firecracker/mod.rs).
#
# The wall is host-side iptables on the VM's tap device
# (crates/lex-os-perimeter/src/firecracker/net.rs):
#
#   ACCEPT tap-lex0 → <allowlisted host>:<port>
#   DROP   tap-lex0 → everything else
#
# The agent is root inside the VM but the dropping rule lives on the host,
# on a tap device the guest does not own — there is no in-guest config it
# can flip to make evil.com succeed. Guest console output (allowed OK,
# evil.com + 8.8.8.8 blocked) is piped to Firecracker's stdout and folded
# into the audit log.
echo "see demo/init-attack.sh — attack #2 runs inside the microVM as /sbin/init.demo"
exit 0
