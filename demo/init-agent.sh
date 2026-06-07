#!/bin/sh
# /sbin/init.agent — PID 1 inside the microVM for the REAL in-VM agent run
# (issue #16). Unlike init-attack.sh (which just probes egress), this boots the
# lex-os-guest agent binary, which:
#   - connects to the host supervisor over vsock (AF_VSOCK → CID 2),
#   - drives the LLM reasoning loop by calling Ollama over the ONE allowed
#     egress target, and
#   - relays each proposed action to the supervisor for mediation.
#
# Ollama host/model come from the kernel cmdline (ollama_host=, ollama_model=)
# so the host can set them per run; sensible defaults otherwise.

mount -t proc  proc /proc 2>/dev/null
mount -t sysfs sys  /sys  2>/dev/null

# Parse ollama_host / ollama_model / guest_script from the kernel command line.
OLLAMA_HOST=""
OLLAMA_MODEL=""
LEX_OS_GUEST_SCRIPT=""
for tok in $(cat /proc/cmdline 2>/dev/null); do
  case "$tok" in
    ollama_host=*)  OLLAMA_HOST="${tok#ollama_host=}" ;;
    ollama_model=*) OLLAMA_MODEL="${tok#ollama_model=}" ;;
    guest_script=*) LEX_OS_GUEST_SCRIPT="${tok#guest_script=}" ;;
  esac
done
: "${OLLAMA_HOST:=192.168.1.165:11434}"
: "${OLLAMA_MODEL:=devstral-small-2:latest}"
export OLLAMA_HOST OLLAMA_MODEL LEX_OS_GUEST_SCRIPT

# Bring up the guest NIC. The host owns the .1 of the /30 tap; we are .2.
# Egress beyond the allowlist is dropped at the host tap (the whole point).
ip addr add 169.254.42.2/30 dev eth0 2>/dev/null
ip link set eth0 up 2>/dev/null
ip route add default via 169.254.42.1 2>/dev/null

echo "[init-agent] eth0 up; ollama=$OLLAMA_HOST model=$OLLAMA_MODEL script=$LEX_OS_GUEST_SCRIPT; id=$(id)"
echo "[init-agent] starting lex-os-guest"
/usr/bin/lex-os-guest
echo "[init-agent] agent exited ($?); powering off"
poweroff -f
