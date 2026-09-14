#!/usr/bin/env bash
# The baseline, in the strongest form the ecosystem has.
set -uo pipefail
cd "$(dirname "$0")"

cat <<'TXT'
  Deno, not Python: the point is not that Lex beats a runtime with no
  authority model. It is that it answers a question the best existing
  one still cannot. Deno's permissions are genuinely good — default
  deny, per-host network, per-path filesystem, per-variable environment,
  enforced by the runtime — and everything below assumes that.

TXT

echo "  1. the source diff — the change is right there:"
diff -u deno/v1_report.ts deno/v2_report.ts | sed 's/^/     /'

echo
echo "  2. the artifact that carries the authority:"
echo "     deno/launch.sh —"
sed -n '/^exec/,$p' deno/launch.sh | sed 's/^/       /'
echo "     unchanged between v1 and v2, and nothing made it change."

echo
echo "  3. what Deno does here, and does well — run, not described:"
echo
if command -v deno >/dev/null 2>&1; then
  echo "     \$ deno run --allow-net=results.demo.internal drive_v2.ts"
  (cd deno && deno run --allow-net=results.demo.internal drive_v2.ts 2>&1)
  echo
  echo "     The token read is what it reached first. Permit that, and the"
  echo "     refusal moves down to the fetch:"
  echo
  echo "     \$ TELEMETRY_TOKEN=… deno run --allow-net=results.demo.internal \\"
  echo "         --allow-env=TELEMETRY_TOKEN drive_v2.ts"
  (cd deno && TELEMETRY_TOKEN=demo-token deno run \
      --allow-net=results.demo.internal \
      --allow-env=TELEMETRY_TOKEN drive_v2.ts 2>&1)
else
  echo "     deno is not installed here, so this is the recorded transcript"
  echo "     of the two runs above, from deno 2.9.6. Install deno (or"
  echo "     \`npm i deno\`) and re-run this script to reproduce it:"
  echo
  echo "     \$ deno run --allow-net=results.demo.internal drive_v2.ts"
  echo "     report built: runs=120 failures=3"
  echo "     telemetry: REFUSED by Deno — NotCapable"
  echo "       NotCapable: Requires env access to \"TELEMETRY_TOKEN\", run again with the --allow-env flag"
  echo
  echo "     \$ TELEMETRY_TOKEN=… deno run --allow-net=results.demo.internal \\"
  echo "         --allow-env=TELEMETRY_TOKEN drive_v2.ts"
  echo "     report built: runs=120 failures=3"
  echo "     telemetry: REFUSED by Deno — NotCapable"
  echo "       NotCapable: Requires net access to \"telemetry.vendor.example:443\", run again with the --allow-net flag"
fi

cat <<'TXT'

  That is a real wall, and it holds. Note where it landed, though: on
  the env read, because that is what the code reached first. The wall
  is wherever execution happens to arrive, in the order it arrives —
  not a statement about the program. Had `pushTelemetry` sat behind a
  feature flag, an error path, or a nightly branch, neither refusal
  would have fired today, and the deploy would have looked clean.

  Four things it still cannot do, none of them a missing feature:

    - It cannot tell you what the program needs. `fetch(url)` takes a
      runtime value, so the set of hosts a JavaScript program may reach
      is not a property any tool can read off the source. Lex's effect
      rows are that property, and the type checker has already refused
      any row that lies about its body.

    - Authority is process-wide, not per-function. `--allow-net=a,b`
      grants both hosts to every line that runs, transitive dependencies
      included. There is no sense in which `submit` may reach the
      results endpoint and `pushTelemetry` may not.

    - There is no delta. Nothing about v2 changes any file a CI job
      could refuse on. If a human does update the flags, that edit is
      the only signal there is — written by the same human who would
      have had to notice in the first place.

    - The flags only ever grow. Nobody removes `--allow-read` because
      nobody can prove it is unused. `lex-os authority narrow` removes
      it on a proof.

  So the refusal arrives at run time, in the environment that has the
  token, on the code path that happens to run, after the deploy — and
  it never arrives at all for a path that does not run that day.
  `lex-os authority gate` refuses the same change before it is merged,
  and names the host that caused it.

  The same holds for WASI, whose capabilities (preopened directories,
  granted sockets) are likewise handed in from outside rather than read
  out of the code.

TXT

echo "  And the common case — Python behind a container sandbox:"
echo "     the sandbox for that job is three files:"
for f in python-docker/Dockerfile python-docker/seccomp.json python-docker/networkpolicy.yaml; do
  printf '       %-34s %s bytes\n' "$f" "$(wc -c < "$f" | tr -d ' ')"
done
cat <<'TXT'
     v2 requires an edit to none of them, and none of them would refuse
     it either: the Dockerfile says which packages exist, not which
     hosts are reached; seccomp says connect(2) is permitted, not to
     where; the NetworkPolicy names one destination but nothing ties it
     to the code. Strictly weaker than the Deno case above.
TXT
