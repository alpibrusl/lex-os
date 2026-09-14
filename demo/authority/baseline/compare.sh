#!/usr/bin/env bash
# The point of the baseline, in two diffs.
set -uo pipefail
cd "$(dirname "$0")"

echo "  1. the source diff — the change is right there, a dozen lines:"
diff -u v1_report.py v2_report.py | sed 's/^/     /'

echo
echo "  2. the policy diff — what the sandbox knows about that change:"
echo "     the sandbox for this job is three files:"
for f in Dockerfile seccomp.json networkpolicy.yaml; do
  printf '       %-20s %s bytes\n' "$f" "$(wc -c < "$f" | tr -d ' ')"
done
echo "     v2 requires an edit to none of them, so the diff is empty."

cat <<'TXT'

  There is no third artifact to diff. The authority this code claims is
  not written down anywhere a reviewer or a CI job can read it:

    - the Dockerfile says which packages exist, not which hosts are reached;
    - seccomp says connect(2) is permitted, not to where;
    - the NetworkPolicy names one destination, but nothing ties it to the
      code — it neither knows v2 added a second host nor fails when it did.

  Two ways to find out are available, and both are worse:

    - run it and watch the traffic. That reports what one run did, not what
      the code can do. A telemetry push behind `if token:` is invisible on
      any run without the token set.
    - read the diff and notice. Which is the thing that does not scale, and
      the reason this demo exists.

  The NetworkPolicy would eventually stop v2 — at run time, in the
  environment that has the token, as an opaque connection timeout, after
  the deploy. Not before the change was approved.
TXT
