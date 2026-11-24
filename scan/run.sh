#!/usr/bin/env bash
# All scans of the new image, in one place. Writes:
#   scan/new-trivy.json, scan/new-grype.json  raw rescans of the patched image
#   scan/diff-vs-baseline.txt                 what changed vs. scan/baseline/*.json
#   scan/scan-with-vex.txt                    both images with/without the targeted VEX,
#                                             plus the CPE scan of the upstream SBOM
# Usage: scan/run.sh [NEW_IMAGE] [ORIG_IMAGE]   (needs trivy, grype, python3)
set -euo pipefail
cd "$(dirname "$0")/.."
NEW=${1:-echo-nginx:1.25-bookworm-patched}
ORIG=${2:-nginx:1.25-bookworm}
VEX=vex/echo-nginx.openvex.json
FOCUS="CVE-2026-27171 CVE-2025-23419"

echo "rescanning $NEW" >&2
trivy image --quiet --format json -o scan/new-trivy.json "$NEW"
grype "$NEW" -q -o json > scan/new-grype.json
python3 scan/diff_scans.py scan/baseline/trivy.json scan/baseline/grype.json \
    scan/new-trivy.json scan/new-grype.json --focus $FOCUS > scan/diff-vs-baseline.txt
exec > scan/scan-with-vex.txt   # everything below is the VEX report

pick() {  # pick SCANNER < json : print the focus CVEs a report still contains
  python3 -c '
import json, sys
d, focus = json.load(sys.stdin), sys.argv[2].split()
if sys.argv[1] == "trivy":
    found = [(v["VulnerabilityID"], v["PkgName"]) for r in d.get("Results", []) for v in r.get("Vulnerabilities") or []]
else:
    found = [(m["vulnerability"]["id"], m["artifact"]["name"]) for m in d["matches"]]
for c in focus:
    hits = sorted({p for i, p in found if i == c})
    print("    %-15s %s" % (c, ("REPORTED on " + ", ".join(hits)) if hits else "not reported"))
print("    total findings: %d" % len(found))' "$1" "$FOCUS"
}

for img in "$NEW" "$ORIG"; do
  for vex in "" "$VEX"; do
    echo "== $img $([ -n "$vex" ] && echo "WITH $vex" || echo "without VEX")"
    echo "  trivy"; trivy image --quiet --scanners vuln ${vex:+--vex $vex} -f json "$img" 2>/dev/null | pick trivy
    echo "  grype"; grype "$img" -q ${vex:+--vex $vex} -o json | pick grype
  done
done
for vex in "" "$VEX"; do
  echo "== CPE scan of vex/upstream-components.cdx.json $([ -n "$vex" ] && echo "WITH $vex" || echo "without VEX")"
  echo "  grype"; grype sbom:vex/upstream-components.cdx.json -q ${vex:+--vex $vex} -o json | pick grype
done

echo
echo "== Upstream nginx/zlib CVEs still open (CPE scan WITH VEX): residual risk"
grype sbom:vex/upstream-components.cdx.json -q --vex "$VEX" -o table
