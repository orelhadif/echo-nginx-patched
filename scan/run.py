#!/usr/bin/env python3
"""All scans, in one place. Writes:
  scan/baseline/trivy.json, grype.json      the original image, rescanned with the SAME
                                            scanner DB as the new image (a fair diff)
  scan/new-trivy.json, scan/new-grype.json  raw rescans of the patched image
  scan/diff-vs-baseline.txt                 what changed vs. scan/baseline/*.json
  scan/scan-with-vex.txt                    both images with/without the targeted VEX,
                                            plus the CPE scan of the upstream SBOM
Usage: python3 scan/run.py [NEW_IMAGE] [ORIG_IMAGE]   (needs trivy, grype)
"""
import json
import os
import subprocess
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
NEW = sys.argv[1] if len(sys.argv) > 1 else "echo-nginx:1.25-bookworm-patched"
ORIG = sys.argv[2] if len(sys.argv) > 2 else "nginx:1.25-bookworm"
VEX = "vex/echo-nginx.openvex.json"
SBOM = "sbom:vex/upstream-components.cdx.json"
FOCUS = ["CVE-2026-27171", "CVE-2025-23419", "CVE-2026-42945"]


def run(*args):
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=True).stdout


def trivy(image, vex=None):
    return json.loads(run("trivy", "image", "--quiet", "--scanners", "vuln", "-f", "json",
                          *(["--vex", vex] if vex else []), image))


def grype(target, vex=None):
    return json.loads(run("grype", target, "-q", "-o", "json", *(["--vex", vex] if vex else [])))


def found(report):
    """(CVE, package) pairs in a Trivy or Grype report."""
    if "matches" in report:
        return [(m["vulnerability"]["id"], m["artifact"]["name"]) for m in report["matches"]]
    return [(v["VulnerabilityID"], v["PkgName"])
            for r in report.get("Results", []) for v in r.get("Vulnerabilities") or []]


def summary(report):
    pairs = found(report)
    lines = []
    for cve in FOCUS:
        hits = sorted({p for c, p in pairs if c == cve})
        lines.append("    %-15s %s" % (cve, "REPORTED on " + ", ".join(hits) if hits else "not reported"))
    lines.append("    total findings: %d" % len(pairs))
    return "\n".join(lines)


def main():
    print("rescanning %s and %s" % (ORIG, NEW), file=sys.stderr)
    plain = {(img, tool): scan(img) for img in (ORIG, NEW) for tool, scan in (("trivy", trivy), ("grype", grype))}
    for name, key in (("baseline/trivy.json", (ORIG, "trivy")), ("baseline/grype.json", (ORIG, "grype")),
                      ("new-trivy.json", (NEW, "trivy")), ("new-grype.json", (NEW, "grype"))):
        with open(os.path.join(ROOT, "scan", name), "w") as f:
            json.dump(plain[key], f)
    diff = run(sys.executable, "scan/diff_scans.py", "scan/baseline/trivy.json", "scan/baseline/grype.json",
               "scan/new-trivy.json", "scan/new-grype.json", "--focus", *FOCUS)
    with open(os.path.join(ROOT, "scan", "diff-vs-baseline.txt"), "w") as f:
        f.write(diff)

    out = []
    for img in (NEW, ORIG):
        out += ["== %s without VEX" % img,
                "  trivy", summary(plain[img, "trivy"]), "  grype", summary(plain[img, "grype"]),
                "== %s WITH %s" % (img, VEX),
                "  trivy", summary(trivy(img, VEX)), "  grype", summary(grype(img, VEX))]
    for vex in (None, VEX):
        out.append("== CPE scan of vex/upstream-components.cdx.json %s" % ("WITH " + vex if vex else "without VEX"))
        out += ["  grype", summary(grype(SBOM, vex))]
    out += ["", "== Upstream nginx/zlib CVEs still open (CPE scan WITH VEX): residual risk",
            run("grype", SBOM, "-q", "--vex", VEX, "-o", "table")]
    with open(os.path.join(ROOT, "scan", "scan-with-vex.txt"), "w") as f:
        f.write("\n".join(out))
    print("wrote scan/baseline/*.json scan/new-trivy.json scan/new-grype.json scan/diff-vs-baseline.txt scan/scan-with-vex.txt",
          file=sys.stderr)


if __name__ == "__main__":
    main()
