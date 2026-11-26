#!/usr/bin/env python3
"""Diff two pairs of scanner reports (baseline vs new image).

Usage: diff_scans.py BASE_TRIVY BASE_GRYPE NEW_TRIVY NEW_GRYPE [--focus CVE ...]

A finding is the pair (CVE id, package name). We report, per scanner, what
disappeared, what appeared and what stayed, and print every finding for the
--focus CVEs (the ones we fixed) in both images. Python 3.9+, stdlib only.
"""
import argparse
import collections
import json


def trivy(path):
    out = {}
    for r in json.load(open(path)).get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            out[(v["VulnerabilityID"], v["PkgName"])] = {
                "version": v.get("InstalledVersion"), "severity": v.get("Severity"),
                "status": v.get("Status"), "fixed": v.get("FixedVersion", "")}
    return out


def grype(path):
    out = {}
    for m in json.load(open(path)).get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        out[(v["id"], a["name"])] = {
            "version": a.get("version"), "severity": v.get("severity"),
            "status": v.get("fix", {}).get("state"),
            "fixed": ",".join(v.get("fix", {}).get("versions") or [])}
    return out


def by_severity(keys, findings):
    return dict(collections.Counter(findings[k]["severity"] for k in keys))


def top_packages(keys):
    return ", ".join("%s(%d)" % kv for kv in collections.Counter(k[1] for k in keys).most_common(12))


def main():
    ap = argparse.ArgumentParser()
    for name in ("base_trivy", "base_grype", "new_trivy", "new_grype"):
        ap.add_argument(name)
    ap.add_argument("--focus", nargs="*", default=[])
    a = ap.parse_args()

    for scanner, load, base_path, new_path in (("Trivy", trivy, a.base_trivy, a.new_trivy),
                                               ("Grype", grype, a.base_grype, a.new_grype)):
        base, new = load(base_path), load(new_path)
        gone, appeared, kept = set(base) - set(new), set(new) - set(base), set(base) & set(new)
        print("== %s" % scanner)
        print("  baseline: %4d findings, %4d unique CVEs" % (len(base), len({k[0] for k in base})))
        print("  new:      %4d findings, %4d unique CVEs" % (len(new), len({k[0] for k in new})))
        print("  disappeared: %4d  by severity %s" % (len(gone), by_severity(gone, base)))
        print("  appeared:    %4d  by severity %s" % (len(appeared), by_severity(appeared, new)))
        print("  unchanged:   %4d" % len(kept))
        print("  disappeared, by package: %s" % top_packages(gone))
        print("  appeared, by package:    %s" % top_packages(appeared))
        for cve in a.focus:
            for label, findings in (("baseline", base), ("new", new)):
                hits = {pkg: v for (c, pkg), v in findings.items() if c == cve}
                print("  %-16s %-8s %s" % (cve, label, "; ".join(
                    "%s %s [%s, %s%s]" % (pkg, v["version"], v["severity"], v["status"],
                                          ", fixed " + v["fixed"] if v["fixed"] else "")
                    for pkg, v in sorted(hits.items())) or "not reported"))
        print()


if __name__ == "__main__":
    main()
