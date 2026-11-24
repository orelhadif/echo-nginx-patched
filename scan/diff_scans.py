#!/usr/bin/env python3
"""Diff two pairs of scanner reports (baseline vs new image).

Usage: diff_scans.py BASE_TRIVY BASE_GRYPE NEW_TRIVY NEW_GRYPE [--focus CVE ...]

A finding is the pair (CVE id, package name). We report, per scanner, what
disappeared, what appeared and what stayed, and print every finding for the
--focus CVEs (the two we fixed) in both images. Python 3.9+, stdlib only.
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_trivy"), ap.add_argument("base_grype")
    ap.add_argument("new_trivy"), ap.add_argument("new_grype")
    ap.add_argument("--focus", nargs="*", default=[])
    a = ap.parse_args()

    for name, load, bp, np_ in (("Trivy", trivy, a.base_trivy, a.new_trivy),
                                ("Grype", grype, a.base_grype, a.new_grype)):
        b, n = load(bp), load(np_)
        gone, new, kept = set(b) - set(n), set(n) - set(b), set(b) & set(n)
        sev = lambda keys, src: dict(collections.Counter(src[k]["severity"] for k in keys))
        print("== %s" % name)
        print("  baseline: %4d findings, %4d unique CVEs" % (len(b), len({k[0] for k in b})))
        print("  new:      %4d findings, %4d unique CVEs" % (len(n), len({k[0] for k in n})))
        print("  disappeared: %4d  by severity %s" % (len(gone), sev(gone, b)))
        print("  appeared:    %4d  by severity %s" % (len(new), sev(new, n)))
        print("  unchanged:   %4d" % len(kept))
        gone_pkgs = collections.Counter(k[1] for k in gone)
        print("  disappeared, by package: %s" % ", ".join("%s(%d)" % kv for kv in gone_pkgs.most_common(12)))
        new_pkgs = collections.Counter(k[1] for k in new)
        print("  appeared, by package:    %s" % ", ".join("%s(%d)" % kv for kv in new_pkgs.most_common(12)))
        for cve in a.focus:
            for label, src in (("baseline", b), ("new", n)):
                hits = {k[1]: v for k, v in src.items() if k[0] == cve}
                print("  %-16s %-8s %s" % (cve, label, "; ".join(
                    "%s %s [%s, %s%s]" % (p, v["version"], v["severity"], v["status"],
                                          ", fixed " + v["fixed"] if v["fixed"] else "")
                    for p, v in sorted(hits.items())) or "not reported"))
        print()


if __name__ == "__main__":
    main()
