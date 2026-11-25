#!/usr/bin/env python3
"""Generate the targeted VEX (OpenVEX) and an upstream-components SBOM for OUR image.

Why two files:
  * echo-nginx.openvex.json - says "CVE-2026-27171, CVE-2025-23419 and CVE-2026-42945
    are fixed"
    for exactly one artifact: our image digest and our exact package versions
    (+echo1). It does not touch any other image, any other version, or any other CVE.
  * upstream-components.cdx.json - a CycloneDX SBOM naming the upstream projects
    inside the image by CPE (f5:nginx 1.25.5, zlib:zlib 1.4). Debian-tracker based
    package matching never reports CVE-2025-23419 on this image (see
    scan/diff-vs-baseline.txt), so without this SBOM there is no finding for the
    VEX to act on; with it, Grype reports the CVEs the way NVD sees nginx 1.25.5.

Digest and versions are read from the image itself, so after a rebuild just rerun:
    python3 vex/make_vex.py [IMAGE]
Python 3.9+, standard library only.
"""
import datetime
import json
import os
import subprocess
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGE = sys.argv[1] if len(sys.argv) > 1 else "echo-nginx:1.25-bookworm-patched"


def sh(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def q(s):
    return urllib.parse.quote(s, safe="")


info = json.loads(sh("docker", "image", "inspect", IMAGE))[0]
digests = [d.split("@", 1)[1] for d in info.get("RepoDigests") or []] or [info["Id"]]
digest = digests[0]
name = IMAGE.split(":")[0].split("@")[0]
arch = info["Architecture"]
ver = dict(l.split(" ", 1) for l in sh(
    "docker", "run", "--rm", "--entrypoint", "dpkg-query", IMAGE, "-W",
    "-f=${Package} ${Version}\n", "zlib1g", "nginx").splitlines())
distro = sh("docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c",
            ". /etc/os-release; echo debian-$(cat /etc/debian_version)")

image_purl = "pkg:oci/%s@%s" % (name, q(digest))


def deb_purls(pkg, version):
    """The same Debian package as Trivy and Grype spell it in their reports."""
    epoch, _, upstream = version.rpartition(":")
    trivy = "pkg:deb/debian/%s@%s?arch=%s" % (pkg, q(upstream), arch) + (
        "&epoch=%s" % epoch if epoch else "")
    grype = "pkg:deb/debian/%s@%s?arch=%s" % (pkg, q(version), arch)
    return list(dict.fromkeys([trivy, grype]))  # identical when there is no epoch


nginx_generic = "pkg:generic/nginx@%s" % q(ver["nginx"])
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
now = now.replace("+00:00", "Z")

statements = [
    {
        "vulnerability": {
            "name": "CVE-2026-27171",
            "description": "zlib: crc32_combine64()/x2nmodp() never terminate for a negative len2",
        },
        "products": [{"@id": image_purl,
                      "subcomponents": [{"@id": p} for p in deb_purls("zlib1g", ver["zlib1g"])]}],
        "status": "fixed",
        "status_notes": (
            "Fixed by a version bump: zlib1g %s is upstream zlib 1.4 built from the "
            "release tarball pinned by sha256 (build/Dockerfile, part 1); "
            "1.4 returns 0 for len2 < 0. Scanners still match the Debian tracker entry "
            "for source package 'zlib', which has no fixed version, so every version is "
            "flagged. Evidence from the image itself: vex/evidence.txt (nginx maps "
            "libz.so.1.4; crc32_combine(len2=-1) returns 0, 1.2.13 loops forever)."
            % ver["zlib1g"]),
    },
    {
        "vulnerability": {
            "name": "CVE-2025-23419",
            "description": "nginx: TLS 1.3 session resumption across SNI virtual servers bypasses client certificate authentication",
        },
        "products": [
            {"@id": image_purl,
             "subcomponents": [{"@id": p} for p in deb_purls("nginx", ver["nginx"]) + [nginx_generic]]},
            # SBOM-based scans carry no registry digest, so the package identity of
            # OUR build (version suffix +echo1) is the product there.
            {"@id": nginx_generic},
        ],
        "status": "fixed",
        "status_notes": (
            "Fixed by backporting upstream commit 13935cf9fdc3c8d8278c70716417d3b71c36140e "
            "(released in 1.27.4/1.26.3) unmodified onto 1.25.5: "
            "build/patches/CVE-2025-23419.patch, applied with fuzz 0 by the nginx.org "
            "packaging (build/Dockerfile, part 2). The version string stays 1.25.5, so "
            "version-based matching (CPE) still reports it. Evidence from the image "
            "itself: vex/evidence.txt (/usr/sbin/nginx and nginx-debug reference "
            "SSL_SESSION_get0_hostname, the function the fix adds; the original binaries "
            "do not). Attack test: test/cve_test.py (rejected in http and stream)."),
    },
    {
        "vulnerability": {
            "name": "CVE-2026-42945",
            "description": "nginx: rewrite module escapes a later regex capture into a buffer sized for the unescaped value (heap buffer overrun)",
        },
        "products": [
            {"@id": image_purl,
             "subcomponents": [{"@id": p} for p in deb_purls("nginx", ver["nginx"]) + [nginx_generic]]},
            {"@id": nginx_generic},
        ],
        "status": "fixed",
        "status_notes": (
            "Fixed by backporting upstream commit 524977e7c534e87e5b55739fa74601c9f1102686 "
            "(released in 1.30.1) unmodified onto 1.25.5: "
            "build/patches/CVE-2026-42945.patch, applied with fuzz 0 by the nginx.org "
            "packaging (build/Dockerfile, part 2). The version string stays 1.25.5, so "
            "version-based matching (CPE) still reports it. Evidence from the image "
            "itself: vex/evidence.txt (the upstream commit's example config returns the "
            "capture escaped and truncated on the original image, unchanged on ours). "
            "Attack test: test/cve_test.py."),
    },
]

vex = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "urn:echo-nginx:vex:%s" % digest.split(":")[1][:16],
    "author": "Echo home assignment build",
    "role": "image builder",
    "timestamp": now,
    "version": 1,
    "statements": statements,
}

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": now,
        "component": {"type": "container", "name": name, "version": digest,
                      "purl": image_purl, "bom-ref": image_purl},
        "properties": [{"name": "echo:note", "value":
                        "Upstream components only, identified by CPE; the full package "
                        "list is in the image's dpkg database (scanned directly)."}],
    },
    "components": [
        {"type": "application", "name": "nginx", "version": "1.25.5",
         "cpe": "cpe:2.3:a:f5:nginx:1.25.5:*:*:*:*:*:*:*",
         "purl": nginx_generic, "bom-ref": nginx_generic,
         "description": "nginx 1.25.5 + backports of CVE-2025-23419 and CVE-2026-42945 (deb %s, %s)" % (ver["nginx"], distro)},
        {"type": "library", "name": "zlib", "version": "1.4",
         "cpe": "cpe:2.3:a:zlib:zlib:1.4:*:*:*:*:*:*:*",
         "purl": "pkg:generic/zlib@1.4", "bom-ref": "pkg:generic/zlib@1.4",
         "description": "zlib 1.4 (deb zlib1g %s)" % ver["zlib1g"]},
    ],
}

for fname, doc in (("echo-nginx.openvex.json", vex), ("upstream-components.cdx.json", sbom)):
    with open(os.path.join(HERE, fname), "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("wrote vex/%s" % fname)
print("image %s  digest %s  arch %s  zlib1g %s  nginx %s" % (IMAGE, digest, arch, ver["zlib1g"], ver["nginx"]))
