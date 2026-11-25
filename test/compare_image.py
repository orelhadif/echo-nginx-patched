#!/usr/bin/env python3
"""Structural drop-in check: is the new image laid out like the original?

Fails (exit 1) on any difference in:
  * image config: User, WorkingDir, Entrypoint, Cmd, ExposedPorts, StopSignal,
    Env, Labels, Volumes
  * the nginx part of the filesystem: every path's type, permissions, owner and
    symlink target; for config/html/entrypoint files also the content (sha256),
    and for the served html files also the mtime (it drives ETag/Last-Modified)
  * the nginx user and group entries (/etc/passwd, /etc/group)

Only reports (does not fail on) the rest of the filesystem: our base image is a
newer Debian 12 point release, so library file names/versions differ by design.

Python 3.9+, standard library only.
"""
import argparse
import collections
import hashlib
import json
import subprocess
import sys
import tarfile

CONFIG_FIELDS = ["User", "WorkingDir", "Entrypoint", "Cmd", "ExposedPorts",
                 "StopSignal", "Env", "Labels", "Volumes"]

# Paths owned by nginx packaging / the official Dockerfile: must match exactly.
STRICT = ("etc/nginx", "usr/share/nginx", "usr/lib/nginx", "var/log/nginx",
          "var/cache/nginx", "docker-entrypoint.sh", "docker-entrypoint.d",
          "usr/sbin/nginx", "usr/sbin/nginx-debug", "usr/bin/njs",
          "etc/init.d/nginx", "etc/init.d/nginx-debug", "etc/default/nginx",
          "etc/default/nginx-debug", "etc/logrotate.d/nginx",
          "usr/lib/systemd/system/nginx.service",
          "usr/lib/systemd/system/nginx-debug.service")
# Compiled from source by us: content is expected to differ, metadata is not.
BINARIES = ("usr/sbin/nginx", "usr/sbin/nginx-debug", "usr/bin/njs",
            "usr/lib/nginx/modules/")
MTIME_CHECKED = ("usr/share/nginx/html/",)
# Differences we expect and explain in the README.
EXPECTED_ONLY_IN_ORIG = {"etc/apt/keyrings/nginx-archive-keyring.gpg"}

TYPES = {tarfile.REGTYPE: "file", tarfile.AREGTYPE: "file", tarfile.DIRTYPE: "dir",
         tarfile.SYMTYPE: "symlink", tarfile.LNKTYPE: "hardlink",
         tarfile.CHRTYPE: "chardev", tarfile.BLKTYPE: "blockdev", tarfile.FIFOTYPE: "fifo"}


def docker(*args):
    return subprocess.run(["docker", *args], check=True, capture_output=True,
                          text=True).stdout


def is_strict(path):
    return any(path == p or path.startswith(p + "/") for p in STRICT)


def is_binary(path):
    return any(path == b or (b.endswith("/") and path.startswith(b)) for b in BINARIES)


def snapshot(image):
    """Stream `docker export` and record metadata for every path."""
    cid = docker("create", image).strip()
    entries, users = {}, {}
    try:
        proc = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE)
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            for ti in tar:
                path = ti.name.lstrip("./").rstrip("/")
                if not path:
                    continue
                e = {"type": TYPES.get(ti.type, ti.type), "mode": oct(ti.mode & 0o7777),
                     "owner": "%d:%d" % (ti.uid, ti.gid)}
                if ti.issym() or ti.islnk():
                    e["target"] = ti.linkname
                if ti.isfile() and (is_strict(path) or path in ("etc/passwd", "etc/group")):
                    data = tar.extractfile(ti).read()
                    e["sha256"] = hashlib.sha256(data).hexdigest()
                    e["mtime"] = int(ti.mtime)
                    if path in ("etc/passwd", "etc/group"):
                        users[path] = [l for l in data.decode().splitlines()
                                       if l.startswith("nginx:")]
                entries[path] = e
        proc.wait()
    finally:
        subprocess.run(["docker", "container", "rm", cid], capture_output=True)
    return entries, users


def check_config(orig, new, failures):
    print("== Image config (docker image inspect)")
    cfg = {img: json.loads(docker("image", "inspect", img))[0] for img in (orig, new)}
    for field in CONFIG_FIELDS:
        o, n = cfg[orig]["Config"].get(field), cfg[new]["Config"].get(field)
        print("  %-4s %-12s %s" % ("ok" if o == n else "DIFF", field, json.dumps(o)))
        if o != n:
            print("       %-12s %s  <- new" % ("", json.dumps(n)))
            failures.append("config %s" % field)
    for img in (orig, new):
        print("  size %-40s %6.1f MB (%s)" % (img, cfg[img]["Size"] / 1e6,
              cfg[img]["Os"] + "/" + cfg[img]["Architecture"]))


def check_nginx_files(orig_files, new_files, failures):
    """The nginx paths must match exactly (content too, except compiled binaries)."""
    print("\n== Filesystem: nginx paths (docker export of both images)")
    strict_paths = sorted(p for p in set(orig_files) | set(new_files) if is_strict(p))
    for p in strict_paths:
        o, n = orig_files.get(p), new_files.get(p)
        if o is None or n is None:
            where = "new" if o is None else "orig"
            failures.append("%s only in %s" % (p, where))
            print("  DIFF %s: only in %s" % (p, where))
            continue
        keys = ["type", "mode", "owner", "target"]
        if not is_binary(p):
            keys.append("sha256")
        if p.startswith(MTIME_CHECKED):
            keys.append("mtime")
        bad = [k for k in keys if o.get(k) != n.get(k)]
        if bad:
            failures.append("%s (%s)" % (p, ",".join(bad)))
            print("  DIFF %s: %s" % (p, "; ".join("%s %s -> %s" % (k, o.get(k), n.get(k)) for k in bad)))
    print("  %d nginx paths compared (type/mode/owner/link; content for non-binaries;"
          " mtime for html)" % len(strict_paths))
    binaries = [p for p in strict_paths if is_binary(p) and orig_files.get(p, {}).get("type") == "file"]
    rebuilt = [p for p in binaries if orig_files[p].get("sha256") != new_files.get(p, {}).get("sha256")]
    print("  %d compiled binaries differ in content, as expected (rebuilt from source)" % len(rebuilt))


def check_nginx_user(orig_users, new_users, failures):
    print("\n== nginx user/group")
    for f in ("etc/passwd", "etc/group"):
        ok = orig_users.get(f) == new_users.get(f)
        print("  %-4s %-10s %s" % ("ok" if ok else "DIFF", f, orig_users.get(f)))
        if not ok:
            failures.append("%s nginx entry" % f)


def check_packages(orig, new, failures):
    """Every package of the original must be installed (versions differ by design)."""
    print("\n== Installed Debian packages (names; versions differ by design)")
    pkgs = {img: set(docker("run", "--rm", "--entrypoint", "dpkg-query", img, "-W",
                            "-f=${Package}\n").split()) for img in (orig, new)}
    missing, extra = sorted(pkgs[orig] - pkgs[new]), sorted(pkgs[new] - pkgs[orig])
    print("  %-4s orig %d packages, new %d" % ("ok" if not missing else "DIFF", len(pkgs[orig]), len(pkgs[new])))
    if missing:
        print("  missing in new: %s" % ", ".join(missing))
        failures.append("packages missing in new: %s" % ", ".join(missing))
    if extra:
        print("  extra in new (report only): %s" % ", ".join(extra))


def report_rest(orig_files, new_files):
    """Report only: the base is a different Debian 12 point release."""
    print("\n== Rest of the filesystem (report only: different Debian 12 point release)")
    only_orig = sorted(set(orig_files) - set(new_files) - EXPECTED_ONLY_IN_ORIG)
    only_new = sorted(set(new_files) - set(orig_files))
    print("  paths: orig %d, new %d, common %d" % (len(orig_files), len(new_files),
                                                  len(set(orig_files) & set(new_files))))
    for label, paths in (("only in orig", only_orig), ("only in new", only_new)):
        groups = collections.Counter("/".join(p.split("/")[:3]) for p in paths)
        print("  %s: %d paths, top dirs: %s" % (label, len(paths), ", ".join(
            "%s(%d)" % kv for kv in groups.most_common(6))))
    for p in sorted(EXPECTED_ONLY_IN_ORIG):
        expected = p in orig_files and p not in new_files
        print("  %s: %s" % (p, "only in orig (expected: nginx.org apt key, unused by us)"
                            if expected else "present in both"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--orig", default="nginx:1.25-bookworm")
    ap.add_argument("--new", default="echo-nginx:1.25-bookworm-patched")
    a = ap.parse_args()
    failures = []

    check_config(a.orig, a.new, failures)
    (orig_files, orig_users), (new_files, new_users) = snapshot(a.orig), snapshot(a.new)
    check_nginx_files(orig_files, new_files, failures)
    check_nginx_user(orig_users, new_users, failures)
    check_packages(a.orig, a.new, failures)
    report_rest(orig_files, new_files)

    print("\nRESULT: %s" % ("PASS" if not failures else
                            "FAIL (%d): %s" % (len(failures), "; ".join(failures[:10]))))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
