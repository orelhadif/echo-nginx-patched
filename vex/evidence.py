#!/usr/bin/env python3
"""Evidence behind the VEX statements, collected from the IMAGES themselves (not
from our build logs), for the original and the patched image side by side.

  CVE-2026-27171 (zlib):  which zlib1g the image ships, which libz the running
                          nginx actually maps, and how crc32_combine() behaves on
                          a negative length (1.2.13: never returns; 1.4: returns 0).
  CVE-2025-23419 (nginx): the fix makes nginx call SSL_SESSION_get0_hostname();
                          the vulnerable binaries never reference it.
  CVE-2026-42945 (nginx): the upstream commit's own example config; the
                          vulnerable binary returns $1 escaped and cut short.
The full attacks for both nginx CVEs are in test/cve_test.py.

Usage: python3 vex/evidence.py [ORIG_IMAGE] [NEW_IMAGE] > vex/evidence.txt
Needs only docker (and out/ from the build, for our zlib1g-dev).
"""
import glob
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.realpath(os.path.join(HERE, "..", "out"))
ORIG = sys.argv[1] if len(sys.argv) > 1 else "nginx:1.25-bookworm"
NEW = sys.argv[2] if len(sys.argv) > 2 else "echo-nginx:1.25-bookworm-patched"

# Compiled inside each image against that image's own zlib headers.
PROBE = r"""#include <stdio.h>
#include <zlib.h>
int main(void) {
  printf("zlibVersion() = %s\n", zlibVersion());
  fflush(stdout);
  uLong r = crc32_combine(0x12345678UL, 0x9abcdef0UL, (z_off_t)-1);
  printf("crc32_combine(len2 = -1) returned 0x%lx\n", r);
  return 0;
}
"""
REWRITE_CONF = r"""server {
    listen 8080;
    location / { rewrite ^(.*) /new?c=1; set $myvar $1; return 200 "myvar=$myvar"; }
}
"""


def docker(*args, stdin=None):
    """Run a docker command; return (output, exit code)."""
    p = subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True)
    return (p.stdout + p.stderr).strip(), p.returncode


def run_in(container, *cmd, stdin=None):
    """Run a command inside a running container; return its output."""
    return docker("exec", "-i", container, *cmd, stdin=stdin)[0]


def main():
    conf = os.path.join(OUT, "evidence-rewrite.conf")
    with open(conf, "w") as f:
        f.write(REWRITE_CONF)
    try:
        for img in (ORIG, NEW):
            print("################ %s" % img)
            print("image id: %s" % docker("image", "inspect", img, "--format", "{{.Id}}")[0])
            cid, _ = docker("run", "-d", "-v", OUT + ":/debs:ro",
                            "-v", conf + ":/etc/nginx/conf.d/zz-evidence.conf:ro", img)
            try:
                time.sleep(1.5)
                print(run_in(cid, "nginx", "-v"))
                print("== CVE-2026-27171: zlib1g package in the image")
                print(run_in(cid, "dpkg-query", "-W", "-f=${Package} ${Version}\n", "zlib1g"))
                print("== CVE-2026-27171: libz mapped into the running nginx master (PID 1)")
                maps = run_in(cid, "cat", "/proc/1/maps")
                print("\n".join(sorted({l.split()[-1] for l in maps.splitlines() if "libz" in l})))

                print("== CVE-2025-23419: SSL_SESSION_get0_hostname in the nginx binaries")
                for b in ("/usr/sbin/nginx", "/usr/sbin/nginx-debug"):
                    print("%s: %s occurrence(s)" % (b, run_in(cid, "grep", "-c", "SSL_SESSION_get0_hostname", b)))

                print("== CVE-2026-42945: rewrite ^(.*) /new?c=1; set $myvar $1;  GET /a%20b%26c%22d")
                print("expected $1 = '/a b&c\"d'; response: %r" % run_in(cid,
                    "curl", "-s", "--path-as-is", "http://127.0.0.1:8080/a%20b%26c%22d"))

                print("== CVE-2026-27171: behaviour probe (compiled against this image's zlib)")
                dev = "zlib1g-dev"
                if img == NEW:  # our zlib1g-dev, from the build output
                    arch = run_in(cid, "dpkg", "--print-architecture")
                    dev = "/debs/" + os.path.basename(glob.glob(os.path.join(OUT, "zlib1g-dev_*_%s.deb" % arch))[0])
                run_in(cid, "apt-get", "update", "-qq")
                run_in(cid, "apt-get", "install", "-qq", "-y", "--no-install-recommends", "gcc", "libc6-dev", dev)
                run_in(cid, "tee", "/tmp/p.c", stdin=PROBE)
                run_in(cid, "gcc", "-O0", "-o", "/tmp/p", "/tmp/p.c", "-lz")
                out, rc = docker("exec", cid, "timeout", "10", "/tmp/p")
                print(out)
                print({124: "probe: still running after 10s -> killed (infinite loop, VULNERABLE)",
                       0: "probe: returned immediately (FIXED)"}.get(rc, "probe: exit code %d" % rc))
            finally:
                docker("rm", "-f", cid)
            print()
    finally:
        os.remove(conf)


if __name__ == "__main__":
    main()
