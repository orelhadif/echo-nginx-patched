#!/usr/bin/env python3
"""Functional test of the two nginx backports: run each attack against both images.

CVE-2025-23419 - TLS 1.3 session resumption across SNI virtual servers bypasses
  ssl_verify_client. One nginx, two TLS servers on one port:
    a.test (default_server) requires a client cert from CA "A",
    b.test                  requires a client cert from CA "B".
  Attack: connect to a.test with a CA-A cert, keep the session, resume it with
  SNI b.test and NO cert. Vulnerable: b.test is served. Fixed: access_denied.
  Run in `http` (port 443) and in `stream` (port 8443): the upstream commit
  fixes both modules, in two separate functions.

CVE-2026-42945 - rewrite module: after `rewrite` with "?" in the replacement, a
  later capture ($1) in `set` is escaped into a buffer sized for the unescaped
  value (heap overrun). Config from the upstream commit message (port 8080):
    rewrite ^(.*) /new?c=1;  set $myvar $1;  return 200 "myvar=$myvar";
  Request /a%20b%26c%22d ($1 = '/a b&c"d', 8 bytes).
  Vulnerable: escaped and cut to 8 bytes ("/a%20b%2"). Fixed: '/a b&c"d'.

Controls run on both images, so a difference means the fix and nothing else:
resuming a.test -> a.test works, b.test with a CA-B cert works, and a rewrite
request without special characters returns the same on both.

The test only counts if every attack SUCCEEDS on the original image: that
proves the test can detect the bug. The client (openssl s_client, curl) is the
original image in both runs, so only the server differs.

Exit code: 0 if all checks pass, 1 otherwise. Python 3.9+, needs only docker.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

NGINX_CONF = r"""
events {}
error_log /dev/stderr info;
http {
    ssl_protocols       TLSv1.3;
    ssl_certificate     /w/server.crt;
    ssl_certificate_key /w/server.key;
    server {
        listen 443 ssl default_server;
        server_name a.test;
        ssl_client_certificate /w/caA.crt;
        ssl_verify_client on;
        location / { return 200 "served:a.test\n"; }
    }
    server {
        listen 443 ssl;
        server_name b.test;
        ssl_client_certificate /w/caB.crt;
        ssl_verify_client on;
        location / { return 200 "served:b.test\n"; }
    }
    server {                                  # CVE-2026-42945
        listen 8080;
        location / {
            rewrite ^(.*) /new?c=1;
            set $myvar $1;
            return 200 "myvar=$myvar";
        }
    }
}
stream {
    ssl_protocols       TLSv1.3;
    ssl_certificate     /w/server.crt;
    ssl_certificate_key /w/server.key;
    server {
        listen 8443 ssl default_server;
        server_name a.test;
        ssl_client_certificate /w/caA.crt;
        ssl_verify_client on;
        return "served:a.test\n";
    }
    server {
        listen 8443 ssl;
        server_name b.test;
        ssl_client_certificate /w/caB.crt;
        ssl_verify_client on;
        return "served:b.test\n";
    }
}
"""

# What every check must return on each image. Only the "attack" rows differ.
EXPECTED = {}
for mod in ("http", "stream"):
    EXPECTED.update({
        f"CVE-2025-23419 {mod} setup":     {"original": "served:a.test(new)",    "ours": "served:a.test(new)"},
        f"CVE-2025-23419 {mod} control-1": {"original": "served:a.test(reused)", "ours": "served:a.test(reused)"},
        f"CVE-2025-23419 {mod} control-2": {"original": "served:b.test(new)",    "ours": "served:b.test(new)"},
        f"CVE-2025-23419 {mod} attack":    {"original": "served:b.test(reused)", "ours": "rejected(access_denied)"},
    })
EXPECTED.update({
    "CVE-2026-42945 rewrite control": {"original": "myvar=/abc",     "ours": "myvar=/abc"},
    "CVE-2026-42945 rewrite attack":  {"original": "myvar=/a%20b%2", "ours": 'myvar=/a b&c"d'},
})
# The request path each rewrite check sends ($1 of the attack is '/a b&c"d').
REWRITE_PATHS = {"control": "/abc", "attack": "/a%20b%26c%22d"}
CERT_A = ("-cert", "/w/clientA.crt", "-key", "/w/clientA.key")
CERT_B = ("-cert", "/w/clientB.crt", "-key", "/w/clientB.key")


def docker(*args, input=None, check=True):
    return subprocess.run(["docker", *args], input=input, capture_output=True,
                          text=True, check=check)


def make_certs(client):
    """Two independent CAs, a client cert from each, and a server cert."""
    def run(*args):
        docker("exec", "-w", "/w", client, "openssl", *args)

    for ca in "AB":
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=Test CA " + ca, "-keyout", "ca%s.key" % ca, "-out", "ca%s.crt" % ca)
        run("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=client-" + ca,
            "-keyout", "client%s.key" % ca, "-out", "client%s.csr" % ca)
        run("x509", "-req", "-in", "client%s.csr" % ca, "-CA", "ca%s.crt" % ca,
            "-CAkey", "ca%s.key" % ca, "-CAcreateserial", "-days", "2", "-out", "client%s.crt" % ca)
    run("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=a.test",
        "-keyout", "server.key", "-out", "server.csr")
    run("x509", "-req", "-in", "server.csr", "-CA", "caA.crt", "-CAkey", "caA.key",
        "-CAcreateserial", "-days", "2", "-out", "server.crt", "-extfile", "san.ext")
    docker("exec", "-w", "/w", client, "chmod", "644",
           "server.key", "clientA.key", "clientB.key", "caA.key", "caB.key")


def tls_probe(client, port, sni, *extra):
    """openssl s_client -> 'served:<host>(new|reused)', 'rejected(access_denied)' or 'other'."""
    request = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % sni
    p = docker("exec", "-i", client, "timeout", "10", "openssl", "s_client", "-tls1_3",
               "-connect", "srv:%d" % port, "-servername", sni, "-ign_eof", *extra,
               input=request, check=False)
    out = p.stdout + p.stderr
    reused = "reused" if "\nReused, TLSv1.3" in "\n" + out else "new"
    served = re.search(r"served:[a-z.]+", out)
    if served:
        return "%s(%s)" % (served.group(0), reused)
    if "alert access denied" in out.lower():
        return "rejected(access_denied)"
    return "other"


def http_probe(client, path):
    p = docker("exec", client, "curl", "-s", "--path-as-is", "http://srv:8080" + path, check=False)
    return p.stdout if p.returncode == 0 else "error(curl %d)" % p.returncode


def run_image(image, net, client, work):
    """Start nginx from `image` as host "srv" and run every check.
    Returns ({check name: result}, number of 'handshake rejected' lines nginx logged)."""
    srv = docker("run", "-d", "--network", net, "--network-alias", "srv", "-v", work + ":/w:ro",
                 "-v", os.path.join(work, "nginx.conf") + ":/etc/nginx/nginx.conf:ro",
                 image).stdout.strip()
    try:
        for _ in range(40):                       # wait until nginx answers
            if tls_probe(client, 443, "a.test", *CERT_A).startswith("served"):
                break
            time.sleep(0.25)
        res = {}
        for mod, port in (("http", 443), ("stream", 8443)):
            sess = f"/tmp/{mod}.sess"
            # full handshake to a.test with a CA-A cert; save the TLS 1.3 session
            res[f"CVE-2025-23419 {mod} setup"] = tls_probe(client, port, "a.test", *CERT_A, "-sess_out", sess)
            # control: resuming on the same server works on both images
            res[f"CVE-2025-23419 {mod} control-1"] = tls_probe(client, port, "a.test", "-sess_in", sess)
            # control: b.test itself works with its own CA-B cert
            res[f"CVE-2025-23419 {mod} control-2"] = tls_probe(client, port, "b.test", *CERT_B)
            # attack: resume the a.test session on b.test, with no cert
            res[f"CVE-2025-23419 {mod} attack"] = tls_probe(client, port, "b.test", "-sess_in", sess)
        for name, path in REWRITE_PATHS.items():
            res[f"CVE-2026-42945 rewrite {name}"] = http_probe(client, path)
        logs = docker("logs", srv, check=False)
        rejected = [l for l in (logs.stdout + logs.stderr).splitlines() if "handshake rejected" in l]
        return res, len(rejected)
    finally:
        docker("rm", "-f", srv, check=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--orig", default="nginx:1.25-bookworm")
    ap.add_argument("--new", default="echo-nginx:1.25-bookworm-patched")
    a = ap.parse_args()

    work = os.path.realpath(tempfile.mkdtemp(prefix="cve-test-"))
    net = "cve-test-%d" % os.getpid()
    client = None
    fail = False
    try:
        with open(os.path.join(work, "nginx.conf"), "w") as f:
            f.write(NGINX_CONF)
        with open(os.path.join(work, "san.ext"), "w") as f:
            f.write("subjectAltName=DNS:a.test,DNS:b.test\n")
        docker("network", "create", net)
        # The client: the original image, idle, with openssl and curl.
        client = docker("run", "-d", "--network", net, "-v", work + ":/w", "--entrypoint",
                        "sleep", a.orig, "infinity").stdout.strip()
        make_certs(client)

        for label, image in (("original", a.orig), ("ours", a.new)):
            print(f"== {label}: {image}")
            res, rejected = run_image(image, net, client, work)
            for check, want_by_image in EXPECTED.items():
                want, got = want_by_image[label], res.get(check)
                ok = got == want
                fail |= not ok
                print("  %s  %-34s %r%s" % ("PASS" if ok else "FAIL", check, got,
                                            "" if ok else "  (expected %r)" % want))
            print("  nginx logged 'handshake rejected' %d time(s)" % rejected)
    finally:
        if client:
            docker("rm", "-f", client, check=False)
        docker("network", "rm", net, check=False)
        shutil.rmtree(work, ignore_errors=True)

    print("RESULT: %s" % ("PASS - every attack works on the original and is blocked by ours"
                          if not fail else "FAIL"))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
