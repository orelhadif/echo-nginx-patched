#!/usr/bin/env python3
"""HTTP compatibility test: does the new image behave like nginx:1.25-bookworm?

For every scenario, the SAME raw request bytes are sent to a container of each
image, started with the SAME arguments and mounts. We compare:
  * the status line,
  * every response header (name, value and order),
  * the body (exact bytes, compared by length + sha256),
  * transport errors (e.g. connection reset), if any,
  * the start-up messages of the docker-entrypoint scripts.

"Working correctly" = identical results for every scenario. The only value we
normalise is the `Date` header: it is the server clock at response time, so two
containers can never agree on it. We still require it to be present and to be a
valid RFC 1123 date in both. ETag / Last-Modified are compared exactly (they
depend on file mtimes, which our packages preserve).

Exit code: 0 if everything matches, 1 on any difference.
Python 3.9+, standard library only. Needs `docker` on PATH.
"""
import argparse
import collections
import hashlib
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
DATE_RE = re.compile(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d\d (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|"
                     r"Sep|Oct|Nov|Dec) \d{4} \d\d:\d\d:\d\d GMT$")
ENTRYPOINT_LOG_RE = re.compile(r"^(/docker-entrypoint\.sh|\d\d-[\w.-]+\.(sh|envsh)):")
INDEX_MTIME = "Tue, 16 Apr 2024 14:29:59 GMT"   # Last-Modified of the packaged index.html


# ---------------------------------------------------------------- requests --
def req(method, path, headers=(), body=b"", version="HTTP/1.1", host="localhost"):
    """Build a well-formed raw HTTP/1.x request (Connection: close)."""
    lines = ["%s %s %s" % (method, path, version)]
    if host is not None:
        lines.append("Host: " + host)
    lines += list(headers)
    if body:
        lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


# One request, sent as the same raw bytes to both images.
#   set:  which container setup it runs in (see container_args)
#   port: container port; tls: None, "tls" or "mtls" (with a client certificate)
Scenario = collections.namedtuple("Scenario", "set name port tls raw")
SETS = ["default", "custom", "njs", "templates"]


def scenarios(data):
    """Every scenario. `data` holds generated payloads."""
    two_mb = b"x" * (2 * 1024 * 1024)
    s = []

    def add(setname, name, raw, port=80, tls=None):
        s.append(Scenario(setname, name, port, tls, raw))

    # -- root / default configuration ----------------------------------------
    add("default", "GET / (root)", req("GET", "/"))
    add("default", "HEAD /", req("HEAD", "/"))
    add("default", "GET /index.html", req("GET", "/index.html"))
    add("default", "GET /50x.html", req("GET", "/50x.html"))
    add("default", "GET missing -> 404", req("GET", "/does-not-exist"))
    add("default", "conditional GET -> 304", req("GET", "/", ["If-Modified-Since: " + INDEX_MTIME]))
    add("default", "POST static -> 405", req("POST", "/index.html", body=b"a=1"))
    add("default", "HTTP/1.0 without Host", req("GET", "/", version="HTTP/1.0", host=None))
    add("default", "gzip not enabled by default", req("GET", "/", ["Accept-Encoding: gzip"]))
    # -- large bodies -------------------------------------------------------
    add("default", "large download 5MB", req("GET", "/data/big.bin"))
    add("default", "range request -> 206", req("GET", "/data/big.bin", ["Range: bytes=1000-1999"]))
    add("default", "POST 2MB > default 1m limit -> 413", req("POST", "/", body=two_mb))
    # -- malformed requests (sent as raw bytes) ----------------------------
    add("default", "malformed: HTTP/1.1 without Host", b"GET / HTTP/1.1\r\n\r\n")
    add("default", "malformed: garbage request line", b"GARBAGE\r\n\r\n")
    add("default", "malformed: header line without colon",
        b"GET / HTTP/1.1\r\nHost: localhost\r\nThis is not a header\r\n\r\n")
    add("default", "malformed: invalid Content-Length",
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: abc\r\n\r\n")
    add("default", "malformed: NUL in URI", b"GET /a%00b HTTP/1.1\r\nHost: localhost\r\n\r\n")
    add("default", "malformed: unsupported HTTP version", b"GET / HTTP/2.0\r\nHost: localhost\r\n\r\n")
    add("default", "malformed: URI too long -> 414", req("GET", "/" + "a" * 9000))
    add("default", "malformed: header too large -> 400", req("GET", "/", ["Cookie: " + "c" * 20000]))
    add("default", "malformed: TE+CL request smuggling",
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")

    # -- custom configuration (conf.d replaced) ----------------------------
    add("custom", "custom: return + add_header", req("GET", "/hello"))
    add("custom", "custom: json default_type", req("GET", "/json"))
    add("custom", "custom: rewrite -> 301", req("GET", "/old/page?x=1"))
    add("custom", "custom: regex location (PCRE2)", req("GET", "/re/12345"))
    add("custom", "custom: regex no match -> 404", req("GET", "/re/abc"))
    add("custom", "custom: try_files fallback", req("GET", "/try/nothing-here"))
    add("custom", "custom: gzip small (zlib)", req("GET", "/", ["Accept-Encoding: gzip"]))
    add("custom", "custom: gzip 2MB text (zlib)", req("GET", "/data/big.txt", ["Accept-Encoding: gzip"]))
    add("custom", "custom: upload 5MB within 10m limit", req("POST", "/upload", body=data["upload"]))
    add("custom", "custom: TLS with SNI", req("GET", "/", host="a.test"), 8443, "tls")
    add("custom", "custom: mTLS with client cert", req("GET", "/", host="a.test"), 8444, "mtls")
    add("custom", "custom: mTLS without client cert -> 400", req("GET", "/", host="a.test"), 8444, "tls")

    # -- njs dynamic module + large request body ---------------------------
    add("njs", "njs: js_content", req("GET", "/njs/hello?a=b"))
    add("njs", "njs: 5MB body hashed by njs", req("POST", "/njs/echo", body=data["upload"]))

    # -- entrypoint: envsubst templates ------------------------------------
    add("templates", "templates: envsubst rendered config", req("GET", "/"), 8081)
    return s


# -------------------------------------------------------------- containers --
def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True)


def container_args(setname, work):
    """Identical `docker run` arguments for both images, per scenario set."""
    data = ["-v", os.path.join(work, "data") + ":/usr/share/nginx/html/data:ro"]
    if setname == "default":
        return data, [80]
    if setname == "custom":
        return data + ["-v", os.path.join(FIX, "custom", "conf.d") + ":/etc/nginx/conf.d:ro",
                       "-v", os.path.join(work, "certs") + ":/etc/nginx/certs:ro"], [80, 8443, 8444]
    if setname == "njs":
        return data + ["-v", os.path.join(FIX, "njs", "nginx.conf") + ":/etc/nginx/nginx.conf:ro",
                       "-v", os.path.join(FIX, "njs") + ":/etc/nginx/njs:ro"], [80]
    if setname == "templates":
        return data + ["-e", "GREETING=shalom",
                       "-v", os.path.join(FIX, "templates") + ":/etc/nginx/templates:ro"], [80, 8081]
    raise ValueError(setname)


def start(image, setname, work):
    args, ports = container_args(setname, work)
    pub = sum((["-p", "127.0.0.1::%d" % p] for p in ports), [])
    cid = docker("run", "-d", *pub, *args, image).stdout.strip()
    mapped = {}
    for p in ports:
        hostport = docker("port", cid, "%d/tcp" % p).stdout.split("\n")[0].rsplit(":", 1)[1]
        mapped[p] = int(hostport)
    deadline = time.time() + 30
    while True:   # ready = answers HTTP on port 80
        try:
            out, _ = exchange(mapped[80], b"GET / HTTP/1.0\r\n\r\n", None, timeout=2)
            if out.startswith(b"HTTP/"):
                break
        except OSError:
            pass
        if time.time() > deadline:
            print(docker("logs", cid, check=False).stderr[-2000:])
            raise RuntimeError("%s (%s) did not become ready" % (image, setname))
        time.sleep(0.3)
    return cid, mapped


def entrypoint_log(cid):
    p = docker("logs", cid, check=False)
    return [l for l in (p.stdout + p.stderr).splitlines() if ENTRYPOINT_LOG_RE.match(l)]


# --------------------------------------------------------------- transport --
def tls_context(work, client_cert):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(os.path.join(work, "certs", "ca.crt"))
    if client_cert:
        ctx.load_cert_chain(os.path.join(work, "certs", "client.crt"),
                            os.path.join(work, "certs", "client.key"))
    return ctx


def exchange(port, raw, ctx, timeout=15, sni="a.test"):
    """Send raw bytes, read until the server closes. Returns (bytes, error)."""
    err = None
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    if ctx is not None:
        sock = ctx.wrap_socket(sock, server_hostname=sni)
    chunks = []
    try:
        try:
            sock.sendall(raw)
        except OSError as e:          # server may answer + close before the full body is sent
            err = "send:" + type(e).__name__
        while True:
            try:
                d = sock.recv(65536)
            except (ConnectionResetError, ssl.SSLError) as e:
                err = (err or "") + " recv:" + type(e).__name__
                break
            if not d:
                break
            chunks.append(d)
    finally:
        sock.close()
    return b"".join(chunks), err


def parse(resp):
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = [tuple(x.strip() for x in l.split(":", 1)) for l in lines[1:] if ":" in l]
    return lines[0], headers, body


# ----------------------------------------------------------------- compare --
def normalise(headers):
    """Replace the Date value by a validity marker; everything else verbatim."""
    out = []
    for k, v in headers:
        if k.lower() == "date":
            v = "<valid RFC1123 date>" if DATE_RE.match(v) else "<INVALID DATE %r>" % v
        out.append((k, v))
    return out


def describe(resp, err):
    status, headers, body = parse(resp)
    return {"status": status, "headers": normalise(headers),
            "body": "%d bytes sha256=%s" % (len(body), hashlib.sha256(body).hexdigest()[:16]),
            "body_preview": body[:120], "error": err}


def make_fixtures(work, orig_image):
    os.makedirs(os.path.join(work, "data"))
    rnd = random.Random(20261124)                    # deterministic payloads
    with open(os.path.join(work, "data", "big.bin"), "wb") as f:
        f.write(bytes(rnd.getrandbits(8) for _ in range(5 * 1024 * 1024)))
    with open(os.path.join(work, "data", "big.txt"), "w") as f:
        for i in range(40000):
            f.write("line %06d: the quick brown fox jumps over the lazy dog %d\n" % (i, rnd.randint(0, 9)))
    certs = os.path.join(work, "certs")
    os.makedirs(certs)
    # Test CA, server cert (a.test) and client cert, made with openssl from the
    # original image, so the host needs nothing but docker + python.
    with open(os.path.join(certs, "san.ext"), "w") as f:
        f.write("subjectAltName=DNS:a.test,DNS:b.test\n")

    def openssl(*args):
        docker("run", "--rm", "-v", certs + ":/c", "-w", "/c", "--entrypoint", "openssl", orig_image, *args)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=Compat Test CA",
            "-keyout", "ca.key", "-out", "ca.crt")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=a.test",
            "-keyout", "server.key", "-out", "server.csr")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
            "-days", "2", "-extfile", "san.ext", "-out", "server.crt")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/O=Compat Test/CN=client.test",
            "-keyout", "client.key", "-out", "client.csr")
    openssl("x509", "-req", "-in", "client.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
            "-days", "2", "-out", "client.crt")
    for d in (work, os.path.join(work, "data"), certs):
        os.chmod(d, 0o755)
    for root, _, files in os.walk(work):
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)
    with open(os.path.join(work, "data", "big.bin"), "rb") as f:
        return {"upload": f.read()}


def compare_set(setname, images, all_scenarios, ctx, work, verbose, containers):
    """Start both images in one setup, compare the start-up log and every scenario.
    Returns the list of differences."""
    print("\n== scenario set: %s" % setname)
    failures = []
    running = {}
    for label, image in images:
        cid, ports = start(image, setname, work)
        containers.append(cid)
        running[label] = (cid, ports)

    logs = {label: entrypoint_log(cid) for label, (cid, _) in running.items()}
    ok = logs["orig"] == logs["new"]
    print("  %-4s entrypoint start-up log (%d lines)" % ("ok" if ok else "DIFF", len(logs["orig"])))
    if not ok:
        failures.append("%s: entrypoint log" % setname)
        print("       orig: %s\n       new:  %s" % (logs["orig"], logs["new"]))

    for sc in all_scenarios:
        if sc.set != setname:
            continue
        res = {}
        for label, (cid, ports) in running.items():
            resp, err = exchange(ports[sc.port], sc.raw, ctx[sc.tls])
            res[label] = describe(resp, err)
        o, n = res["orig"], res["new"]
        diffs = [k for k in ("status", "headers", "body", "error") if o[k] != n[k]]
        print("  %-4s %-42s %s" % ("ok" if not diffs else "DIFF", sc.name, o["status"] or o["error"]))
        for k in ("status", "headers", "body", "error"):
            if k in diffs:
                print("       %s orig: %s\n       %s new:  %s" % (k, o[k], k, n[k]))
            elif verbose:
                print("       %s: %s" % (k, o[k]))
        if diffs:
            failures.append("%s: %s (%s)" % (setname, sc.name, ",".join(diffs)))

    for cid, _ in running.values():
        docker("stop", "-t", "2", cid, check=False)
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--orig", default="nginx:1.25-bookworm")
    ap.add_argument("--new", default="echo-nginx:1.25-bookworm-patched")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every response")
    a = ap.parse_args()

    # Docker Desktop on macOS shares /private/var/folders, so a temp dir works
    work = os.path.realpath(tempfile.mkdtemp(prefix="compat-"))
    containers, failures = [], []
    try:
        data = make_fixtures(work, a.orig)
        ctx = {"tls": tls_context(work, False), "mtls": tls_context(work, True), None: None}
        all_scenarios = scenarios(data)
        for setname in SETS:
            failures += compare_set(setname, (("orig", a.orig), ("new", a.new)),
                                    all_scenarios, ctx, work, a.verbose, containers)
    finally:
        for cid in containers:
            docker("container", "rm", "-f", cid, check=False)
        shutil.rmtree(work, ignore_errors=True)

    total = len(all_scenarios) + len(SETS)   # + one entrypoint-log check per set
    print("\nRESULT: %s" % ("PASS (%d checks, all identical)" % total if not failures
                            else "FAIL (%d of %d differ):\n  - %s" % (len(failures), total, "\n  - ".join(failures))))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
