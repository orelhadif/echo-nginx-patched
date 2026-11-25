# echo-nginx: a patched drop-in replacement for `nginx:1.25-bookworm`

This repository builds a drop-in replacement for the official `nginx:1.25-bookworm`
image (nginx 1.25.5 on Debian 12). In the replacement, three CVEs are eliminated by
rebuilding the affected components from source:

| CVE | Component | Severity | How it was fixed |
|---|---|---|---|
| **CVE-2026-27171** | zlib (`zlib1g`), linked into nginx | Medium (CVSS 3.x 5.5, NVD) | **Dependency version bump**: zlib 1.2.13 → **1.4**, built from the upstream release |
| **CVE-2026-42945** ("NGINX Rift") | nginx 1.25.5, `rewrite` module | **High** (CVSS 3.1 8.1 / 4.0 9.2, F5); EPSS 99th percentile, public exploit | **Backport** of upstream commit [`524977e`](https://github.com/nginx/nginx/commit/524977e7c534e87e5b55739fa74601c9f1102686) onto 1.25.5, unmodified |
| **CVE-2025-23419** | nginx 1.25.5, TLS / SNI | Medium (CVSS 3.1 4.3 / 4.0 5.3, F5) | **Backport** of upstream commit [`13935cf`](https://github.com/nginx/nginx/commit/13935cf9fdc3c8d8278c70716417d3b71c36140e) onto 1.25.5, unmodified |

Every package that changes is built from source into a `.deb` inside a clean
`debian:bookworm-slim` container. The image installs those `.deb` files exactly the way
the official Dockerfile installs nginx.org's packages. One command builds and proves it:

```bash
make test      # build the .debs -> build the image -> structure test -> HTTP compat test -> CVE attack test
```

---

## Contents

1. [Quick start](#1-quick-start)
2. [Repository layout](#2-repository-layout)
3. [Baseline and choice of the CVEs](#3-baseline-and-choice-of-the-cves)
4. [Fix 1: CVE-2026-27171 (zlib version bump)](#4-fix-1-cve-2026-27171-zlib-version-bump)
5. [Fixes 2 and 3: nginx backports](#5-fixes-2-and-3-nginx-backports)
6. [Build artifact](#6-build-artifact)
7. [Drop-in compatibility: how it was proven](#7-drop-in-compatibility-how-it-was-proven)
8. [Rescan, evidence and VEX (bonus)](#8-rescan-evidence-and-vex-bonus)
9. [Residual risks](#9-residual-risks)
10. [Surprises and what we would do differently](#10-surprises-and-what-we-would-do-differently)
11. [How AI was used](#11-how-ai-was-used)
12. [Verified vs. still open](#12-verified-vs-still-open)

---

## 1. Quick start

**Requirements:** Docker with BuildKit (Docker Desktop or Engine ≥ 23), GNU make and
Python ≥ 3.9 (standard library only). For `make scan` you also need `trivy` and `grype`.
Everything else runs inside containers.

| Command | What it does |
|---|---|
| `make test` | Builds the `.deb` files ([build/Dockerfile](build/Dockerfile) → `out/`), builds the image `echo-nginx:1.25-bookworm-patched` ([Containerfile](Containerfile)), then runs the three tests in [test/](test/) against the original image. Exits non-zero on any failure |
| `make scan` | Bonus, after `make test`. Collects evidence from both images, writes the VEX for the **current** image digest, and rescans both images with Trivy and Grype, with and without the VEX |
| `make clean` | Removes `out/` |

You can override the image names: `make test ORIG=nginx:1.25-bookworm IMAGE=my/tag`.

## 2. Repository layout

```
build/
  Dockerfile                the whole build: pinned sources (sha256), zlib, nginx -> out/*.deb
  patches/                  the two nginx backports, each with a provenance header
  zlib/                     Debian metadata of our zlib1g / zlib1g-dev packages
Containerfile               the final image (mirrors the official Dockerfile)
docker-entrypoint/          the official entrypoint scripts, byte-identical
test/
  compare_image.py          structure: config, filesystem, user, packages vs. the original
  compat_test.py            behaviour: 40 HTTP checks, same bytes to both images
  cve_test.py               the attacks for both nginx CVEs: original vulnerable, ours not
  fixtures/                 custom config, njs script, envsubst template
Makefile                    make test / make scan / make clean
scan/
  baseline/                 the original image: identity (image.txt) + Trivy/Grype reports
  run.py, diff_scans.py     rescan both images, diff vs. baseline, scans with/without VEX
vex/
  evidence.py               evidence from both images -> evidence.txt
  make_vex.py               the targeted VEX + the upstream-components SBOM
```

The only shell scripts are the official `docker-entrypoint/` scripts, which must stay
byte-identical to the original image's.

## 3. Baseline and choice of the CVEs

**What was scanned.** The baseline is pinned in [scan/baseline/image.txt](scan/baseline/image.txt):

| Field | Value |
|---|---|
| Image | `nginx:1.25-bookworm` |
| Index digest | `sha256:a484819e…` |
| Platform | linux/arm64 (manifest `557b2c07…`); the amd64 manifest is `e688fed0…` |
| Built | 2024-05 from `nginxinc/docker-nginx@9abe4ae` |
| Scanners | Trivy 0.76.2 and Grype 0.122.1 |

Scanner databases change daily, so `make scan` rescans the original image **with the
same DB** as the new one before comparing. Last run (2026-11-25):

| | Trivy | Grype |
|---|---|---|
| Findings (CVE × package) | 956 | 889 |
| Unique CVEs | 603 | 537 |

To choose the CVEs, both reports were merged per CVE and package and sorted by the
package's role in the image (linked by nginx, a module dependency, the curl stack, or the
base OS), by fix status and by severity. The two scanners disagree on severity in about
400 rows, which is why the severities in this README name their source. Upstream nginx
CVEs are invisible to this Debian-based matching (see below), so they were listed with a
CPE scan of nginx 1.25.5.

**Why these three.**

- **CVE-2026-27171 (zlib, bump).**
  - zlib is on nginx's real runtime path: `libz.so.1` is a `NEEDED` entry of `/usr/sbin/nginx` and is used for gzip.
  - Debian has **no fixed version**: the status is "affected" and Grype reports it as wont-fix. `apt-get upgrade` cannot fix it.
  - A newer upstream release, zlib **1.4**, contains the fix (`if (len2 < 0) return 0;`). A version bump is the natural method.
  - We rejected zlib **1.3.2**. CPE data marks it affected by CVE-2026-85091, which 1.4 is not.
- **CVE-2026-42945 (nginx, backport) - the High one.**
  - It has the highest exploitation probability of every open nginx CVE: EPSS 69% (99th
    percentile) at selection time, with a public exploit.
  - It is in `ngx_http_rewrite_module`, which is built into every nginx and widely used.
  - Upstream fixed it only in 1.30.1. A backport keeps 1.25.5 and the drop-in promise.
  - The fix is **one line**, and the commit applies to 1.25.5 with `--fuzz=0`.
  - We considered CVE-2026-27654 (High, `dav` module) too. It also backports cleanly, but
    needs a rarer config (`dav_methods COPY/MOVE`), has a lower EPSS and a 39-line fix.
- **CVE-2025-23419 (nginx, backport).**
  - The CVE is in nginx itself, in the main binary, in both `http` and `stream`.
  - Upstream fixed it only in 1.27.4 and 1.26.3. A backport keeps 1.25.5.
  - The upstream fix is one commit touching 2 files, applied **unmodified**.

**No scanner reports either nginx CVE on the original image.** Scanners match Debian
packages against the Debian security tracker, and nginx.org's `1.25.5-1~bookworm` package
is not in that tracker. This blind spot is why VEX and CPE matching matter here (§8).

## 4. Fix 1: CVE-2026-27171 (zlib version bump)

**The bug.** `crc32_combine()` and `crc32_combine64()` use `x2nmodp()`. When `len2` is
negative, the loop shifts a negative number to the right, the value never reaches 0, and
the call never returns. Any caller that passes an attacker-influenced length can be made
to hang (DoS). zlib 1.4 returns 0 for `len2 < 0`.

**What [build/Dockerfile](build/Dockerfile) part 1 does:**

1. **Download and verify.** `ADD --checksum=sha256:…` downloads `zlib-1.4.tar.gz`;
   BuildKit fails the build if the sha256 differs from the pin.
2. **Check that the fix is in the source** (step 1a). It greps `crc32.c` for
   `if (len2 < 0)` and fails if the check is missing.
3. **Build with Debian's hardening flags** (`dpkg-buildflags`, step 1b).
   - zlib's own `configure` ignores `CPPFLAGS`, so `_FORTIFY_SOURCE` would be silently
     dropped. We fold `CPPFLAGS` into `CFLAGS`, and `LDFLAGS` into `LDSHARED`.
   - The SONAME stays `libz.so.1` and the symbol-version script stays `zlib.map`.
   - The libraries go to Debian's paths: `/lib/<triplet>` and `/usr/lib/<triplet>`.
   - `make test` runs zlib's own tests.
4. **ABI check** (step 1c). It compares every exported, versioned symbol of Debian's
   `libz.so.1.2.13` with those of the new library and fails if any symbol is missing
   (all 102 are present; 9 are added). This is what makes the bump safe for every binary
   already linked against `libz.so.1`, nginx included.
5. **Package as `zlib1g` and `zlib1g-dev`** (step 1d) with version `1:1.4-0+echo1`.
   The metadata is in [build/zlib/](build/zlib/):
   - the epoch `1:` makes it sort above Debian's `1:1.2.13.dfsg-1`;
   - the same names, `Source: zlib`, `Provides`, `Breaks` and `Multi-Arch: same` as
     Debian's, so they replace Debian's packages 1:1 and scanners keep seeing zlib;
   - `Depends: libc6 (>= …)`, the newest glibc symbol version the library uses;
   - a `shlibs` file, so packages built against it depend on it;
   - an `ldconfig` trigger.
6. **Install it into the builder** (step 1e) before nginx's build dependencies. The step
   fails unless the installed `zlib1g-dev` is ours, so nginx is compiled against 1.4.

The image installs this `zlib1g` in place of Debian's. Nothing is relinked, because nginx
loads `libz.so.1` at runtime. See [vex/evidence.txt](vex/evidence.txt): the running nginx
maps `libz.so.1.4`.

## 5. Fixes 2 and 3: nginx backports

### The bugs and the patches

**CVE-2026-42945, `rewrite` module.** A `rewrite` whose replacement contains `?` sets an
internal flag, `is_args`: "what follows is a query string, escape it". The flag was never
cleared. A capture used later in `set` or `if` (`$1`) was therefore escaped, but its
buffer had been allocated for the **unescaped** length. Escaping makes the value longer,
so it is written past the buffer: a heap overrun, crashing the worker or worse. The
upstream fix is one line in `ngx_http_script_regex_end_code()`: `e->is_args = 0;`.
Patch: [build/patches/CVE-2026-42945.patch](build/patches/CVE-2026-42945.patch).

**CVE-2025-23419, TLS / SNI.** With TLS 1.3, OpenSSL resumes sessions in the *default*
SSL context before the SNI callback runs. Suppose two virtual servers on one port require
client certificates from different CAs (`ssl_verify_client on`). A client can get a
session on one, resume it with the SNI name of the other, and skip that server's
client-certificate check. The fix: when verification is enabled, reject a resumed
handshake if the session's original host name (`SSL_SESSION_get0_hostname`) differs from
the current SNI name. It is applied in `http` and in `stream`.
Patch: [build/patches/CVE-2025-23419.patch](build/patches/CVE-2025-23419.patch).

Each patch starts with a provenance header (upstream commit, release, advisory, backport
notes), followed by the **unmodified** `git format-patch` of the upstream commit. Both
apply to 1.25.5 with `--fuzz=0`, so a reviewer can diff them against upstream.

### How the package is built: nginx.org's own recipe plus our patches

[build/Dockerfile](build/Dockerfile) part 2 does not package nginx by hand. It runs
**pkg-oss**, nginx.org's packaging repository, at tag `1.25.5-1`. That is the same recipe
that produced the original `nginx_1.25.5-1~bookworm` packages. Its `debian/rules`,
`control`, maintainer scripts, configure arguments and compiler flags are used unchanged.
We add only three things:

1. **Our patches** (step 2a). They are copied to `contrib/src/nginx/`. pkg-oss puts every
   `*.patch` there into `debian/patches/series`, and `dpkg-source` (quilt format, fuzz 0)
   applies them before compiling. The build log shows `applying CVE-2025-23419.patch` and
   `applying CVE-2026-42945.patch`.
2. **A changelog entry** made with `dch` (step 2c). It raises the version to `…+echo1`
   and says what changed and why.
3. **Our name as `Maintainer`** (`PACKAGE_VENDOR`). nginx.org did not build these
   packages, so they must not claim it did.

Details:

- **Sources** are pinned by sha256 with `ADD --checksum`: pkg-oss, nginx 1.25.5, njs
  0.8.4. pkg-oss also checks nginx against its own SHA512SUMS. pkg-oss pins njs to an
  `hg.nginx.org` archive, but that server is gone, so we pin the GitHub tag archive.
  QuickJS is fetched by pkg-oss with git and checked against its pinned commit hash.
- **Source trees** come from `make rules-base rules-module-{geoip,image-filter,njs,xslt}`
  (step 2b). pkg-oss is unpacked at the same path as nginx.org's build
  (`/data/builder/debuild/nginx-1.25.5`), so `-ffile-prefix-map` gives the same
  `nginx -V`. `MODULE_RELEASE_njs=3` matches the original `nginx-module-njs …-3~bookworm`.
- **Build** with `dpkg-buildpackage -b` (step 2c). debhelper builds `nginx` and
  `nginx-debug` and both module variants, strips them, fixes permissions, and writes
  `md5sums`, `conffiles` and `shlibs` dependencies. `nginx` now depends on
  `zlib1g (>= 1:1.4-0+echo1)`.
- **Build-time evidence** (step 2d). The build fails unless both patches are in the
  series **and** `nm -D` shows that `nginx` and `nginx-debug` import
  `SSL_SESSION_get0_hostname`, which only the CVE-2025-23419 fix calls.

**Why the four modules are rebuilt too.** The original image ships `nginx-module-geoip`,
`-image-filter`, `-njs` and `-xslt`. Leaving them out would break every config with a
`load_module` line, so the image would not be a drop-in. The original module packages
can't be reused: they depend on `nginx (= 1.25.5-1~bookworm)` exactly, and a module is
built against one exact nginx binary.

`nginx -V` of the two images is identical except for the compiler and OpenSSL version
lines: our base is a newer Debian 12 point release.

### Behavioural proof: [test/cve_test.py](test/cve_test.py)

The test runs each attack against **both** images. It only counts if the attack succeeds
on the original: that proves the test can detect the bug. The client (`openssl s_client`,
`curl`) is the original image in both runs, so only the server differs.

| Check | Original | Ours |
|---|---|---|
| **CVE-2026-42945**, the upstream commit's config: `rewrite ^(.*) /new?c=1; set $myvar $1;`, request `/a%20b%26c%22d` (`$1` = `/a b&c"d`, 8 bytes) | `myvar=/a%20b%2`: escaped and cut to 8 bytes, i.e. written past its buffer | `myvar=/a b&c"d` |
| CVE-2026-42945 control: request `/abc` | `myvar=/abc` | `myvar=/abc` |
| **CVE-2025-23419**: TLS 1.3 session from `a.test` (CA-A cert) resumed with SNI `b.test` (requires CA B), **no** cert, in `http` and in `stream` | `b.test` served | rejected, `access_denied`; nginx logs `handshake rejected` |
| CVE-2025-23419 controls: resume `a.test` → `a.test`; `b.test` with a CA-B cert | served | served |

## 6. Build artifact

**One reproducible command:** `make test`. Its first step runs
[build/Dockerfile](build/Dockerfile):

```
debian:bookworm-slim@sha256:e67eeead…  (pinned)
  ADD --checksum=sha256:…  zlib 1.4, nginx 1.25.5, pkg-oss 1.25.5-1, njs 0.8.4
  part 1: zlib  -> fix check, build, make test, ABI check -> out/zlib1g*.deb
          dpkg -i our zlib1g-dev; apt-get install debhelper, quilt, devscripts, -dev libraries
  part 2: nginx -> pkg-oss + our 2 patches, dch +echo1, dpkg-buildpackage, evidence
          -> out/nginx_*.deb, out/nginx-module-*.deb
FROM scratch AS export   -> copied to ./out by BuildKit (--output type=local)
```

Artifacts (arm64), with their sha256 values recorded in `out/SHA256SUMS`:

| Package | Version | Size |
|---|---|---|
| `zlib1g` | `1:1.4-0+echo1` | 45 KB |
| `zlib1g-dev` | `1:1.4-0+echo1` | 172 KB |
| `nginx` | `1.25.5-1~bookworm+echo1` | 942 KB |
| `nginx-module-njs` | `1.25.5+0.8.4-3~bookworm+echo1` | 839 KB |
| `nginx-module-{geoip,image-filter,xslt}` | `1.25.5-1~bookworm+echo1` | 81–85 KB each |

**Pins.** Every upstream input is pinned in [build/Dockerfile](build/Dockerfile): the base
image by digest and each source tarball by sha256 (`ADD --checksum`). A changed input
fails the build.

**The image.** [Containerfile](Containerfile) is the official Dockerfile, step by step.
- It keeps the same `LABEL`, the same `ENV` (`NGINX_VERSION`, `NJS_VERSION`, …), the same
  `nginx` user and group (uid and gid 101), and the same entrypoint scripts.
- It installs the same extra packages, `gettext-base` and `curl`, plus `ca-certificates`.
  The original installs `ca-certificates` too and never removes it.
- It sets up the same log symlinks and keeps the same `EXPOSE 80`, `STOPSIGNAL SIGQUIT`
  and `CMD`.
- The only intended difference is where the packages come from: the `.deb` files are
  bind-mounted for the one `RUN` step, so they never end up in a layer.

**Image size** (arm64, `docker image inspect`): original **275.2 MB**, new **274.8 MB**.

## 7. Drop-in compatibility: how it was proven

*Drop-in* means a user changes only the image name: same config paths, same user,
same ports, same entrypoint behaviour and same responses. Two automated tests check this.
Each exits non-zero on any difference.

### Structure: [test/compare_image.py](test/compare_image.py)

| What | How | Result |
|---|---|---|
| `User`, `WorkingDir`, `Entrypoint`, `Cmd`, `ExposedPorts`, `StopSignal`, `Env`, `Labels`, `Volumes` | `docker image inspect` on both images, compared field by field | identical |
| nginx part of the filesystem (47 paths: `/etc/nginx`, `/usr/share/nginx`, modules, logs, cache, entrypoint, init and systemd files) | `docker export` of both images, streamed through `tarfile`. Compares type, mode, owner and symlink target; sha256 for every non-binary file; mtime for served HTML | identical |
| Compiled binaries (15) | Same metadata. Content differs, as expected, since they were rebuilt | as expected |
| `nginx` user and group | Their lines in `/etc/passwd` and `/etc/group` | identical (101:101, `/nonexistent`, `/bin/false`) |
| Installed packages | `dpkg-query` package names | 149 = 149, none missing |
| Rest of the filesystem | Report only. Our base is Debian 12.15 vs. 12.5, so library file names differ | expected; see below |

The only file that exists only in the original is `/etc/apt/keyrings/nginx-archive-keyring.gpg`.
It is the nginx.org apt key, which we don't use, and leaving it out is intentional.

**This test found two real bugs in earlier builds:**
1. Module `.so` files had mode `0755` instead of `0644`. Our first nginx build packaged
   the files by hand and missed what `dh_fixperms` does. This is one reason the final
   build uses nginx.org's own recipe (§5), where debhelper does it.
2. `ca-certificates` was missing. A config that verifies HTTPS upstreams against
   `/etc/ssl/certs` would have broken.

### Behaviour: [test/compat_test.py](test/compat_test.py)

Both images are started with the same `docker run` arguments and receive **the same raw
bytes** over a plain socket. A socket can send malformed requests that HTTP libraries
refuse to send. For each request the test compares the status line, every header (names,
values and order), the body (length and sha256) and any transport error. It also compares
the entrypoint log lines.

The test makes 40 checks in 4 container setups:

| Area | Checks |
|---|---|
| **Root and defaults** | `GET /`, `HEAD`, `/index.html`, `/50x.html`, 404, 304 (`If-Modified-Since`), 405, HTTP/1.0, gzip off by default |
| **Custom config** (`test/fixtures/custom`) | `return` with `add_header`, JSON, `rewrite` 301, PCRE2 regex locations, `try_files`, gzip of small and 2 MB bodies (zlib 1.4 output is byte-identical), TLS with SNI, mTLS with and without a client certificate |
| **Large bodies** | 5 MB download, `Range` → 206, 2 MB `POST` over `client_max_body_size` → 413, 5 MB upload → 201, 5 MB body hashed by njs |
| **Malformed requests** | no `Host`, garbage request line, header without a colon, invalid `Content-Length`, NUL in the URI, `HTTP/2.0` → 505, URI too long → 414, header too large, `Transfer-Encoding` with `Content-Length` (smuggling shape) |
| **Startup** | entrypoint logs for each setup; envsubst template (`GREETING=shalom` rendered on port 8081) |

The certificates are generated with `openssl` from the original image. The payloads come
from a fixed random seed, so every run sends the same bytes.

**Normalization: only `Date`.** It is the time of the response, so two containers can
never agree on it. The test first checks that it is present and is a valid HTTP date; only
then is the value ignored. `ETag` and `Last-Modified` are **compared exactly** and match,
because our packaging keeps the tarball mtimes of the HTML files.

**Negative control.** We built an image whose `index.html` has one extra byte. The test
exited 1 and reported `Content-Length`, `ETag` and body differences. The test can fail,
so a PASS means something.

**Result:** `make test` exits 0. Structure: `PASS`. Compat: `PASS (40 checks, all
identical)`. CVE test: `PASS`, every attack works on the original and is blocked by ours
(§5).

## 8. Rescan, evidence and VEX (bonus)

### Rescan vs. baseline ([scan/diff-vs-baseline.txt](scan/diff-vs-baseline.txt))

Both images scanned with the same scanner versions and the same DB:

| | Original | New | Disappeared | Appeared |
|---|---|---|---|---|
| Trivy | 956 | **585** | 373 | 2 |
| Grype | 889 | **527** | 362 | 0 |

**Most of this drop comes from the newer Debian 12.15 base, not from our fixes.**
The biggest drops are in openssl, expat, gnutls, curl and libxml2. Our three CVEs:

- **CVE-2026-27171** is **still reported** on `zlib1g 1:1.4-0+echo1`, by both scanners.
  Both match the package to Debian's source package `zlib`, and Debian lists no fixed
  version, so every version is flagged. The finding comes from version matching, not from
  the code.
- **CVE-2026-42945 and CVE-2025-23419** are **not reported on either image**, for the
  blind spot described in §3.
- **The 2 new Trivy findings** are LOW nginx CVEs: CVE-2009-4487 and CVE-2013-0337. We
  tested it: Trivy skips packages whose `Maintainer` is nginx.org's packaging team, as
  third-party packages. Our package has a different maintainer, so Trivy now evaluates it.
  The same two issues exist in the original; they were simply not looked at.

### Evidence the fixes are in the build ([vex/evidence.py](vex/evidence.py) → [vex/evidence.txt](vex/evidence.txt))

The evidence is collected from **the images themselves**, not from build logs:

| Check | Original | New |
|---|---|---|
| `zlib1g` package | `1:1.2.13.dfsg-1` | `1:1.4-0+echo1` |
| libz mapped by the running nginx (`/proc/1/maps`) | `libz.so.1.2.13` | `libz.so.1.4` |
| `crc32_combine(…, len2 = -1)`, compiled in the image against its own zlib | never returns (killed after 10 s) | returns `0x0` immediately |
| CVE-2026-42945 config, request `/a%20b%26c%22d` | `myvar=/a%20b%2` | `myvar=/a b&c"d` |
| `SSL_SESSION_get0_hostname` in `/usr/sbin/nginx`, `nginx-debug` | 0, 0 | 1, 1 |

The zlib probe calls the public API with a negative length. The full nginx attacks are
in `test/cve_test.py` (§5).

### Targeted VEX ([vex/echo-nginx.openvex.json](vex/echo-nginx.openvex.json))

[vex/make_vex.py](vex/make_vex.py) generates an OpenVEX document from the image. It holds
three statements, each with `status: fixed` and `status_notes` that point to the patch,
the build step, the evidence and the test. **The statements are targeted:**

- The product is **our image digest** (`pkg:oci/echo-nginx@sha256:095b3734…`). The
  subcomponents are **our exact package versions** (`+echo1`), spelled the way each
  scanner reports them.
- They cover only these three CVEs. They do not cover other images, other versions or
  other CVEs.

Scanners can't see the nginx CVEs through Debian package matching. To make them visible,
the same script writes [vex/upstream-components.cdx.json](vex/upstream-components.cdx.json),
a CycloneDX SBOM that names the upstream projects by CPE (`f5:nginx:1.25.5`,
`zlib:zlib:1.4`). An SBOM scan carries no registry digest, so for that scan the VEX
product is our build's own package identity: `pkg:generic/nginx@1.25.5-1~bookworm%2Becho1`.

Results ([scan/scan-with-vex.txt](scan/scan-with-vex.txt)):

| Scan | Without VEX | With VEX |
|---|---|---|
| New image, Trivy: CVE-2026-27171 | reported | **suppressed** |
| New image, Grype: CVE-2026-27171 | reported | **suppressed** |
| Upstream SBOM (CPE), Grype: CVE-2026-42945 | reported | **suppressed** |
| Upstream SBOM (CPE), Grype: CVE-2025-23419 | reported | **suppressed** |
| **Original image**, Trivy and Grype: CVE-2026-27171 | reported | **still reported** |

The last row, plus a run with a deliberately wrong digest (also still reported), shows
that the VEX applies only to our artifact. The VEX is pinned to a digest, so after any
rebuild you must rerun `make scan`.

## 9. Residual risks

- **nginx 1.25.5 has many other upstream CVEs.** The CPE scan (end of
  [scan/scan-with-vex.txt](scan/scan-with-vex.txt)) still lists 27: 7 Critical, 7 High
  and 13 Medium (for example CVE-2026-27654, High, in the `dav` module). They apply to the
  original image too: 1.25.x is end-of-life. Debian matching does not show them, so
  standard scans of either image under-report the real nginx risk. The proper fix is to
  move to a supported nginx branch, which is no longer a drop-in of 1.25.
- **njs 0.8.4** and its QuickJS are also old, with known issues. They are only used if
  the njs module is loaded.
- **About 530–590 Debian findings remain.** They come from the base OS and module
  dependencies; many have no Debian fix (`affected` or `will_not_fix`). See
  the baseline reports (`scan/baseline/*.json`) and the rescans (`scan/new-*.json`).
- **zlib 1.4 is a new major upstream release** running under binaries built for 1.2.13.
  - The ABI check (no missing versioned symbols) and gzip output that is byte-identical
    in the compat test reduce the risk.
  - They don't prove every zlib consumer in the image behaves identically: libpng,
    libxml2, curl, perl and others.
  - Debian's tracker also lists CVE-2026-85091 (High) for every zlib version. CPE data
    says 1.4 is not affected, but we did not verify it in the code, so it is **not** in
    the VEX.
- **Source integrity relies on sha256 pins.** The build checks every download against a
  pinned sha256; it does not verify GPG signatures. The zlib and nginx tarballs behind
  the current pins were verified against their upstream signatures when they were pinned
  (an earlier version of this build did it on every run). pkg-oss and njs are GitHub
  archives with no signature at all. When bumping a version, check the new release's
  signature once, then pin its sha256.
- **Only arm64 was built and tested.** The build is architecture-neutral
  (`dpkg-architecture`, `$arch` in the Containerfile), but amd64 was not run.
- **`/etc/apt/keyrings/nginx-archive-keyring.gpg` is absent.** A downstream Dockerfile
  that runs `apt-get install nginx-module-…` from nginx.org would fail. It would also pull
  in unpatched nginx.org packages, so we see the failure as a feature.

## 10. Surprises and what we would do differently

**Surprises**

- **Scanners are blind to nginx.org's nginx.** Package names and versions from a
  third-party apt repository never match the Debian tracker. A CPE-based SBOM was needed
  to see even one nginx CVE.
- **Trivy's third-party skip is keyed on the `Maintainer` field.** Rebuilding the same
  version with a different maintainer made 2 old CVEs "appear".
- **"No fixed version" in Debian means "flagged forever".** For zlib, a bump to a
  release that really contains the fix still leaves the finding. Only evidence plus VEX
  closes it.
- **Scanner DBs change overnight.** A rescan one day after the baseline showed findings
  that were new in the DB, not in the image. `make scan` therefore rescans the original
  with the same DB before comparing.
- **zlib's `configure` silently drops `CPPFLAGS`.** Without our fix the library would have
  built without `_FORTIFY_SOURCE`. We caught this by checking for `_chk` symbols and RELRO.
- **`set -o pipefail` with `grep -q` gives false failures.** `grep -q` exits early, the
  writer (`nm`) gets SIGPIPE, and the pipeline reports an error although the symbol is
  there. The build uses `grep … >/dev/null`, which reads all its input.
- **pkg-oss can no longer fetch all of its own sources.** `hg.nginx.org` is gone, so its
  pinned njs archive and the xslscript tool are unreachable. We pin njs from GitHub
  ourselves, and we skip xslscript: it only regenerates a stylesheet that pkg-oss already
  ships.
- **`dpkg-source` un-applies the patches after the build.** A grep of the source tree after
  `dpkg-buildpackage` finds nothing. The build therefore checks the patch series and the
  compiled binaries, and `test/cve_test.py` checks the behaviour.
- **The structural test earned its place.** It found the `0755` module mode and the
  missing `ca-certificates`, which a "does it serve the page" test would never catch.

**What we would do differently**

- **For zlib, consider the Debian source package plus a targeted patch** (a backport) next
  to the version bump. That is a smaller change for a shared library. We chose the bump
  because the assignment asks for a bump, and 1.4 is the upstream fix.
- **Build amd64 and arm64 in CI** (buildx multi-platform) and run the same tests on both.
- **Make the build bit-for-bit reproducible.** That means `SOURCE_DATE_EPOCH` and
  normalized archive metadata, and building twice to compare `.deb` hashes. Today the
  inputs are pinned, but the outputs were not checked for identity.
- **Publish the image to a registry** and generate the VEX against the registry digest.
  Then attach both the VEX and a full SBOM to the image as attestations.

## 11. How AI was used

This project was developed with an AI coding assistant (Claude Code), used as a mentor
and co-developer, in explicit stages with human approval at every decision point:

- **Triage and choosing the CVEs.** The AI helped merge and explain the scanner output.
  The candidate CVEs and the trade-offs were discussed, and the final choice was mine.
- **Implementation.** The AI wrote most of the build steps, the Containerfile and the
  tests. It first explained each fix (what changes, which files, what might break, how to
  test it), and I approved before any file was edited.
- **Second iteration.** After the first version, more research on the open nginx CVEs
  showed that a High-severity one with a public exploit, CVE-2026-42945, could be
  backported cleanly, so I added it. I also simplified the project so every part is easy
  to review and explain: three `make` commands, the whole build in one Dockerfile, and the
  tools in Python instead of shell scripts. I considered dropping the four modules and
  kept them, because removing them would break the drop-in promise (§5).
- **Verification.** Every claim in this README was checked by running something: builds,
  tests, scans, the evidence script. Checks that failed were fixed, not explained away:
  the module load test, the pipefail false failure, module permissions and the missing
  `ca-certificates`.
- **Learning.** After each fix, I walked through the diff and the evidence and answered
  interview-style questions about it, so I can explain every decision myself.

Not done by AI on its own: choosing which CVEs to fix, approving each change, and deciding
what goes into the VEX. Nothing was published or committed without my explicit decision.

## 12. Verified vs. still open

**Verified (by running it, on arm64):**

- [x] `make test` builds everything from source and exits 0.
- [x] Image config, nginx filesystem, nginx user and package set are identical to the
      original (`compare_image.py`).
- [x] 40 HTTP checks are identical, covering root, custom config, large bodies, malformed
      requests and startup; only `Date` is normalized (`compat_test.py`).
- [x] The negative control fails as expected (exit 1).
- [x] zlib 1.4 keeps every exported versioned symbol of 1.2.13. nginx loads `libz.so.1.4`.
      `crc32_combine(len2 = -1)` returns 0, while 1.2.13 hangs.
- [x] Both backports are byte-identical to upstream and apply with fuzz 0.
- [x] The CVE-2026-42945 attack corrupts the captured value on the original image; ours
      returns it unchanged (`cve_test.py`, `evidence.txt`).
- [x] The CVE-2025-23419 attack (TLS 1.3 cross-SNI resumption without the second
      server's client cert) succeeds on the original image and is rejected by ours, in
      both `http` and `stream`, with both controls passing on both images (`cve_test.py`).
- [x] All 6 dynamic modules load: release modules in `nginx`, debug modules in
      `nginx-debug`.
- [x] The rescan diff uses the same scanner versions and DB for both images.
- [x] The VEX suppresses the three CVEs for our image only. It does not apply to the
      original image or to a wrong digest.

**Still open:**

- [ ] amd64 build and test.
- [ ] Bit-for-bit reproducibility check (build twice, compare hashes).
- [ ] Code-level review of CVE-2026-85091 against zlib 1.4.
- [ ] The VEX is pinned to the local image digest and must be regenerated after a
      rebuild or a push to a registry.
