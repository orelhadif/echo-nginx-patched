# echo-nginx: a patched drop-in replacement for `nginx:1.25-bookworm`

This repository builds a drop-in replacement for the official `nginx:1.25-bookworm`
image (nginx 1.25.5 on Debian 12). In the replacement, two CVEs are eliminated by
rebuilding the affected components from source:

| CVE | Component | Severity | How it was fixed |
|---|---|---|---|
| **CVE-2026-27171** | zlib (`zlib1g`), linked into nginx | Medium (CVSS 3.x 5.5, NVD) | **Dependency version bump**: zlib 1.2.13 → **1.4**, built from the signed upstream release |
| **CVE-2025-23419** | nginx 1.25.5 itself | Medium (CVSS 3.1 4.3 / 4.0 5.3, F5) | **Backport** of upstream commit [`13935cf`](https://github.com/nginx/nginx/commit/13935cf9fdc3c8d8278c70716417d3b71c36140e) onto 1.25.5, unmodified |

Every package that changes is built from source into a `.deb` inside a clean
`debian:bookworm-slim` container with one command. The image installs those `.deb`
files exactly the way the official Dockerfile installs nginx.org's packages.

```bash
make test      # build the .debs -> build the image -> structural test -> HTTP compat test
```

---

## Contents

1. [Quick start](#1-quick-start)
2. [Repository layout](#2-repository-layout)
3. [Baseline and choice of the CVE pair](#3-baseline-and-choice-of-the-cve-pair)
4. [Fix 1: CVE-2026-27171 (zlib bump)](#4-fix-1-cve-2026-27171-zlib-version-bump)
5. [Fix 2: CVE-2025-23419 (nginx backport)](#5-fix-2-cve-2025-23419-nginx-backport)
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
| `make debs` | Builds all `.deb` files from source in `debian:bookworm-slim` and writes them to `out/` |
| `make image` | `make debs`, then builds `echo-nginx:1.25-bookworm-patched` from `Containerfile` |
| `make test` | `make image`, then `test-structure` and `test-compat`. Exits non-zero on any difference |
| `make test-structure` | Only `test/compare_image.py`, the image config and filesystem comparison |
| `make test-compat` | Only `test/compat_test.py`, the HTTP behaviour comparison |
| `make clean` | Removes `out/` |
| `make vex` | Bonus, after `make test`. Collects the evidence from both images (`vex/evidence.txt`) and regenerates the VEX and the upstream SBOM for the **current** image digest |
| `make scan` | Bonus. Runs `make vex`, then rescans with Trivy and Grype, diffs against `scan/baseline/`, and scans both images with and without the VEX |

You can override the image names: `make test ORIG=nginx:1.25-bookworm IMAGE=my/tag`.

## 2. Repository layout

```
build/
  versions.env              every upstream input: version, URL, sha256, GPG fingerprint
  keys/                     pinned public keys (zlib: Mark Adler, nginx: Roman Arutyunyan)
  lib.sh                    helpers: verified download (sha256 + pinned GPG key)
  build-zlib.sh             zlib 1.4 -> zlib1g + zlib1g-dev .debs
  build-nginx.sh            nginx.org's packaging recipe (pkg-oss) + our patch -> nginx + 4 module .debs
  patches/CVE-2025-23419.patch   the backport, with a provenance header
  Dockerfile.build          the clean, single-command build environment
Containerfile               the final image (mirrors the official Dockerfile)
docker-entrypoint/          the official entrypoint scripts, byte-identical
test/
  compare_image.py          structural drop-in test
  compat_test.py            HTTP behaviour drop-in test
  fixtures/                 custom config, njs script, envsubst template
Makefile
scan/
  baseline/                 the original image: identity (image.txt) + Trivy/Grype reports
  run.sh                    rescan, diff vs. baseline, VEX report (outputs next to it)
vex/                        evidence script + output, VEX, upstream-components SBOM
```

## 3. Baseline and choice of the CVE pair

**What was scanned.** The baseline is pinned in [scan/baseline/image.txt](scan/baseline/image.txt):

| Field | Value |
|---|---|
| Image | `nginx:1.25-bookworm` |
| Index digest | `sha256:a484819e…` |
| Platform | linux/arm64 (manifest `557b2c07…`); the amd64 manifest is `e688fed0…` |
| Built | 2024-05 from `nginxinc/docker-nginx@9abe4ae` |
| Scanners | Trivy 0.76.2 and Grype 0.122.1, with both DBs from 2026-11-24 |

Every comparison in this repository uses the same scanner versions and DBs.

| | Trivy | Grype |
|---|---|---|
| Findings (CVE × package) | 960 | 892 |
| Unique CVEs | 604 | 538 |

To choose the pair, both reports were merged per CVE and package (962 rows) and sorted
by the package's role in the image (linked by nginx, a module dependency, the curl stack,
or the base OS), by fix status and by severity. The two scanners disagree on severity in
419 of those rows, which is why the severities in this README name their source.

**Why this pair.**

- **CVE-2026-27171 (zlib, bump).**
  - zlib is on nginx's real runtime path: `libz.so.1` is a `NEEDED` entry of `/usr/sbin/nginx` and is used for gzip.
  - Debian has **no fixed version**: the status is "affected" and Grype reports it as wont-fix. `apt-get upgrade` cannot fix it, so we had to fix it ourselves.
  - A newer upstream release, zlib **1.4**, contains the fix (`if (len2 < 0) return 0;`). A version bump is the natural method.
  - Most of the other "bump" candidates in the table were already fixed in Debian, so picking one would have meant only running `apt-get upgrade`.
  - We rejected zlib **1.3.2**. CPE data marks it affected by CVE-2026-85091, which 1.4 is not.
- **CVE-2025-23419 (nginx, backport).**
  - The CVE is in nginx itself, in the main binary.
  - Upstream fixed it only in 1.27.4 and 1.26.3. Upgrading to one of those would change the shipped version and break the drop-in promise. A backport keeps 1.25.5.
  - The upstream fix is small: one commit touching 2 files. It applies to 1.25.5 with `--fuzz=0`, so we ship it **unmodified**. That matters for review, because the reviewer can diff our patch against upstream.
  - **No scanner reports it on the original image.** Scanners match Debian packages against the Debian security tracker, and nginx.org's `1.25.5-1~bookworm` package is not in that tracker. This blind spot is why VEX and CPE matching matter for this CVE (§8).

## 4. Fix 1: CVE-2026-27171 (zlib version bump)

**The bug.** `crc32_combine()` and `crc32_combine64()` use `x2nmodp()`. When `len2` is
negative, the loop shifts a negative number to the right, the value never reaches 0, and
the call never returns. Any caller that passes an attacker-influenced length can be made
to hang (DoS). zlib 1.4 returns 0 for `len2 < 0`.

**What [build/build-zlib.sh](build/build-zlib.sh) does:**

1. **Download and verify.** It downloads `zlib-1.4.tar.gz` and checks two things: the sha256
   pinned in [build/versions.env](build/versions.env), and a GPG signature that must be
   `VALIDSIG` from **the pinned fingerprint** of the key in
   [build/keys/zlib-madler.asc](build/keys/zlib-madler.asc). Signed by "any valid key" is
   not enough.
2. **Check that the fix is in the source.** It greps `crc32.c` for `if (len2 < 0)` and
   fails if the check is missing.
3. **Build with Debian's hardening flags** (`dpkg-buildflags`).
   - zlib's own `configure` ignores `CPPFLAGS`, so `_FORTIFY_SOURCE` was silently dropped.
     We fold `CPPFLAGS` into `CFLAGS`, and `LDFLAGS` into `LDSHARED`.
   - The SONAME stays `libz.so.1` and the symbol-version script stays `zlib.map`.
   - The libraries are installed at Debian's paths: `/lib/<triplet>` and `/usr/lib/<triplet>`.
   - `make test` runs zlib's own tests.
4. **ABI check.** It compares every exported, versioned symbol of Debian's
   `libz.so.1.2.13` with those of the new library and fails if any symbol is missing. This
   is what makes the bump safe for every binary already linked against `libz.so.1`,
   nginx included.
5. **Package as `zlib1g` and `zlib1g-dev`** with version `1:1.4-0+echo1`:
   - the epoch `1:` makes it sort above Debian's `1:1.2.13.dfsg-1`;
   - `Source: zlib`, `Provides: libz1` and `Multi-Arch: same`;
   - a `shlibs` file, so packages built against it depend on it;
   - an `ldconfig` trigger;
   - `Depends` computed by `dpkg-shlibdeps`.

The image installs this `zlib1g` in place of Debian's. Nothing is relinked, because nginx
loads `libz.so.1` at runtime. See [vex/evidence.txt](vex/evidence.txt): the running nginx
maps `libz.so.1.4`.

## 5. Fix 2: CVE-2025-23419 (nginx backport)

**The bug.** With TLS 1.3, OpenSSL resumes sessions in the *default* SSL context before
the SNI callback runs. Suppose two virtual servers share a session cache, and one requires
client certificates (`ssl_verify_client on`). A client can get a session on a server that
doesn't verify client certificates, then resume it with the SNI name of the protected
server, and skip client-certificate authentication there.

The fix: when verification is enabled, reject a resumed handshake if the session's
original host name (`SSL_SESSION_get0_hostname`) differs from the current SNI name.

**The patch** is [build/patches/CVE-2025-23419.patch](build/patches/CVE-2025-23419.patch).
- It starts with a provenance header: upstream commit, release versions, advisory links
  and backport notes.
- The header is followed by the **unmodified** `git format-patch` of commit `13935cf9…`,
  which touches `src/http/ngx_http_request.c` and `src/stream/ngx_stream_ssl_module.c`.
- The body's sha256 is identical to upstream's.
- The fields the fix needs (`handshake_rejected` and the `verify` config field) already
  exist in 1.25.5, so the patch needed no adaptation.

**How the package is built: nginx.org's own recipe plus our patch.**
[build/build-nginx.sh](build/build-nginx.sh) does not package nginx by hand. It runs
**pkg-oss**, nginx.org's packaging repository, at tag `1.25.5-1`. That is the same
recipe that produced the original `nginx_1.25.5-1~bookworm` packages. Its `debian/rules`,
`control`, maintainer scripts, configure arguments and compiler flags are used unchanged.
We add only three things:

1. **Our patch.** It is copied to `contrib/src/nginx/`. pkg-oss puts every `*.patch`
   there into `debian/patches/series`, and `dpkg-source` (quilt, fuzz 0) applies it before
   compiling. The build log shows `applying CVE-2025-23419.patch`.
2. **A changelog entry** made with `dch`. It raises the version to `…+echo1` and says
   what changed and why.
3. **Our name as `Maintainer`** (`PACKAGE_VENDOR`). nginx.org did not build these
   packages, so they must not claim it did.

The steps, in order:

1. **Verify sources.**
   - pkg-oss: sha256.
   - nginx 1.25.5: sha256 plus GPG with a pinned fingerprint. pkg-oss then also checks
     it against its own SHA512SUMS.
   - njs 0.8.4: sha256. pkg-oss pins njs to an `hg.nginx.org` archive, but that server
     is gone, so we pin the GitHub tag archive.
   - QuickJS: pkg-oss fetches it with git and checks the pinned commit hash itself.
   - The script also checks that the `zlib1g-dev` in the builder is **ours**, so nginx
     is compiled, and its `Depends` computed, against the zlib we ship.
2. **Generate the source trees** with `make rules-base rules-module-{geoip,image-filter,njs,xslt}`.
   - pkg-oss is unpacked at the same path as nginx.org's build
     (`/data/builder/debuild/nginx-1.25.5`), so `-ffile-prefix-map` gives the same
     `nginx -V` output.
   - `MODULE_RELEASE_njs=3` matches the original `nginx-module-njs …-3~bookworm`.
3. **Build** each package with `dpkg-buildpackage -b`. debhelper builds `nginx` and
   `nginx-debug` and both module variants, strips the binaries, fixes permissions, and
   writes `md5sums`, `conffiles` and `shlibs` dependencies. The result: `nginx` now
   depends on `zlib1g (>= 1:1.4-0+echo1)`.
4. **Binary evidence.** The script fails unless the patch is in the series **and**
   `nm -D` shows that the built `nginx` and `nginx-debug` import
   `SSL_SESSION_get0_hostname@OPENSSL_3.0.0`. The original binaries never import that
   function.

`nginx -V` of the two images is identical except for the compiler and OpenSSL version
lines: our base is a newer Debian 12 point release. Configure arguments and paths are
byte-identical.

## 6. Build artifact

**One reproducible command:** `make debs` (or `make test` for everything). It runs
[build/Dockerfile.build](build/Dockerfile.build):

```
debian:bookworm-slim@sha256:e67eeead…  (pinned)
  apt-get install build-essential dpkg-dev curl ca-certificates gnupg binutils
  build-zlib.sh          -> out/zlib1g_*.deb, out/zlib1g-dev_*.deb
  dpkg -i our zlib1g-dev; apt-get install debhelper, quilt, devscripts, -dev libraries
  build-nginx.sh         pkg-oss 1.25.5-1 + our patch, dpkg-buildpackage
                         -> out/nginx_*.deb, out/nginx-module-*.deb
FROM scratch AS export   -> copied to ./out by BuildKit (--output type=local)
```

Artifacts (arm64), with their sha256 values recorded in `out/zlib.sha256` and `out/nginx.sha256`:

| Package | Version | Size |
|---|---|---|
| `zlib1g` | `1:1.4-0+echo1` | 45 KB |
| `zlib1g-dev` | `1:1.4-0+echo1` | 171 KB |
| `nginx` | `1.25.5-1~bookworm+echo1` | 941 KB |
| `nginx-module-njs` | `1.25.5+0.8.4-3~bookworm+echo1` | 837 KB |
| `nginx-module-{geoip,image-filter,xslt}` | `1.25.5-1~bookworm+echo1` | 80–84 KB each |

**Pins.** Every upstream input is pinned in [build/versions.env](build/versions.env): the
base image digest, the tarballs' sha256 and the GPG fingerprints. A changed input fails
the build.

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

**Result:** `make test` exits 0. Structure: PASS. Compat: `PASS (40 checks, all identical)`.

## 8. Rescan, evidence and VEX (bonus)

### Rescan vs. baseline ([scan/diff-vs-baseline.txt](scan/diff-vs-baseline.txt))

| | Baseline | New | Disappeared | Appeared |
|---|---|---|---|---|
| Trivy | 960 | **589** | 373 | 2 |
| Grype | 892 | **530** | 362 | 0 |

**Most of this drop comes from the newer Debian 12.15 base, not from our two fixes.**
The biggest drops are in openssl, expat, gnutls, curl and libxml2. Our two CVEs:

- **CVE-2026-27171** is **still reported** on `zlib1g 1:1.4-0+echo1`, by both scanners.
  Both match the package to Debian's source package `zlib`, and Debian lists no fixed
  version, so every version is flagged. The finding comes from version matching, not from
  the code.
- **CVE-2025-23419** is **not reported on either image**, for the version blind spot
  described in §3.
- **The 2 new Trivy findings** are LOW nginx CVEs: CVE-2009-4487 and CVE-2013-0337. We
  tested it: Trivy skips packages whose `Maintainer` is nginx.org's packaging team, as
  third-party packages. Our package has a different maintainer, so Trivy now evaluates it.
  The same two issues exist in the original; they were simply not looked at.

### Evidence the fixes are in the build ([vex/evidence.sh](vex/evidence.sh) → [vex/evidence.txt](vex/evidence.txt))

The evidence is collected from **the images themselves**, not from build logs:

| Check | Original | New |
|---|---|---|
| `zlib1g` package | `1:1.2.13.dfsg-1` | `1:1.4-0+echo1` |
| libz mapped by the running nginx (`/proc/<pid>/maps`) | `libz.so.1.2.13` | `libz.so.1.4` |
| `crc32_combine(…, len2 = -1)`, compiled in the image against its own zlib | never returns (killed after 10 s) | returns `0x0` immediately |
| `SSL_SESSION_get0_hostname` in `/usr/sbin/nginx`, `nginx-debug` | 0, 0 | 1, 1 |

This is not an exploit. The zlib probe calls the public API with a negative length.

### Targeted VEX ([vex/echo-nginx.openvex.json](vex/echo-nginx.openvex.json))

[vex/make_vex.py](vex/make_vex.py) generates an OpenVEX document from the image. It holds
two statements, each with `status: fixed` and `status_notes` that point to the patch,
the build script and the evidence. **The statements are targeted:**

- The product is **our image digest** (`pkg:oci/echo-nginx@sha256:37d33a2b…`). The
  subcomponents are **our exact package versions** (`+echo1`), spelled the way each
  scanner reports them.
- They cover only these two CVEs. They do not cover other images, other versions or other
  CVEs.

Scanners can't see CVE-2025-23419 through Debian package matching. To make it visible,
the same script writes [vex/upstream-components.cdx.json](vex/upstream-components.cdx.json),
a CycloneDX SBOM that names the upstream projects by CPE (`f5:nginx:1.25.5`,
`zlib:zlib:1.4`). An SBOM scan carries no registry digest, so for that scan the VEX
product is our build's own package identity: `pkg:generic/nginx@1.25.5-1~bookworm%2Becho1`.

Results ([scan/scan-with-vex.txt](scan/scan-with-vex.txt)):

| Scan | Without VEX | With VEX |
|---|---|---|
| New image, Trivy: CVE-2026-27171 | reported | **suppressed** |
| New image, Grype: CVE-2026-27171 | reported | **suppressed** |
| Upstream SBOM (CPE), Grype: CVE-2025-23419 | reported | **suppressed** |
| **Original image**, Trivy and Grype: CVE-2026-27171 | reported | **still reported** |

The last row, plus a run with a deliberately wrong digest (also still reported), shows
that the VEX applies only to our artifact. The VEX is pinned to a digest, so after any
rebuild you must rerun `make vex` (`make scan` does it for you).

## 9. Residual risks

- **nginx 1.25.5 has many other upstream CVEs.** The CPE scan
  (end of [scan/scan-with-vex.txt](scan/scan-with-vex.txt)) still
  lists 28 CVEs: 7 Critical, 8 High and 13 Medium (for example CVE-2026-1642, High, and
  CVE-2024-7347, Medium, in the mp4 module). They apply to the original image too: 1.25.x is end-of-life. Debian
  matching does not show them, so standard scans of either image under-report the real
  nginx risk. The proper fix is to move to a supported nginx branch, which is no longer a
  drop-in of 1.25.
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
- **Source integrity.** zlib and nginx are verified by sha256 **and** a pinned GPG
  fingerprint. pkg-oss, njs and QuickJS are GitHub archives and are pinned by sha256 only,
  because no signature exists.
- **The fix for CVE-2025-23419 was not exercised behaviourally.** We prove the patch is
  applied and compiled in (an unmodified upstream diff, a source grep and a binary import).
  We did not run a TLS 1.3 cross-SNI resumption test against both images.
- **Only arm64 was built and tested.** The build scripts are architecture-neutral
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
- **zlib's `configure` silently drops `CPPFLAGS`.** Without our fix the library would have
  built without `_FORTIFY_SOURCE`. We caught this by checking for `_chk` symbols and RELRO.
- **`set -o pipefail` with `grep -q` gives false failures.** `grep -q` exits early, the
  writer gets SIGPIPE, and the pipeline reports an error. We capture output into a variable
  instead.
- **pkg-oss can no longer fetch all of its own sources.** `hg.nginx.org` is gone, so its
  pinned njs archive and the xslscript tool are unreachable. We pin njs from GitHub
  ourselves, and we skip xslscript: it only regenerates a stylesheet that pkg-oss already
  ships.
- **`dpkg-source` un-applies the patch after the build.** A grep of the source tree after
  `dpkg-buildpackage` finds nothing. The evidence therefore checks the patch series and
  the compiled binaries.
- **The structural test earned its place.** It found the `0755` module mode and the
  missing `ca-certificates`, which a "does it serve the page" test would never catch.

**What we would do differently**

- **For zlib, consider the Debian source package plus a targeted patch** (a backport) next
  to the version bump. That is a smaller change for a shared library. We chose the bump
  because the assignment asks for one bump and one backport, and 1.4 is the upstream fix.
- **Add a TLS 1.3 cross-SNI resumption regression test.** We would run it against both
  images with a shared session cache and `ssl_verify_client`. It would prove the backport
  behaviourally, not only by its presence.
- **Build amd64 and arm64 in CI** (buildx multi-platform) and run the same tests on both.
- **Make the build bit-for-bit reproducible.** That means `SOURCE_DATE_EPOCH` and
  normalized archive metadata, and building twice to compare `.deb` hashes. Today the
  inputs are pinned, but the outputs were not checked for identity.
- **Publish the image to a registry** and generate the VEX against the registry digest.
  Then attach both the VEX and a full SBOM to the image as attestations.

## 11. How AI was used

This project was developed with an AI coding assistant (Claude Code), used as a mentor
and co-developer, in explicit stages with human approval at every decision point:

- **Triage and choosing the pair.** The AI helped merge and explain the scanner output.
  The candidate CVEs and the trade-offs were discussed, and the final pair was chosen by
  me.
- **Implementation.** The AI wrote most of the build scripts, the Containerfile and the
  tests. It first explained each fix (what changes, which files, what might break, how to
  test it), and I approved before any file was edited.
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
- [x] The backport is byte-identical to upstream and applies with `--fuzz=0`. Both nginx
      binaries contain `SSL_SESSION_get0_hostname`; the original binaries do not.
- [x] All 6 dynamic modules load: release modules in `nginx`, debug modules in
      `nginx-debug`.
- [x] Rescan diff against the baseline uses the same scanner and DB versions.
- [x] The VEX suppresses both CVEs for our image only. It does not apply to the original
      image or to a wrong digest.

**Still open:**

- [ ] amd64 build and test.
- [ ] Behavioural regression test for CVE-2025-23419 (TLS 1.3 cross-SNI resumption).
- [ ] Bit-for-bit reproducibility check (build twice, compare hashes).
- [ ] Code-level review of CVE-2026-85091 against zlib 1.4.
- [ ] The VEX is pinned to the local image digest and must be regenerated after a
      rebuild or a push to a registry.
- [ ] Nothing is committed yet.
