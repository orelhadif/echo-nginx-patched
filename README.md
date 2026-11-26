# echo-nginx: patched `nginx:1.25-bookworm`

A drop-in replacement for `nginx:1.25-bookworm` (nginx 1.25.5, Debian 12) with three
CVEs fixed:

| CVE | Where | Severity | Fix |
|---|---|---|---|
| CVE-2026-42945 | nginx `rewrite` module, heap overrun | High (F5 CVSS 3.1 8.1), public exploit | backport of upstream [`524977e`](https://github.com/nginx/nginx/commit/524977e7c534e87e5b55739fa74601c9f1102686) |
| CVE-2025-23419 | nginx TLS 1.3 / SNI, client-cert bypass | Medium (F5 CVSS 3.1 4.3) | backport of upstream [`13935cf`](https://github.com/nginx/nginx/commit/13935cf9fdc3c8d8278c70716417d3b71c36140e) |
| CVE-2026-27171 | zlib `crc32_combine()`, infinite loop | Medium (NVD 5.5) | version bump, zlib 1.2.13 → 1.4 |

## Usage

Needs Docker with BuildKit, make and Python 3.9+. `make scan` also needs `trivy` and `grype`.

```bash
make test    # build the .debs and the image, then compare it with the original
make scan    # evidence, VEX, and Trivy/Grype rescans of both images
make clean   # remove out/
```

## Layout

```
build/Dockerfile        the whole build: pinned sources -> out/*.deb
build/patches/          the two nginx backports (provenance header + upstream commit)
build/zlib/             Debian metadata for our zlib1g / zlib1g-dev
Containerfile           the image, following the official Dockerfile
docker-entrypoint/      the official entrypoint scripts, unchanged
test/                   compare_image.py, compat_test.py, cve_test.py, fixtures/
scan/                   baseline/ (original image), run.py, diff_scans.py, results
vex/                    evidence.py, make_vex.py, the VEX and the CPE SBOM
```

## Why these CVEs

The original image was scanned with Trivy and Grype (identity in
[scan/baseline/image.txt](scan/baseline/image.txt)). Neither scanner reports any nginx
CVE: nginx.org's package isn't in the Debian tracker that they match against. The nginx
CVEs were listed with a CPE scan of nginx 1.25.5 instead.

- **CVE-2026-42945**: the highest EPSS of the open nginx CVEs (69%), a public exploit,
  and in a module every nginx has. Upstream fixed it only in 1.30.1; the fix is one line.
- **CVE-2025-23419**: in the main binary, in both `http` and `stream`. Fixed upstream only
  in 1.26.3 / 1.27.4; one commit, two files.
- **CVE-2026-27171**: zlib is loaded by nginx (gzip) and Debian has no fixed version, so
  `apt-get upgrade` can't fix it. zlib 1.4 has the fix. 1.3.2 was rejected because CPE
  data lists it as affected by CVE-2026-85091.

## The build ([build/Dockerfile](build/Dockerfile))

Runs in a pinned `debian:bookworm-slim`. Every source is downloaded with
`ADD --checksum=sha256:…`, so a changed tarball fails the build.

**zlib (part 1).** Check that `crc32.c` contains the fix, build with Debian's hardening
flags (`dpkg-buildflags`; zlib's `configure` ignores `CPPFLAGS`, so they are folded into
`CFLAGS`), run zlib's tests, and check the ABI: every versioned symbol exported by
Debian's `libz.so.1.2.13` must exist in the new library. Then package it as `zlib1g` and
`zlib1g-dev`, version `1:1.4-0+echo1`, with the same names and fields as Debian's so it
replaces them in place. The new `zlib1g-dev` is installed in the builder before nginx is
compiled.

**nginx (part 2).** Built with pkg-oss, nginx.org's own packaging, at tag `1.25.5-1`: the
same recipe, configure flags and paths as the original packages. We add only:
- the two patches in `contrib/src/nginx/`, which `dpkg-source` applies with fuzz 0;
- a changelog entry raising the version to `…+echo1`;
- our name as `Maintainer`.

The four dynamic modules (geoip, image-filter, njs, xslt) are rebuilt too: the original
ones depend on the exact original nginx version, and dropping them would break configs
that `load_module` them. The build fails unless both patches are in the series and both
`nginx` and `nginx-debug` import `SSL_SESSION_get0_hostname`, which only the
CVE-2025-23419 fix calls.

**The image ([Containerfile](Containerfile))** repeats the official Dockerfile step by
step (labels, env, uid/gid 101, entrypoint, `STOPSIGNAL`, `CMD`), but installs our
`.deb` files, bind-mounted so they don't stay in a layer.

## Tests (`make test`)

- **[compare_image.py](test/compare_image.py)**: image config, the nginx part of the
  filesystem (47 paths: mode, owner, content), the `nginx` user, and the package list
  (149 = 149) must match the original. It found two real bugs in early builds: module
  files with mode `0755`, and missing `ca-certificates`.
- **[compat_test.py](test/compat_test.py)**: 40 requests sent as identical raw bytes to
  both images, in 4 setups: defaults, a custom config (rewrite, gzip, TLS, mTLS), large
  bodies, malformed requests, envsubst templates. Status, headers in order and body must
  match; only `Date` is ignored. A copy of the image with one extra byte in `index.html`
  makes it fail.
- **[cve_test.py](test/cve_test.py)**: each attack runs against both images. It must
  succeed on the original (so the test can see the bug) and fail on ours.

| Check | Original | Ours |
|---|---|---|
| CVE-2026-42945: `rewrite ^(.*) /new?c=1; set $myvar $1;`, request `/a%20b%26c%22d` | `myvar=/a%20b%2` (escaped, written past the buffer) | `myvar=/a b&c"d` |
| control: request `/abc` | `myvar=/abc` | `myvar=/abc` |
| CVE-2025-23419: TLS 1.3 session from `a.test` resumed as `b.test` without the client cert `b.test` requires, in `http` and `stream` | served | rejected |
| controls: resume `a.test` as `a.test`; `b.test` with its cert | served | served |

## Scan and VEX (`make scan`)

**Rescan.** [scan/run.py](scan/run.py) scans the original and the new image with the same
scanner DB (it changes daily) and writes [scan/diff-vs-baseline.txt](scan/diff-vs-baseline.txt):

| | Original | New | Gone | New findings |
|---|---|---|---|---|
| Trivy | 956 | 585 | 373 | 2 |
| Grype | 867 | 505 | 362 | 0 |

Most of the drop comes from the newer Debian 12 point release in our base, not from our
three fixes. For those three:
- CVE-2026-27171 is still reported on our `zlib1g`, because Debian lists no fixed version
  and the scanners match on the package name.
- The nginx CVEs are not reported on either image (the blind spot above).
- The 2 new Trivy findings are old LOW nginx CVEs. Trivy skips packages maintained by
  nginx.org; ours has a different `Maintainer`, so it is checked now.

**Evidence.** [vex/evidence.py](vex/evidence.py) checks both running images and writes
[vex/evidence.txt](vex/evidence.txt):

| | Original | New |
|---|---|---|
| `zlib1g` / libz mapped by nginx | `1:1.2.13.dfsg-1` / `libz.so.1.2.13` | `1:1.4-0+echo1` / `libz.so.1.4` |
| `crc32_combine(…, -1)` compiled in the image | hangs | returns 0 |
| CVE-2026-42945 request | `myvar=/a%20b%2` | `myvar=/a b&c"d` |
| `SSL_SESSION_get0_hostname` in nginx, nginx-debug | 0, 0 | 1, 1 |

**VEX.** [vex/make_vex.py](vex/make_vex.py) writes an OpenVEX file with a `fixed` statement
for each CVE. The product is our image digest, so it can't hide anything on another image.
Because scanners don't see the nginx CVEs at all, the script also writes a small
CycloneDX SBOM naming nginx and zlib by CPE, which Grype can scan.

| Scan ([scan/scan-with-vex.txt](scan/scan-with-vex.txt)) | Without VEX | With VEX |
|---|---|---|
| New image, Trivy and Grype: CVE-2026-27171 | reported | suppressed |
| CPE SBOM, Grype: CVE-2026-42945, CVE-2025-23419 | reported | suppressed |
| Original image: CVE-2026-27171 | reported | still reported |

The VEX is tied to the digest, so rerun `make scan` after every rebuild.

## Residual risk

- nginx 1.25.5 is end-of-life. The CPE scan still lists 28 other upstream CVEs (7 Critical,
  7 High, 14 Medium). The real fix is a supported nginx branch, which is not a drop-in.
- About 500–590 Debian findings remain in the base OS, many with no Debian fix.
- zlib 1.4 runs under binaries built for 1.2.13. The ABI check and byte-identical gzip
  output lower the risk, but don't prove every library in the image behaves the same.
- Sources are checked by sha256 only. GPG signatures were verified once when pinning;
  pkg-oss and njs are unsigned GitHub archives.
- Only arm64 was built and tested.
- The nginx.org apt key is not in the image, so installing more modules from nginx.org
  fails. Those packages would be unpatched anyway.

## Surprises

- Scanners don't see nginx.org's nginx at all; a CPE SBOM was needed.
- Debian "no fixed version" means the zlib finding stays after a real fix. Only VEX
  closes it.
- Trivy's skip of third-party packages depends on the `Maintainer` field.
- The scanner DB changed overnight, so the baseline has to be rescanned with the same DB.
- `pipefail` plus `grep -q` failed the build falsely (SIGPIPE to `nm`).
- `hg.nginx.org` is gone, so pkg-oss can't fetch njs; it's pinned from GitHub instead.

Next time: build amd64 too, check that two builds give identical `.deb` hashes, and push
the image to a registry with the VEX and SBOM attached as attestations.
