# syntax=docker/dockerfile:1
#
# Builder: produces our .deb files from pinned upstream source inside a clean
# debian:bookworm-slim, and exports only the packages (`make test` runs it):
#   docker build -f build/Dockerfile --target export --output type=local,dest=out build/
#
#   Part 1  zlib 1.4               version bump  -> CVE-2026-27171
#   Part 2  nginx 1.25.5 + patches backports     -> CVE-2025-23419, CVE-2026-42945
#
# Nothing pre-built is copied in: only the source pins below, build/patches/
# and build/zlib/ (Debian metadata for the zlib packages).

# Base pinned by digest (debian:bookworm-slim, Debian 12.15, 2026-11-24), so the
# toolchain does not drift between runs.
ARG BASE=debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e

FROM ${BASE} AS builder
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

ARG ZLIB_VERSION=1.4
# Epoch "1:" is required: Debian's version is 1:1.2.13.dfsg-1, and without the
# epoch dpkg would consider 1.4 *older*. "+echo1" marks our rebuild.
ARG ZLIB_DEB_VERSION=1:1.4-0+echo1
ARG NGINX_VERSION=1.25.5
ARG VENDOR="Echo home assignment build <build@localhost>"

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential dpkg-dev ca-certificates binutils \
 && rm -rf /var/lib/apt/lists/*

# ---- Pinned upstream sources --------------------------------------------------
# ADD --checksum: BuildKit downloads the file and fails the build if its sha256
# differs from the pin. To bump a version: check the new release's upstream
# signature once, then pin its sha256 here.
#
# zlib 1.4: 1.3.2 is the first release that fixes CVE-2026-27171, but
# 1.3.1.2..1.3.2 are affected by CVE-2026-85091, so we take 1.4 (fixes both).
ADD --checksum=sha256:02dd159783677a749c04adbdd02b55b8a2bcc7e054f51b76b549199a916ad584 \
    https://github.com/madler/zlib/releases/download/v1.4/zlib-1.4.tar.gz /src/zlib-1.4.tar.gz
# nginx 1.25.5: the same upstream version as nginx:1.25-bookworm.
ADD --checksum=sha256:2fe2294f8af4144e7e842eaea884182a84ee7970e11046ba98194400902bbec0 \
    https://nginx.org/download/nginx-1.25.5.tar.gz /src/nginx-1.25.5.tar.gz
# pkg-oss 1.25.5-1: nginx.org's own packaging recipe (debian/rules, control,
# configs, maintainer scripts), the tag the original packages were built from.
ADD --checksum=sha256:53070dffc727af6fc9ac18b56cfcf294ecdce222264e26cc9320ec96b80fc9b3 \
    https://github.com/nginx/pkg-oss/archive/refs/tags/1.25.5-1.tar.gz /src/pkg-oss-1.25.5-1.tar.gz
# njs 0.8.4 (same as the original image). pkg-oss pins an hg.nginx.org archive
# that no longer exists, so we pin the GitHub tag archive (same tree) instead.
ADD --checksum=sha256:fe197e254204c15e9f1df0acf375add57be3416901ec8d7b87319dccb490f90d \
    https://github.com/nginx/njs/archive/refs/tags/0.8.4.tar.gz /src/njs-0.8.4.tar.gz
# QuickJS (engine of the /usr/bin/njs CLI) is fetched by pkg-oss itself with git
# and checked against the commit hash pkg-oss pins.

# ==== Part 1: zlib 1.4 (version bump, CVE-2026-27171) ==========================
WORKDIR /zlib

# 1a. Unpack and prove the fix is in the source we build: 1.4 rejects a negative
#     length in crc32_combine_gen64() (the CVE is an infinite loop on len2 < 0).
RUN tar xzf /src/zlib-$ZLIB_VERSION.tar.gz --strip-components=1 \
 && grep -A2 'crc32_combine_gen64(z_off64_t len2)' crc32.c | tee /dev/stderr | grep 'if (len2 < 0)' >/dev/null

# 1b. Build with Debian's hardening flags (dpkg-buildflags), Debian's soname
#     (libz.so.1) and symbol versions (zlib.map), and Debian's paths: the .so in
#     /lib/<triplet>, dev files in /usr/lib/<triplet>. Then zlib's own tests.
RUN eval "$(dpkg-buildflags --export=sh)" \
 && T=$(dpkg-architecture -qDEB_HOST_MULTIARCH) \
 && CFLAGS="$CPPFLAGS $CFLAGS" \
    LDSHARED="gcc -shared -Wl,-soname,libz.so.1,--version-script,zlib.map $LDFLAGS" \
    ./configure --prefix=/usr --libdir=/usr/lib/$T --sharedlibdir=/lib/$T --includedir=/usr/include \
 && make -j"$(nproc)" \
 && make test

# 1c. ABI check: every symbol Debian's libz 1.2.13 (installed in this builder)
#     exports must still exist in our 1.4, or programs linked to it would break.
RUN T=$(dpkg-architecture -qDEB_HOST_MULTIARCH) \
 && nm -D --defined-only --with-symbol-versions /lib/$T/libz.so.1    | awk '{print $3}' | sort > /tmp/abi.old \
 && nm -D --defined-only --with-symbol-versions libz.so.$ZLIB_VERSION | awk '{print $3}' | sort > /tmp/abi.new \
 && missing=$(comm -23 /tmp/abi.old /tmp/abi.new) \
 && if [ -n "$missing" ]; then echo "ABI BREAK, missing in $ZLIB_VERSION: $missing"; exit 1; fi \
 && echo "ABI OK: all $(wc -l < /tmp/abi.old) symbols of 1.2.13 present; added: $(comm -13 /tmp/abi.old /tmp/abi.new | tr '\n' ' ')"

# 1d. Package as zlib1g + zlib1g-dev: same names, files and paths as Debian's,
#     metadata from build/zlib/. Depends: libc6 >= the newest glibc symbol we use.
COPY zlib/ /zlib-debian/
RUN T=$(dpkg-architecture -qDEB_HOST_MULTIARCH) && ARCH=$(dpkg --print-architecture) \
 && GLIBC=$(objdump -T libz.so.$ZLIB_VERSION | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1) \
 && rt=/pkg/zlib1g && dev=/pkg/zlib1g-dev \
 && install -Dm644 libz.so.$ZLIB_VERSION $rt/lib/$T/libz.so.$ZLIB_VERSION \
 && strip --strip-unneeded $rt/lib/$T/libz.so.$ZLIB_VERSION \
 && ln -s libz.so.$ZLIB_VERSION $rt/lib/$T/libz.so.1 \
 && install -Dm644 LICENSE $rt/usr/share/doc/zlib1g/copyright \
 && install -Dm644 -t $dev/usr/include zlib.h zconf.h \
 && install -Dm644 -t $dev/usr/lib/$T libz.a \
 && install -Dm644 -t $dev/usr/lib/$T/pkgconfig zlib.pc \
 && ln -s /lib/$T/libz.so.1 $dev/usr/lib/$T/libz.so \
 && install -Dm644 LICENSE $dev/usr/share/doc/zlib1g-dev/copyright \
 && mkdir -p $rt/DEBIAN $dev/DEBIAN /out \
 && sed "s/@VERSION@/$ZLIB_DEB_VERSION/" /zlib-debian/zlib1g.shlibs > $rt/DEBIAN/shlibs \
 && cp /zlib-debian/zlib1g.triggers $rt/DEBIAN/triggers \
 && for p in zlib1g zlib1g-dev; do \
        sed -e "s/@VERSION@/$ZLIB_DEB_VERSION/g" -e "s/@ARCH@/$ARCH/" -e "s/@GLIBC@/$GLIBC/" \
            -e "s/@SIZE@/$(du -sk /pkg/$p | cut -f1)/" /zlib-debian/$p.control > /pkg/$p/DEBIAN/control \
     && dpkg-deb --root-owner-group --build /pkg/$p /out/${p}_${ZLIB_DEB_VERSION#*:}_$ARCH.deb; \
    done \
 && dpkg-deb -I /out/zlib1g_*.deb | sed -n '/Package:/,/Description/p'

# 1e. Install OUR zlib1g/zlib1g-dev before nginx's build dependencies, so nginx
#     is compiled against the 1.4 headers and records a dependency on our zlib1g.
#     The last line fails the build if any other zlib1g-dev ended up installed.
RUN dpkg -i /out/zlib1g_*.deb /out/zlib1g-dev_*.deb \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        debhelper quilt lsb-release devscripts fakeroot file git xz-utils \
        xsltproc libxml2-utils \
        libssl-dev libpcre2-dev libgeoip-dev libgd-dev libxml2-dev libxslt1-dev libedit-dev \
 && rm -rf /var/lib/apt/lists/* \
 && [ "$(dpkg-query -W -f='${Version}' zlib1g-dev)" = "$ZLIB_DEB_VERSION" ]
# (debhelper/quilt/lsb-release/fakeroot: pkg-oss's debian/rules; devscripts: dch;
#  git/xz-utils: pkg-oss fetches QuickJS; xsltproc/xmllint: pkg-oss changelogs.)

# ==== Part 2: nginx 1.25.5 + backports (CVE-2025-23419, CVE-2026-42945) ========
# nginx.org builds pkg-oss checked out at this path; it ends up in `nginx -V`
# (-ffile-prefix-map), so the same path keeps `nginx -V` identical.
WORKDIR /data/builder/debuild/nginx-$NGINX_VERSION

# 2a. pkg-oss + sources in contrib/tarballs (so pkg-oss does not download them;
#     it still checks nginx against its own SHA512SUMS; .sum-njs marks njs as
#     checked, since its pinned SHA512 is of the defunct hg archive). Our patches
#     go to contrib/src/nginx/: pkg-oss lists every *.patch there in
#     debian/patches/series, and dpkg-source applies them (quilt format, fuzz 0).
COPY patches/ /patches/
RUN tar xzf /src/pkg-oss-1.25.5-1.tar.gz --strip-components=1 \
 && mkdir -p contrib/tarballs \
 && cp /src/nginx-$NGINX_VERSION.tar.gz /src/njs-0.8.4.tar.gz contrib/tarballs/ \
 && touch contrib/.sum-njs \
 && cp -v /patches/*.patch contrib/src/nginx/

# 2b. Generate the debian/ trees for nginx and the four modules the original ships.
#     MODULE_RELEASE_njs=3: the original ships nginx-module-njs ...-3~bookworm.
#     XSLS: points at an existing file so make does not try to download xslscript
#     from the defunct hg.nginx.org (docs/changes.xslt is already pre-generated).
WORKDIR /data/builder/debuild/nginx-$NGINX_VERSION/debian
RUN make PACKAGE_VENDOR="$VENDOR" MODULE_RELEASE_njs=3 XSLS="$PWD/../docs/changes.xsls" \
        rules-base rules-module-geoip rules-module-image-filter rules-module-njs rules-module-xslt

# 2c. In each tree: a changelog entry "+echo1" (the package version comes from
#     it, e.g. 1.25.5-1~bookworm+echo1), then build the binary packages.
ENV DEBFULLNAME="Echo home assignment build" DEBEMAIL=build@localhost
RUN for d in debuild-base debuild-module-geoip debuild-module-image-filter \
             debuild-module-njs debuild-module-xslt; do \
        cd $d/nginx-$NGINX_VERSION \
     && dch --newversion "$(dpkg-parsechangelog -S Version)+echo1" \
            --distribution "$(dpkg-parsechangelog -S Distribution)" --force-distribution \
            "Backport fixes for CVE-2025-23419 (13935cf9) and CVE-2026-42945 (524977e7)." \
     && DEB_BUILD_OPTIONS="parallel=$(nproc)" dpkg-buildpackage -b -us -uc \
     && cd ../..; \
    done

# 2d. Evidence in what we ship: each patch is in the series dpkg-source applied,
#     and both nginx binaries import SSL_SESSION_get0_hostname, which only the
#     CVE-2025-23419 fix calls. (dpkg-source un-applies the patches after the
#     build, so the source tree is not checked.) Behaviour: test/cve_test.py.
RUN src=debuild-base/nginx-$NGINX_VERSION \
 && for patch in CVE-2025-23419.patch CVE-2026-42945.patch; do \
        grep -x $patch $src/debian/patches/series || { echo "$patch not applied"; exit 1; }; \
    done \
 && for b in $src/debian/nginx/usr/sbin/nginx $src/debian/nginx/usr/sbin/nginx-debug; do \
        nm -D $b | grep SSL_SESSION_get0_hostname >/dev/null || { echo "CVE-2025-23419 fix missing from $b"; exit 1; }; \
        echo "$b: imports SSL_SESSION_get0_hostname"; \
    done \
 && for p in nginx nginx-module-geoip nginx-module-image-filter nginx-module-njs nginx-module-xslt; do \
        cp -v debuild-*/${p}_*.deb /out/; \
    done \
 && cd /out && sha256sum *.deb | tee SHA256SUMS

# Export only the packages.
FROM scratch AS export
COPY --from=builder /out/ /
