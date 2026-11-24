#!/usr/bin/env bash
# Build zlib from upstream source and package it as drop-in replacements for
# Debian's zlib1g / zlib1g-dev. Runs inside the builder (debian:bookworm-slim).
#
# Usage: build-zlib.sh <out-dir>
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"
. "$here/versions.env"

out=${1:?usage: build-zlib.sh <out-dir>}
work=/tmp/zlib-build
mkdir -p "$out" "$work"
cd "$work"

ARCH=$(dpkg --print-architecture)                    # e.g. arm64 / amd64
TRIPLET=$(dpkg-architecture -qDEB_HOST_MULTIARCH)    # e.g. aarch64-linux-gnu

log "Fetching zlib $ZLIB_VERSION"
fetch_verified "$ZLIB_URL" "$ZLIB_SHA256" "$ZLIB_GPG_FPR" \
    "$here/keys/zlib-madler.asc" "zlib-$ZLIB_VERSION.tar.gz"
tar xzf "zlib-$ZLIB_VERSION.tar.gz"
cd "zlib-$ZLIB_VERSION"

log "Evidence: the CVE-2026-27171 check is present in the source we build"
fix=$(grep -n -A2 'crc32_combine_gen64(z_off64_t len2)' crc32.c)
echo "$fix"
case $fix in *'if (len2 < 0)'*) ;; *) echo "negative-length check missing from crc32.c" >&2; exit 1 ;; esac

log "Configure + build (Debian hardening flags from dpkg-buildflags)"
eval "$(dpkg-buildflags --export=sh)"
# zlib's hand-written configure ignores CPPFLAGS, so fold them (-D_FORTIFY_SOURCE=2)
# into CFLAGS, and pass LDFLAGS (-z relro) to the shared-library link too.
export CFLAGS="$CPPFLAGS $CFLAGS"
export LDSHARED="gcc -shared -Wl,-soname,libz.so.1,--version-script,zlib.map $LDFLAGS"
# Same split as Debian: runtime .so in /lib/<triplet> (that is the exact path
# zlib1g owns; dpkg treats /lib and /usr/lib as different paths even on
# merged-/usr), dev files in /usr/lib/<triplet>.
./configure --prefix=/usr \
            --libdir="/usr/lib/$TRIPLET" \
            --sharedlibdir="/lib/$TRIPLET" \
            --includedir=/usr/include
make -j"$(nproc)"

log "Upstream test suite"
make test

log "ABI check: every symbol exported by Debian's libz must still exist"
old=$(readlink -f "/lib/$TRIPLET/libz.so.1")          # builder's Debian 1.2.13
new=$(readlink -f "libz.so.$ZLIB_VERSION")
nm -D --defined-only --with-symbol-versions "$old" | awk '{print $3}' | sort > /tmp/abi.old
nm -D --defined-only --with-symbol-versions "$new" | awk '{print $3}' | sort > /tmp/abi.new
missing=$(comm -23 /tmp/abi.old /tmp/abi.new)
if [ -n "$missing" ]; then
    echo "ABI BREAK - symbols missing in zlib $ZLIB_VERSION:" >&2; echo "$missing" >&2; exit 1
fi
echo "old: $(wc -l < /tmp/abi.old) symbols, new: $(wc -l < /tmp/abi.new) symbols, removed: 0"
echo "added: $(comm -13 /tmp/abi.old /tmp/abi.new | tr '\n' ' ')"
objdump -p "$new" | grep SONAME

# Lowest glibc symbol version the library needs -> accurate libc6 dependency.
GLIBC_MIN=$(objdump -T "$new" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1)

log "Staging packages"
rt=$work/pkg-zlib1g
dev=$work/pkg-zlib1g-dev
rm -rf "$rt" "$dev"
install -Dm644 "libz.so.$ZLIB_VERSION" "$rt/lib/$TRIPLET/libz.so.$ZLIB_VERSION"
ln -s "libz.so.$ZLIB_VERSION" "$rt/lib/$TRIPLET/libz.so.1"
install -Dm644 LICENSE "$rt/usr/share/doc/zlib1g/copyright"
install -Dm644 zlib.h  "$dev/usr/include/zlib.h"
install -Dm644 zconf.h "$dev/usr/include/zconf.h"
install -Dm644 libz.a  "$dev/usr/lib/$TRIPLET/libz.a"
install -Dm644 zlib.pc "$dev/usr/lib/$TRIPLET/pkgconfig/zlib.pc"
ln -s "/lib/$TRIPLET/libz.so.1" "$dev/usr/lib/$TRIPLET/libz.so"
install -Dm644 LICENSE "$dev/usr/share/doc/zlib1g-dev/copyright"

# Strip like a release build, but keep the build-id so it stays traceable.
strip --strip-unneeded "$rt/lib/$TRIPLET/libz.so.$ZLIB_VERSION"

mkdir -p "$rt/DEBIAN" "$dev/DEBIAN"
# Source stays "zlib" on purpose: scanners must keep seeing this as zlib.
# Renaming it would hide the package from them - that is not a fix.
cat > "$rt/DEBIAN/control" <<EOF
Package: zlib1g
Source: zlib
Version: $ZLIB_DEB_VERSION
Architecture: $ARCH
Maintainer: Echo home assignment build <build@localhost>
Installed-Size: $(du -sk "$rt" | cut -f1)
Depends: libc6 (>= $GLIBC_MIN)
Provides: libz1
Breaks: libxml2 (<< 2.7.6.dfsg-2), texlive-binaries (<< 2009-12)
Multi-Arch: same
Section: libs
Priority: optional
Homepage: https://zlib.net/
Description: compression library - runtime (upstream $ZLIB_VERSION rebuild)
 zlib $ZLIB_VERSION built from upstream source. Replaces Debian's
 1:1.2.13.dfsg-1 to fix CVE-2026-27171 (crc32_combine infinite loop on
 negative length) without introducing CVE-2026-85091 (zlib 1.3.1.2-1.3.2).
EOF
# Let other packages built against us compute dependencies, and run ldconfig.
echo "libz 1 zlib1g (>= $ZLIB_DEB_VERSION)" > "$rt/DEBIAN/shlibs"
echo "activate-noawait ldconfig" > "$rt/DEBIAN/triggers"

cat > "$dev/DEBIAN/control" <<EOF
Package: zlib1g-dev
Source: zlib
Version: $ZLIB_DEB_VERSION
Architecture: $ARCH
Maintainer: Echo home assignment build <build@localhost>
Installed-Size: $(du -sk "$dev" | cut -f1)
Depends: zlib1g (= $ZLIB_DEB_VERSION), libc6-dev | libc-dev
Provides: libz-dev
Multi-Arch: same
Section: libdevel
Priority: optional
Homepage: https://zlib.net/
Description: compression library - development (upstream $ZLIB_VERSION rebuild)
 Headers and static library for zlib $ZLIB_VERSION.
EOF

log "Building .deb files"
debver=${ZLIB_DEB_VERSION#*:}                 # file names carry no epoch
dpkg-deb --root-owner-group --build "$rt"  "$out/zlib1g_${debver}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$dev" "$out/zlib1g-dev_${debver}_${ARCH}.deb"
dpkg-deb -I "$out/zlib1g_${debver}_${ARCH}.deb" | sed -n '/Package:/,/Description/p'
dpkg-deb -c "$out/zlib1g_${debver}_${ARCH}.deb"
(cd "$out" && sha256sum zlib1g*.deb | tee zlib.sha256)
