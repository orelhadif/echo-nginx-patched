#!/usr/bin/env bash
# Build the nginx packages with nginx.org's OWN packaging recipe (pkg-oss, the
# same tag the original nginx:1.25-bookworm packages came from), adding only:
#   1. our backport patch(es) from build/patches/  (pkg-oss puts every
#      contrib/src/nginx/*.patch into debian/patches/series - quilt applies it)
#   2. a changelog entry "+echo1" so the packages are identifiable as our rebuild
#   3. our name as Maintainer (we built it, not nginx.org)
# Everything else - configure arguments, compiler flags, file layout, maintainer
# scripts, stripping, permissions - is pkg-oss's debian/rules + debhelper.
#
# Runs inside the builder, after our zlib1g/zlib1g-dev 1.4 are installed.
# Usage: build-nginx.sh <out-dir>
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"
. "$here/versions.env"

out=${1:?usage: build-nginx.sh <out-dir>}
mkdir -p "$out"
MODULES="geoip image-filter njs xslt"          # the four modules the original image ships
VENDOR="Echo home assignment build <build@localhost>"

# nginx.org builds pkg-oss checked out at this path; it ends up in `nginx -V`
# (-ffile-prefix-map), so using the same path keeps `nginx -V` identical.
ROOT=/data/builder/debuild/nginx-$NGINX_VERSION

log "Our zlib must be the one we compile against"
[ "$(dpkg-query -W -f='${Version}' zlib1g-dev)" = "$ZLIB_DEB_VERSION" ] \
    || { echo "zlib1g-dev $ZLIB_DEB_VERSION not installed in builder" >&2; exit 1; }

log "Fetching pkg-oss $PKGOSS_TAG (nginx.org packaging recipe)"
mkdir -p "$ROOT"
fetch_sha256 "$PKGOSS_URL" "$PKGOSS_SHA256" /tmp/pkg-oss.tar.gz
tar xzf /tmp/pkg-oss.tar.gz -C "$ROOT" --strip-components=1

# Sources go where pkg-oss looks for them (contrib/tarballs), so it does not
# download them itself. pkg-oss then still checks them against its own SHA512SUMS.
log "Fetching sources into pkg-oss contrib/tarballs"
TB=$ROOT/contrib/tarballs; mkdir -p "$TB"
fetch_verified "$NGINX_URL" "$NGINX_SHA256" "$NGINX_GPG_FPR" \
    "$here/keys/nginx-arut.asc" "$TB/nginx-$NGINX_VERSION.tar.gz"
# pkg-oss pins njs to an hg.nginx.org archive, but that server is gone. We use
# the GitHub tag archive (same tree), pinned by our own sha256, and mark it as
# checked for pkg-oss (its SHA512 is of the old hg archive, a different tarball).
fetch_sha256 "$NJS_URL" "$NJS_SHA256" "$TB/njs-$NJS_VERSION.tar.gz"
touch "$ROOT/contrib/.sum-njs"
# QuickJS: pkg-oss fetches it from GitHub with git and checks the commit hash itself.

log "Adding our patches to the pkg-oss nginx patch series"
cp -v "$here"/patches/*.patch "$ROOT/contrib/src/nginx/"

log "Generating debian/ source trees (pkg-oss: make rules-*)"
cd "$ROOT/debian"
# MODULE_RELEASE_njs=3: the original image ships nginx-module-njs ...-3~bookworm.
# XSLS: pkg-oss would download xslscript (from the defunct hg.nginx.org) only to
# regenerate docs/changes.xslt, which pkg-oss already ships pre-generated. Pointing
# XSLS at an existing, equally old file tells make that nothing needs regenerating.
make PACKAGE_VENDOR="$VENDOR" MODULE_RELEASE_njs=3 XSLS="$ROOT/docs/changes.xsls" \
     rules-base $(printf 'rules-module-%s ' $MODULES)

log "Changelog entry for our rebuild (+echo1)"
export DEBFULLNAME="${VENDOR% <*}" DEBEMAIL=build@localhost
for d in debuild-base $(printf 'debuild-module-%s ' $MODULES); do
    (cd "$d/nginx-$NGINX_VERSION"
     v=$(dpkg-parsechangelog -S Version)
     dch --newversion "$v+echo1" --distribution "$(dpkg-parsechangelog -S Distribution)" \
         --force-distribution \
         "Backport fix for CVE-2025-23419 (nginx commit 13935cf9, from 1.27.4/1.26.3)."
     echo "$d: $(dpkg-parsechangelog -S Version)")
done

log "Building packages (dpkg-buildpackage; quilt applies the patch with fuzz 0)"
for d in debuild-base $(printf 'debuild-module-%s ' $MODULES); do
    (cd "$d/nginx-$NGINX_VERSION" && DEB_BUILD_OPTIONS="parallel=$(nproc)" dpkg-buildpackage -b -us -uc)
done

log "Evidence: the CVE-2025-23419 fix is in what we ship"
src=debuild-base/nginx-$NGINX_VERSION
# (dpkg-source un-applies quilt patches after the build, so check the series and
# the compiled binaries, not the source tree.)
grep -x CVE-2025-23419.patch "$src/debian/patches/series"
for b in "$src"/debian/nginx/usr/sbin/nginx "$src"/debian/nginx/usr/sbin/nginx-debug; do
    sym=$(nm -D "$b" | grep SSL_SESSION_get0_hostname || true)
    echo "$(basename "$b"): ${sym:-MISSING}"
    [ -n "$sym" ] || { echo "backport missing from $b" >&2; exit 1; }
done

log "Collecting packages"
for p in nginx $(printf 'nginx-module-%s ' $MODULES); do
    cp -v $(find . -maxdepth 2 -name "${p}_*.deb") "$out/"
done
(cd "$out" && sha256sum nginx*.deb | tee nginx.sha256)
dpkg-deb -I "$out"/nginx_*.deb | sed -n '/Package:/,/Description/p'
