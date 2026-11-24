#!/usr/bin/env bash
# Collects the evidence behind the VEX statements, from the IMAGES themselves
# (not from our build logs), for the original and the patched image side by side.
#
#   CVE-2026-27171 (zlib):  which libz the image ships and nginx actually loads,
#                           and how crc32_combine() behaves on a negative length
#                           (1.2.13: never returns; 1.4: returns 0).
#   CVE-2025-23419 (nginx): the backported fix makes nginx call
#                           SSL_SESSION_get0_hostname(); the vulnerable binary
#                           never imports that OpenSSL function.
#
# Usage: vex/evidence.sh [ORIG_IMAGE] [NEW_IMAGE]   (needs only docker)
# No exploit is run: the zlib probe calls the public API with len2 = -1.
set -euo pipefail
ORIG=${1:-nginx:1.25-bookworm}
NEW=${2:-echo-nginx:1.25-bookworm-patched}
HERE=$(cd "$(dirname "$0")" && pwd)

# The probe is compiled inside each image against that image's own zlib headers
# (orig: Debian zlib1g-dev 1.2.13; new: our zlib1g-dev 1.4 from out/).
PROBE='#include <stdio.h>
#include <zlib.h>
int main(void) {
  printf("zlibVersion() = %s\n", zlibVersion());
  fflush(stdout);
  uLong r = crc32_combine(0x12345678UL, 0x9abcdef0UL, (z_off_t)-1);
  printf("crc32_combine(len2 = -1) returned 0x%lx\n", r);
  return 0;
}'

for img in "$ORIG" "$NEW"; do
  echo "################ $img"
  docker image inspect "$img" --format 'image id: {{.Id}}'
  dev=""
  [ "$img" = "$NEW" ] && dev="/debs/zlib1g-dev_*_\$(dpkg --print-architecture).deb"
  docker run --rm --entrypoint bash -v "$HERE/../out:/debs:ro" -e PROBE="$PROBE" "$img" -c "
    set -e
    echo '== CVE-2026-27171: zlib package and library in the image'
    dpkg-query -W -f='\${Package} \${Version}\n' zlib1g
    ls -l /usr/lib/\$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || uname -m)-linux-gnu/libz.so.1* 2>/dev/null || ls -l /usr/lib/*/libz.so.1*

    echo '== CVE-2026-27171: libz mapped into the running nginx master'
    nginx 2>/dev/null; sleep 1
    grep -o '/[^ ]*libz[^ ]*' /proc/\$(cat /run/nginx.pid)/maps | sort -u
    nginx -s quit 2>/dev/null; sleep 1

    echo '== CVE-2025-23419: SSL_SESSION_get0_hostname in the nginx binaries'
    for b in /usr/sbin/nginx /usr/sbin/nginx-debug; do
      printf '%s: %s occurrence(s)\n' \$b \$(grep -c SSL_SESSION_get0_hostname \$b || true)
    done
    nginx -v 2>&1

    echo '== CVE-2026-27171: behaviour probe (compiled against this image s zlib)'
    apt-get update -qq >/dev/null
    apt-get install -qq -y --no-install-recommends gcc libc6-dev ${dev:-zlib1g-dev} >/dev/null 2>&1
    printf '%s\n' \"\$PROBE\" > /tmp/p.c
    gcc -O0 -o /tmp/p /tmp/p.c -lz
    set +e
    timeout 10 /tmp/p; rc=\$?
    [ \$rc = 124 ] && echo 'probe: still running after 10s -> killed (infinite loop, VULNERABLE)'
    [ \$rc = 0 ] && echo 'probe: returned immediately (FIXED)'
    true
  "
  echo
done
