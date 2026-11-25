#!/usr/bin/env bash
# Functional test for CVE-2025-23419: TLSv1.3 session resumption across SNI
# virtual servers bypasses ssl_verify_client.
#
# Setup (same for both images): one nginx, two TLS servers on one port,
#   a.test (default_server) - requires a client cert from CA "A"
#   b.test                  - requires a client cert from CA "B"
# once in `http` (port 443) and once in `stream` (port 8443, TLS proxy module;
# SNI virtual servers in stream are new in 1.25.5). The upstream commit fixes
# both, in two separate functions, so both are tested.
# Attack: connect to a.test with a CA-A client cert, keep the TLSv1.3 session,
# then resume that session with SNI b.test and NO client cert.
#   vulnerable nginx -> resumes and serves b.test without its client cert
#   fixed nginx      -> rejects the handshake (alert access_denied)
#
# Controls, run on both images, so a failure means the attack and nothing else:
#   1. resuming a.test -> a.test works (resumption itself is not broken)
#   2. b.test with a CA-B client cert works (b.test itself is not broken)
#
# The test only counts if the attack SUCCEEDS on the original image: that is
# what proves the test can detect the vulnerability at all.
# The client is always the original image's openssl, so only the server differs.
#
# Usage: cve_2025_23419_test.sh <original-image> <patched-image>
set -euo pipefail
ORIG=${1:?usage: $0 <original-image> <patched-image>}
NEW=${2:?usage: $0 <original-image> <patched-image>}
CLIENT=$ORIG

work=$(mktemp -d)
net=cve-23419-$$
cleanup() {
    docker rm -f "$net-srv" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

# ---- test PKI: two independent CAs, one client cert from each -----------------
docker run --rm -v "$work:/w" -w /w --entrypoint sh "$CLIENT" -c '
set -e
for ca in A B; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Test CA $ca" \
      -keyout ca$ca.key -out ca$ca.crt 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=client-$ca" \
      -keyout client$ca.key -out client$ca.csr 2>/dev/null
  openssl x509 -req -in client$ca.csr -CA ca$ca.crt -CAkey ca$ca.key \
      -CAcreateserial -days 2 -out client$ca.crt 2>/dev/null
done
printf "subjectAltName=DNS:a.test,DNS:b.test\n" > san.ext
openssl req -newkey rsa:2048 -nodes -subj "/CN=a.test" \
    -keyout server.key -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA caA.crt -CAkey caA.key -CAcreateserial \
    -days 2 -extfile san.ext -out server.crt 2>/dev/null
chmod 644 *.key'

cat > "$work/nginx.conf" <<'EOF'
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
EOF

# Runs in the client container. Prints one "RESULT <module>-<check> <outcome>" line per check.
cat > "$work/client.sh" <<'EOF'
#!/bin/sh
srv=$1
get() { printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$1"; }
# s_client <sni> [extra args...] -> outcome: rejected | served:<host> | other
probe() {
    sni=$1; shift
    out=$(get "$sni" | timeout 10 openssl s_client -tls1_3 -connect "$srv:$port" \
          -servername "$sni" -ign_eof "$@" 2>&1)
    reused=new; echo "$out" | grep -q '^Reused, TLSv1.3' && reused=reused
    body=$(echo "$out" | grep -o 'served:[a-z.]*' | head -1)
    if [ -n "$body" ]; then echo "$body($reused)"
    elif echo "$out" | grep -qi 'alert access denied'; then echo "rejected(access_denied)"
    else echo "other"; echo "$out" | tail -5 >&2; fi
}
port=443
for i in $(seq 40); do    # wait until nginx answers
    case $(probe a.test -cert /w/clientA.crt -key /w/clientA.key 2>/dev/null) in served:*) break ;; esac
    sleep 0.25
done
for m in http:443 stream:8443; do
    mod=${m%:*}; port=${m#*:}
    # Full handshake to a.test with a CA-A cert; save the TLSv1.3 session.
    echo "RESULT $mod-setup     $(probe a.test -cert /w/clientA.crt -key /w/clientA.key -sess_out /tmp/$mod.pem)"
    echo "RESULT $mod-control-1 $(probe a.test -sess_in /tmp/$mod.pem)"
    echo "RESULT $mod-control-2 $(probe b.test -cert /w/clientB.crt -key /w/clientB.key)"
    echo "RESULT $mod-attack    $(probe b.test -sess_in /tmp/$mod.pem)"
done
EOF
chmod +x "$work/client.sh"

run() {   # run <image> -> RESULT lines
    docker network create "$net" >/dev/null
    docker run -d --name "$net-srv" --network "$net" -v "$work:/w:ro" \
        -v "$work/nginx.conf:/etc/nginx/nginx.conf:ro" "$1" >/dev/null
    docker run --rm --network "$net" -v "$work:/w:ro" --entrypoint sh "$CLIENT" \
        /w/client.sh "$net-srv" | grep '^RESULT'
    docker logs "$net-srv" 2>&1 | grep -i 'handshake rejected' | sed 's/, client.*//' | tail -2 | sed 's/^/  nginx: /' || true
    docker rm -f "$net-srv" >/dev/null; docker network rm "$net" >/dev/null
}

fail=0
check() {  # check <label> <results> <check> <expected>
    got=$(echo "$2" | awk -v c="$3" '$2==c {print $3}')
    if [ "$got" = "$4" ]; then echo "  PASS  $3: $got"
    else echo "  FAIL  $3: got '$got', expected '$4'"; fail=1; fi
}

echo "== original: $ORIG"
r=$(run "$ORIG"); echo "$r" | grep -v '^RESULT' || true
for mod in http stream; do
check orig "$r" $mod-setup     "served:a.test(new)"
check orig "$r" $mod-control-1 "served:a.test(reused)"
check orig "$r" $mod-control-2 "served:b.test(new)"
check orig "$r" $mod-attack    "served:b.test(reused)"     # vulnerable: B served without B's cert
done

echo "== patched:  $NEW"
r=$(run "$NEW"); echo "$r" | grep -v '^RESULT' || true
for mod in http stream; do
check new "$r" $mod-setup     "served:a.test(new)"
check new "$r" $mod-control-1 "served:a.test(reused)"
check new "$r" $mod-control-2 "served:b.test(new)"
check new "$r" $mod-attack    "rejected(access_denied)"   # fixed: cross-SNI resumption refused
done

if [ $fail = 0 ]; then
    echo "CVE-2025-23419: original is exploitable, patched rejects the attack - PASS"
else
    echo "CVE-2025-23419 test FAILED" >&2; exit 1
fi
