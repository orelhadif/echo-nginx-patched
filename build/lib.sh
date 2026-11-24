# Shared helpers for the build scripts (sourced, not executed).
set -euo pipefail

log() { printf '\n==> %s\n' "$*"; }

# fetch_verified URL SHA256 GPG_FPR KEYFILE DEST
# Downloads a tarball and its .asc, then refuses to continue unless both the
# pinned sha256 and the upstream signature (from a pinned key) check out.
fetch_verified() {
    local url=$1 sha=$2 fpr=$3 keyfile=$4 dest=$5
    curl -fsSL --retry 3 -o "$dest" "$url"
    curl -fsSL --retry 3 -o "$dest.asc" "$url.asc"

    echo "$sha  $dest" | sha256sum -c -

    local gh; gh=$(mktemp -d)
    gpg --homedir "$gh" -q --import "$keyfile"
    # --status-fd lets us check WHICH key signed, not just "a good signature".
    gpg --homedir "$gh" --status-fd 1 --verify "$dest.asc" "$dest" 2>/dev/null \
        | grep -q "^\[GNUPG:\] VALIDSIG $fpr " \
        || { echo "GPG signature check FAILED for $dest" >&2; exit 1; }
    echo "gpg: good signature from $fpr"
    rm -rf "$gh"
}

# fetch_sha256 URL SHA256 DEST - for sources upstream does not sign.
fetch_sha256() {
    curl -fsSL --retry 3 -o "$3" "$1"
    echo "$2  $3" | sha256sum -c -
}
