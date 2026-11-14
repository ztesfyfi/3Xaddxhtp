#!/usr/bin/env bash
# One-command launcher for the unattended 3x-ui XHTTP H2/H3 batch installer.
set -Eeuo pipefail
umask 077
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required." >&2; exit 1; }
SCRIPT="$(mktemp /tmp/3xaddxhttp.XXXXXX.sh)"
trap 'rm -f "$SCRIPT"' EXIT
URL="https://raw.githubusercontent.com/ztesfyfi/3Xaddxhtp/main/add-xhttp-pairs-v2.sh"
curl --fail --location --silent --show-error "$URL" -o "$SCRIPT"
chmod 700 "$SCRIPT"
bash "$SCRIPT" "$@"
