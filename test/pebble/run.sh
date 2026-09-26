#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"
REPO=$(cd "$ROOT/../.." && pwd)
export ROOT REPO

export PYTHONDONTWRITEBYTECODE=1
export ACMECTL_SUBNET=10.87.64.0/24
export ACMECTL_PEBBLE_IP=10.87.64.2
export ACMECTL_IP=10.87.64.3
export ACMECTL_DIR_PORT="${ACMECTL_DIR_PORT:-18443}"
export ACMECTL_MGMT_PORT="${ACMECTL_MGMT_PORT:-18444}"
export ACMECTL_HTTP_PORT="${ACMECTL_HTTP_PORT:-18445}"
export ACMECTL_CHALL_MGMT_PORT="${ACMECTL_CHALL_MGMT_PORT:-18446}"
export ACMECTL_CHALLTESTSRV_HTTP="http://127.0.0.1:${ACMECTL_HTTP_PORT}"
export ACMECTL_CHALLTESTSRV_MGMT="http://127.0.0.1:${ACMECTL_CHALL_MGMT_PORT}"

if [[ -x /usr/bin/python3 ]] && /usr/bin/python3 -c 'import sys; raise SystemExit(0 if sys.platform == "cygwin" else 1)'; then
  PY=/usr/bin/python3
else
  PY=python3
fi
"$PY" -c 'import sys; raise SystemExit(0 if sys.platform != "win32" else 1)' \
  || { printf '%s\n' "refusing Win32 Python ($PY); on MSYS use /usr/bin/python3" >&2; exit 1; }
export PY

WORK=$(mktemp -d "${TMPDIR:-/tmp}/acmectl-pebble.XXXXXX")
export WORK

# Same pinned image as docker-compose.yml, so the extracted listener CA is the
# one that image will use to serve TLS.
PEBBLE_IMAGE=ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199

compose() {
  docker compose -p acmectl-pebble -f "$ROOT/docker-compose.yml" "$@"
}

snapshot() {
  (
    cd "$REPO"
    paths=()
    for p in acmectl.py acme_hooked.py acmectl.conf readme.md TODO.md \
             hooks certs state by-hook le.rsa.key; do
      [[ -e "$p" ]] && paths+=("$p")
    done
    ((${#paths[@]})) || exit 0
    # GNU find/xargs: MSYS coreutils and Linux findutils.
    find "${paths[@]}" -type f -print0 | sort -z | xargs -0 -r sha256sum
  )
}

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    compose logs --no-color --tail 200 pebble challtestsrv >&2 || true
    if [[ -f "$WORK/client.log" ]]; then
      printf '%s\n' "----- $WORK/client.log -----" >&2
      cat "$WORK/client.log" >&2 || true
    fi
  fi
  compose down -v --remove-orphans --timeout 10 || true
  if [[ $rc -eq 0 && -f "$WORK/tree.sha" ]]; then
    now=$(snapshot || true)
    if [[ "$now" != "$(cat "$WORK/tree.sha")" ]]; then
      echo "repo tree changed during the test" >&2
      rc=1
    fi
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT
# A kill during the wait must still run the EXIT trap.
trap 'exit 1' HUP INT TERM

compose down -v --remove-orphans --timeout 10 || true
snapshot > "$WORK/tree.sha"

compose pull

cid=$(docker create "$PEBBLE_IMAGE")
cp_rc=0
docker cp "$cid:/test/certs/pebble.minica.pem" "$WORK/pebble.minica.pem" || cp_rc=$?
docker cp "$cid:/test/certs/localhost/cert.pem" "$WORK/listener.pem" || cp_rc=$?
docker rm "$cid"
[[ "$cp_rc" -eq 0 ]]

san=$(openssl x509 -in "$WORK/listener.pem" -noout -ext subjectAltName)
printf '%s\n' "$san" | grep -F 'DNS:localhost'
printf '%s\n' "$san" | grep -F 'DNS:pebble'
printf '%s\n' "$san" | grep -F 'IP Address:127.0.0.1'

compose up -d pebble challtestsrv

export ACMECTL_PROBE_URL="https://127.0.0.1:${ACMECTL_DIR_PORT}/dir"
i=0
until SSL_CERT_FILE="$WORK/pebble.minica.pem" "$PY" - <<'PY'
import json, os, urllib.request
url = os.environ["ACMECTL_PROBE_URL"]
with urllib.request.urlopen(url, timeout=3) as resp:
    body = json.load(resp)
assert "newOrder" in body and "newNonce" in body, body
profiles = body.get("meta", {}).get("profiles", {})
assert "shortlived" in profiles, profiles
print("directory ok", list(profiles))
PY
do
  i=$((i + 1))
  if [[ $i -ge 60 ]]; then
    printf '%s\n' "directory probe failed after ${i} attempts" >&2
    exit 1
  fi
  sleep 1
done
