#!/usr/bin/env bash
set -euo pipefail

die() { printf '%s\n' "$*" >&2; exit 1; }

: "${ACMECTL_CHALLTESTSRV_MGMT:?}"
: "${ACMECTL_CHALLTESTSRV_HTTP:?}"

post() {
  curl --fail-with-body --silent --show-error \
    --header 'Content-Type: application/json' \
    --data "$2" \
    "${ACMECTL_CHALLTESTSRV_MGMT}$1" >/dev/null
}

setup() {
  local domain=$1 token=$2 content=$3
  post /add-http01 "$(printf '{"token":"%s","content":"%s"}' "$token" "$content")"
}

activate() { :; }

check() {
  # $domain is accepted because the client always passes it.
  # The dial is ACMECTL_CHALLTESTSRV_HTTP (127.0.0.1:<published HTTP port>),
  # not http://$domain:5002. The VA dials the CSR address on the bridge.
  local domain=$1 token=$2 content=$3
  local i=0 body
  while [[ $i -lt 10 ]]; do
    body=$(curl --fail-with-body --silent --show-error \
      "${ACMECTL_CHALLTESTSRV_HTTP}/.well-known/acme-challenge/${token}" || true)
    [[ "$body" == "$content" ]] && return 0
    i=$((i + 1))
    sleep 1
  done
  die "HTTP-01 body at ${ACMECTL_CHALLTESTSRV_HTTP} did not match"
}

remove() {
  local domain=$1 token=$2 content=$3
  post /del-http01 "$(printf '{"token":"%s"}' "$token")"
}

finish() { :; }

write() {
  local csrfile=$1
  cat > "${csrfile%.csr}.crt"
}

[[ $# -ge 1 ]] || die 'Missing arguments.'
case $1 in
  setup)    [[ $# -eq 4 ]] || die 'Wrong number of arguments.'; setup "$2" "$3" "$4" ;;
  activate) [[ $# -eq 1 ]] || die 'Wrong number of arguments.'; activate ;;
  check)    [[ $# -eq 4 ]] || die 'Wrong number of arguments.'; check "$2" "$3" "$4" ;;
  remove)   [[ $# -eq 4 ]] || die 'Wrong number of arguments.'; remove "$2" "$3" "$4" ;;
  finish)   [[ $# -eq 1 ]] || die 'Wrong number of arguments.'; finish ;;
  write)    [[ $# -eq 2 ]] || die 'Wrong number of arguments.'; write "$2" ;;
  *) die "Unknown command: $1" ;;
esac
