#!/usr/bin/env bash
set -euo pipefail

: "${PY:?}"
: "${WORK:?}"
: "${REPO:?}"
: "${ROOT:?}"
: "${ACMECTL_IP:?}"
: "${ACMECTL_DIR_PORT:?}"
: "${ACMECTL_MGMT_PORT:?}"
: "${ACMECTL_CHALLTESTSRV_MGMT:?}"
: "${ACMECTL_CHALLTESTSRV_HTTP:?}"

# Listener certificate SAN for this client is iPAddress 127.0.0.1.
dir_url="https://127.0.0.1:${ACMECTL_DIR_PORT}/dir"
if [[ "$dir_url" != "https://127.0.0.1:${ACMECTL_DIR_PORT}/dir" ]] \
  || [[ "$dir_url" == *10.87.64.2* ]] \
  || [[ "$dir_url" == "https://pebble:14000/dir" ]]; then
  printf '%s\n' "refusing directory URL: ${dir_url}" >&2
  exit 1
fi

sed 's/\r$//' "$ROOT/http01-challtestsrv.sh" > "$WORK/http01-challtestsrv.sh"
chmod 755 "$WORK/http01-challtestsrv.sh"

cat > "$WORK/acmectl.conf" <<EOF
[general]
WORKDIR = ${WORK}
CURVE = secp256r1
RENEW_THRESHOLD = 30
DNS_HOOK = cloudns.sh
HTTP_HOOK = nginx.sh
LE_ACCOUNT_KEY = account.rsa.key
PROFILE =
CONTACT =
[endpoints]
LE_PROD = https://acme-v02.api.letsencrypt.org/directory
LE_STAGING = https://acme-staging-v02.api.letsencrypt.org/directory
PEBBLE = ${dir_url}
EOF

mkdir -p "$WORK/certs"
umask 077
openssl genrsa 4096 > "$WORK/account.rsa.key"
openssl genrsa 4096 > "$WORK/certs/ip1.rsa.key"
# A native Win32 openssl on MSYS rewrites a lone "/" into a Windows path.
# "//" is handed to that openssl as subject "/". Linux keeps "-subj /".
subj=/
if [[ -n ${MSYSTEM:-} ]]; then
  subj=//
fi
openssl req -new -sha256 \
  -key "$WORK/certs/ip1.rsa.key" \
  -subj "$subj" \
  -addext "subjectAltName = IP:${ACMECTL_IP}" \
  -out "$WORK/certs/ip1.rsa.csr"

# UCRT "req -text" ends the SAN header in \r\n. _identifiers matches
# "X509v3 Subject Alternative Name: " only when \n is next, so the CR
# drops the block before the value is read. MSYS openssl prints LF.
client_path=$PATH
if [[ -n ${MSYSTEM:-} ]]; then
  if [[ ! -x /usr/bin/openssl ]]; then
    printf '%s\n' "refusing MSYS getone without /usr/bin/openssl: UCRT openssl req -text is CRLF and _identifiers drops the SAN" >&2
    exit 1
  fi
  client_path="/usr/bin:${PATH}"
fi
PATH="$client_path" SSL_CERT_FILE="$WORK/pebble.minica.pem" "$PY" "$REPO/acmectl.py" \
  --config "$WORK/acmectl.conf" \
  -e PEBBLE \
  getone ip1 \
  --http "$WORK/http01-challtestsrv.sh" \
  --profile shortlived \
  > "$WORK/client.log" 2>&1

[[ -s "$WORK/certs/ip1.rsa.crt" ]]
grep -F 'Requesting profile: shortlived' "$WORK/client.log"
if grep -F "Let's Encrypt IP certificate; requesting the shortlived profile." "$WORK/client.log"; then
  printf '%s\n' "auto-select sentence must be absent" >&2
  exit 1
fi

openssl x509 -in "$WORK/certs/ip1.rsa.crt" -out "$WORK/leaf.pem"
"$PY" - "$WORK/leaf.pem" <<'PY'
import subprocess, sys
from datetime import datetime, timezone
pem = sys.argv[1]

def field(flag):
    out = subprocess.check_output(
        ["openssl", "x509", "-in", pem, "-noout", flag], text=True)
    text = out.split("=", 1)[1].strip()
    if text.endswith(" GMT"):
        text = text[:-4]
    return datetime.strptime(text, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)

span = int((field("-enddate") - field("-startdate")).total_seconds())
if span != 518399:
    raise SystemExit(f"lifetime {span} != 518399")
PY

san=$(openssl x509 -in "$WORK/leaf.pem" -noout -ext subjectAltName)
printf '%s\n' "$san" | grep -F "IP Address:${ACMECTL_IP}"
printf '%s\n' "$san" | grep -F 'DNS:' && exit 1 || true

curl --cacert "$WORK/pebble.minica.pem" -fsS \
  "https://127.0.0.1:${ACMECTL_MGMT_PORT}/roots/0" -o "$WORK/root.pem"
curl --cacert "$WORK/pebble.minica.pem" -fsS \
  "https://127.0.0.1:${ACMECTL_MGMT_PORT}/intermediates/0" -o "$WORK/intermediate.pem"
openssl verify -CAfile "$WORK/root.pem" -untrusted "$WORK/intermediate.pem" "$WORK/leaf.pem"
openssl x509 -in "$WORK/leaf.pem" -noout -checkend 0

printf '%s\n' "ip1 ${ACMECTL_IP} shortlived verify-ok"
