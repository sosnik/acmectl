#!/usr/bin/env bash
#
# acme-hooked - a script to issue TLS certificates via ACME
# Copyright (C) 2015-2022 The acme-hooked authors
# Copyright (C) 2023-2026 Nikita Sosnik
# Licensed under the MIT license, see LICENSE.
#
# For use with CloudNS: https://www.cloudns.net/
# dependencies: curl (duh)

umask 077

# load config; required values: API_URL, SUB_AUTH_USER, AUTH_PASSWORD
if [ ! -f "$PWD/hooks/dns/cloudns.conf" ] && { [ -z "$API_URL" ] || [ -z "$SUB_AUTH_USER" ] || [ -z "$AUTH_PASSWORD" ]; }; then
  echo "Missing required configuration values. Either create ./cloudns.conf or set API_URL, SUB_AUTH_USER, and AUTH_PASSWORD in the environment."
  exit 1
fi
. "$PWD/hooks/dns/cloudns.conf"

die()
{
  echo "[hook script] $@"
  exit 1
}

setup()
{
  domain="$1" 
  token="$2"
  content="$3"

  # add challenge for the given domain
  # also save the record ID, will need it to delete the record later
  curl -s -X POST "${API_URL}/add-record.json" \
    -d "sub-auth-user=${SUB_AUTH_USER}&auth-password=${AUTH_PASSWORD}&domain-name=${VALIDATION_ZONE}&record-type=TXT&host=&record=${content}&ttl=60" \
    | grep -o -e "[0-9]*" > "$PWD/state/${content}.id" || { result=$?; if [ $result -ne 0 ]; then die "Failed to add challenge for ${domain}"; fi; }
}

activate()
{
  # make challenge(s) accessible to ACSD server
  : # noop
}

check()
{
  domain="$1"
  token="$2"
  content="$3"

  # use cloudflare's DoH to check if the record is available; retry every 5 seconds for up to an hour (aligns with acme-hooked _poll_until_not)

  tries=1 
  while [ $tries -lt 3600 ]; 
  do
    curl -A "acmectl" -s -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=_acme-challenge.${domain}&type=TXT" | grep -q "${content}"
    if [ $? -eq 0 ]; then
      return 0
    fi
    tries=$(($tries + 5))
    sleep 5
  done
  if [ $tries -gt 3598 ]; then
    die "[hook script] Failed to check challenge for ${domain} after ${($tries / 5)} attempts."
  fi
}

remove()
{
  domain="$1"
  token="$2"
  content="$3"

  # remove the challenges for the given domain
  if [ -f "$PWD/state/${content}.id" ]; then
  
    curl -s -X POST "${API_URL}/delete-record.json" \
      -d "sub-auth-user=${SUB_AUTH_USER}&auth-password=${AUTH_PASSWORD}&domain-name=${VALIDATION_ZONE}&record-id=$(cat "$PWD/state/${content}.id")" \
      || die "Failed to remove challenge for ${domain}"

    rm "$PWD/state/${content}.id" > /dev/null 2>&1

  fi
}

finish()
{
  # finalize cleanup after all challenges are removed
  : # noop
}

write()
{
  # read certificate from stdin and process it
  # any output of this function is echoed by acme_hooked
  # the CSR path is passed as the first argument
  echo $1 
  certname="$(basename $1 .csr)"
  echo $certname
  # save certificate to $PWD/certs/<certname>.crt
  if [ -f "$PWD/certs/${certname}.crt" ]; then
    mv "$PWD/certs/${certname}.crt" "$PWD/certs/${certname}.crt.bak" > /dev/null 2>&1 || true # backup existing cert if it exists
  fi
  # write new cert
  cat > "$PWD/certs/${certname}.crt"
}


[[ $# -ge 1 ]] || die 'Missing arguments.'
if [[ "$1" == 'setup' ]]; then
  [[ $# == 4 ]] || die 'Wrong number of arguments.'
  setup "$2" "$3" "$4"
elif [[ "$1" == 'activate' ]]; then
  [[ $# == 1 ]] || die 'Wrong number of arguments.'
  activate
elif [[ "$1" == 'check' ]]; then
  [[ $# == 4 ]] || die 'Wrong number of arguments.'
  check "$2" "$3" "$4"
elif [[ "$1" == 'remove' ]]; then
  [[ $# == 4 ]] || die 'Wrong number of arguments.'
  remove "$2" "$3" "$4"
elif [[ "$1" == 'finish' ]]; then
  [[ $# == 1 ]] || die 'Wrong number of arguments.'
  finish
elif [[ "$1" == 'write' ]]; then
  [[ $# == 2 ]] || die 'Wrong number of arguments.'
  write "$2"
else
  die "Unknown command: $1"
fi