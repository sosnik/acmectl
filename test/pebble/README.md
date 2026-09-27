# Local Pebble

`bash test/pebble/run.sh` starts Let's Encrypt Pebble v2.10.1 and challtestsrv, checks that the ACME directory answers and advertises the `shortlived` profile, issues one HTTP-01 certificate for challtestsrv's bridge address, checks that PEM, and tears the stack down. The client is not modified. Nothing in this directory is a key or a certificate.

## Prerequisites

- bash
- Docker Engine and Docker Compose v2 (`docker compose`, not the `docker-compose` binary), with the daemon running
- `openssl` and `curl` on the host. On MSYS, `getone` is started with `PATH="/usr/bin:$PATH"` and the script exits if `/usr/bin/openssl` is missing. UCRT `openssl req -text` prints CRLF. `_identifiers` matches the SAN block only when `X509v3 Subject Alternative Name: ` is followed immediately by `\n`, so that CR drops the SAN. A normal `getone` on this machine, using the UCRT `openssl` on `PATH`, fails that way. CRLF tolerance belongs in the client and is not part of this test. A green run does not show that the `openssl` on `PATH` can issue the IP certificate. Linux `openssl` already prints LF, and `issue.sh` does not change `PATH` there.
- Python: `/usr/bin/python3` on MSYS (CPython, `sys.platform == cygwin`). On Linux, `python3`. `run.sh` exits before `compose up` if the interpreter it selected reports `sys.platform == win32`. The UCRT `python3` on `PATH` is that interpreter on MSYS and is not used. The same interpreter runs the directory probe and `getone`: it can spawn the `#!/usr/bin/env bash` hook and open a POSIX `SSL_CERT_FILE`. A Win32 interpreter does neither.

The images are `ghcr.io/letsencrypt/pebble` and `ghcr.io/letsencrypt/pebble-challtestsrv`, tag `2.10.1`, digest-pinned in `docker-compose.yml`. They are public. No client image is built.

## Run

From the repository root, or from any working directory:

```bash
bash test/pebble/run.sh
```

The script selects the interpreter above, exports `PYTHONDONTWRITEBYTECODE=1`, and creates a work directory under `${TMPDIR:-/tmp}`. It removes a leftover `acmectl-pebble` project, pulls the images, copies the listener CA out of the Pebble image, and publishes ports on `127.0.0.1` only. It waits until `https://127.0.0.1:${ACMECTL_DIR_PORT}/dir` returns `newOrder`, `newNonce`, and `meta.profiles.shortlived`, then runs `issue.sh`. On any exit it runs `docker compose down` and deletes the work directory. On failure it prints `$WORK/client.log` first, when that file exists. A missing `le.rsa.key` does not fail the run. Host ports already set in the environment are kept; otherwise they default to the table below. The bridge addresses are fixed.

Do not run `docker compose` by itself. Unset `${VAR:?}` values fail the parse instead of becoming an empty address.

Success prints:

```text
ip1 10.87.64.3 shortlived verify-ok
```

## CSR and the two challtestsrv addresses

The CSR is RSA, subject `/`, with one SAN `IP:10.87.64.3`. That is challtestsrv's bridge address. It is not `127.0.0.1`. The host cannot route to `10.87.64.3`, and the hook does not dial it.

One HTTP-01 listener is reached at two addresses:

| Who dials | Address |
| --- | --- |
| Hook `check` | `http://127.0.0.1:18445` (`ACMECTL_CHALLTESTSRV_HTTP`, container `:5002`) |
| Hook `POST /add-http01` and `POST /del-http01` | `http://127.0.0.1:18446` (`ACMECTL_CHALLTESTSRV_MGMT`, container `:8055`) |
| Pebble VA | `http://10.87.64.3:5002` |

The host check does not prove the bridge route. If the VA cannot dial `10.87.64.3`, `getone` fails and there is no PEM. `issue.sh` copies `http01-challtestsrv.sh` into the work directory and passes that absolute path to `--http`. The hook is not installed under `hooks/http/`.

## PEM checks

`issue.sh` runs:

```text
PATH="/usr/bin:$PATH" SSL_CERT_FILE=$WORK/pebble.minica.pem \
  $PY acmectl.py --config $WORK/acmectl.conf -e PEBBLE \
  getone ip1 --http $WORK/http01-challtestsrv.sh --profile shortlived
```

On MSYS, `issue.sh` sets that `PATH` for this process only, so `getone` runs `/usr/bin/openssl` instead of UCRT `openssl`. On Linux it does not set `PATH`. The generated config sets `WORKDIR` to that work directory, leaves `PROFILE` empty, and still defines `LE_PROD` and `LE_STAGING`. The directory URL is `https://127.0.0.1:${ACMECTL_DIR_PORT}/dir`. There is no `-t`. `SSL_CERT_FILE` is set only on that Python process, so a later `openssl verify` does not trust minica.

The run fails unless all of these hold:

- `$WORK/certs/ip1.rsa.crt` exists and is non-empty
- the client log contains `Requesting profile: shortlived`
- the client log does not contain `Let's Encrypt IP certificate; requesting the shortlived profile.`
- the leaf SAN text contains `IP Address:10.87.64.3` and does not contain `DNS:`
- `notAfter - notBefore` is 518399 seconds, from that Python's `datetime`, not from `date -d`
- `openssl verify -CAfile` the PEM from `https://127.0.0.1:${ACMECTL_MGMT_PORT}/roots/0` `-untrusted` the PEM from `/intermediates/0` succeeds. The leaf is not verified against minica
- `openssl x509 -checkend 0` succeeds

## Ports

| Host | Container | Who uses it |
| --- | --- | --- |
| `127.0.0.1:18443` (`ACMECTL_DIR_PORT`) | pebble `14000` | Directory probe and `getone`. URL `https://127.0.0.1:18443/dir` |
| `127.0.0.1:18444` (`ACMECTL_MGMT_PORT`) | pebble `15000` | Pebble management, including `/roots/0`, `/intermediates/0`, and `/root-keys/0` |
| `127.0.0.1:18445` (`ACMECTL_HTTP_PORT`) | challtestsrv `5002` | Hook `check`. Same listener the VA dials at `10.87.64.3:5002` |
| `127.0.0.1:18446` (`ACMECTL_CHALL_MGMT_PORT`) | challtestsrv `8055` | Hook management `POST /add-http01` and `POST /del-http01` |

Nothing is published on `0.0.0.0`. DNS `:8053`, TLS-ALPN `:5001`, and HTTPS-01 `:5003` stay unpublished. challtestsrv is started with `-https01 ""` and `-tlsalpn01 ""`.

| Address | Who |
| --- | --- |
| `10.87.64.2` | pebble, on bridge `10.87.64.0/24`. Not the CSR address. The listener certificate has no SAN for it. |
| `10.87.64.3` | challtestsrv. The CSR IP. The Pebble VA dials it on port 5002. The host cannot route to it. |
| `127.0.0.1` | Host loopback publishes only. Not an address for a CSR. Inside the pebble container it is pebble itself. |

## Do not trust this CA

Pebble's listener certificate is signed by `pebble.minica.pem`. The test copies that file out of the image with `docker cp` and passes it as `SSL_CERT_FILE` only on the directory probe and on `getone`. The private key is published in the Pebble repository, so anyone can mint a certificate this CA would verify. Do not install it into a system trust store or the Windows certificate store. The copy is deleted with the work directory. The management listener stays on loopback because it can serve the issuance root private key. The issued leaf is checked against that process's `/roots/0` and `/intermediates/0`, not against minica.

## Difference from the repository README

The "Testing with Pebble" section of `readme.md` tells you to add `https://localhost:14000/dir`, to put an address such as `127.0.0.1` in the CSR, and to serve the token on host port 5002, with challtestsrv management on host port 8055. That does not match this bridge. The VA dials the address written in the CSR from inside the pebble container, where `127.0.0.1` is pebble, not challtestsrv. Docker Desktop does not offer host networking for Linux containers. This stack's directory URL is `https://127.0.0.1:18443/dir`, which matches the listener certificate's `IP Address:127.0.0.1` SAN. The CSR names `10.87.64.3`. Host ports are 18443, 18444, 18445, and 18446.

The `shortlived` sentence in `readme.md` is the automatic rule: Let's Encrypt issues an IP certificate under that profile when the caller did not pass one, and the profile is not sent to any other directory on that path. It is not a description of an explicit `--profile`. This run passes `--profile shortlived`, leaves `PROFILE` empty, and fails unless the client log contains that request and the leaf span is 518399 seconds.
