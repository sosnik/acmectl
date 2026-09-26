# Local Pebble

`bash test/pebble/run.sh` starts Let's Encrypt Pebble v2.10.1 and challtestsrv, checks that the ACME directory answers and advertises the `shortlived` profile, and tears the stack down. The client is not modified. Nothing in this directory is a key or a certificate.

## Prerequisites

- bash
- Docker Engine and Docker Compose v2 (`docker compose`, not the `docker-compose` binary), with the daemon running
- `openssl` and `curl` on the host
- Python: `/usr/bin/python3` on MSYS (CPython, `sys.platform == cygwin`). On Linux, `python3`. `run.sh` exits before `compose up` if the interpreter it selected reports `sys.platform == win32`. The UCRT `python3` on `PATH` is that interpreter on MSYS and is not used.

The images are `ghcr.io/letsencrypt/pebble` and `ghcr.io/letsencrypt/pebble-challtestsrv`, tag `2.10.1`, digest-pinned in `docker-compose.yml`. They are public. No client image is built.

## Run

From the repository root, or from any working directory:

```bash
bash test/pebble/run.sh
```

The script selects the interpreter above, exports `PYTHONDONTWRITEBYTECODE=1`, and creates a work directory under `${TMPDIR:-/tmp}`. It removes a leftover `acmectl-pebble` project, pulls the images, copies the listener CA out of the Pebble image, and publishes ports on `127.0.0.1` only. It exits 0 when `https://127.0.0.1:${ACMECTL_DIR_PORT}/dir` returns `newOrder`, `newNonce`, and `meta.profiles.shortlived`. On any exit it runs `docker compose down` and deletes the work directory. A missing `le.rsa.key` does not fail the run. Host ports already set in the environment are kept; otherwise they default to the table below. The bridge addresses are fixed.

Do not run `docker compose` by itself. Unset `${VAR:?}` values fail the parse instead of becoming an empty address.

## Ports

| Host | Container | Who uses it |
| --- | --- | --- |
| `127.0.0.1:18443` (`ACMECTL_DIR_PORT`) | pebble `14000` | Directory probe. URL `https://127.0.0.1:18443/dir` |
| `127.0.0.1:18444` (`ACMECTL_MGMT_PORT`) | pebble `15000` | Pebble management, including `/roots/0`, `/intermediates/0`, and `/root-keys/0` |
| `127.0.0.1:18445` (`ACMECTL_HTTP_PORT`) | challtestsrv `5002` | HTTP-01 listener, published for the host |
| `127.0.0.1:18446` (`ACMECTL_CHALL_MGMT_PORT`) | challtestsrv `8055` | challtestsrv management |

Nothing is published on `0.0.0.0`. DNS `:8053`, TLS-ALPN `:5001`, and HTTPS-01 `:5003` stay unpublished. challtestsrv is started with `-https01 ""` and `-tlsalpn01 ""`.

| Address | Who |
| --- | --- |
| `10.87.64.2` | pebble, on bridge `10.87.64.0/24` |
| `10.87.64.3` | challtestsrv. An IP certificate for this stack names this address. The Pebble VA dials it on port 5002. The host cannot route to it. |
| `127.0.0.1` | Host loopback publishes only. Not an address for a CSR. Inside the pebble container it is pebble itself. |

## Do not trust this CA

Pebble's listener certificate is signed by `pebble.minica.pem`. The test copies that file out of the image with `docker cp` and passes it as `SSL_CERT_FILE` only on the directory probe. The private key is published in the Pebble repository, so anyone can mint a certificate this CA would verify. Do not install it into a system trust store or the Windows certificate store. The copy is deleted with the work directory. The management listener stays on loopback because it can serve the issuance root private key.

## Difference from the repository README

The "Testing with Pebble" section of `readme.md` tells you to add `https://localhost:14000/dir`, to put an address such as `127.0.0.1` in the CSR, and to serve the token on host port 5002, with challtestsrv management on host port 8055. That does not match this bridge. The VA dials the address written in the CSR from inside the pebble container, where `127.0.0.1` is pebble, not challtestsrv. Docker Desktop does not offer host networking for Linux containers. This stack's directory URL is `https://127.0.0.1:18443/dir`, which matches the listener certificate's `IP Address:127.0.0.1` SAN. Host ports are 18443, 18444, 18445, and 18446.

The `shortlived` sentence in `readme.md` is the automatic rule: Let's Encrypt issues an IP certificate under that profile when the caller did not pass one, and the profile is not sent to any other directory on that path. It is not a description of an explicit `--profile`. This script only checks that Pebble advertises `shortlived`.
