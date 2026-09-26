# What
This is:
* an updated fork of [acme-hooked](https://github.com/mmorak/acme-hooked/), a tiny and auditable Let's Encrypt / ACME client; and
* a rewrite of my own (once `.sh`) wrapper scripts for `acme-hooked` and its predecessor, [`acme-tiny`](https://github.com/diafygi/acme-tiny/) with the same minimalist approach.

# Why
I like the simplicity and mission of `acme-hooked` and `acme-tiny`. These scripts strive to be less than 300 lines of code, while most other ACME clients only _start_ at 2,000.
To be sure, those other clients are more full-featured, but I have been historically content to supplement the client script with a wrapper that fits into my environment.

`acme-tiny`'s major limitation is that it only supports `HTTP-01` challenges. Wildcard certificates require `DNS-01` challenges.
`acme-hooked` has not been updated for a number of years at this point. While it Just Works™ for the most part, it has a glaring bug where it tries to `finalize` requests that are already `valid` (encountered while generating RSA+ECDSA certificates for the same domains). I figured that, since I am patching this anyway, I might also clean up my own wrapper scripts from a loose collection of `.sh` files into a more coherent control script.

# Features
* Separate the concerns of interacting with ACME API and responding to challenges (+ my cloudns hook script is provided).
* Supports HTTP-01 and DNS-01 challenges, allowing for wildcard certificates.
* Helper functions to generate keys and CSRs so that you don't have to remember how to do it / check docs every time you spin up a new server.
* Unattended mode issues any enrolled CSR that has no certificate yet, and renews a certificate when its ARI window is open. When the CA has no renewal window, renewal happens within `RENEW_THRESHOLD` days of expiry.
* WONTFIX: I will assume that people running this script know enough to debug things themselves and won't need strict input validation for commands. 
# Quickstart
```Shell
sudo useradd -m acmectl
sudo visudo -f /etc/sudoers.d/acmectl
# add the following two lines:
#	# Allow acmectl account to reload nginx after renewing certs
#	acmectl ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx

python3 acmectl.py quickstart
# answer the prompts. This generates the account key, dhparam, certificate keys, and CSRs,
# links the CSRs into by-hook/, and requests the certificate.

# enable the daily check
sudo cp /home/acmectl/acmectl.timer /home/acmectl/acmectl.service /etc/systemd/system/
sudo systemctl enable --now acmectl.timer
```

# Usage
Default hooks, the account key, the expiry threshold, and the directory URLs live in `acmectl.conf` beside the script. `--config` selects a different file. An empty `WORKDIR` means the directory that contains the config.

`quickstart` links each new CSR into `by-hook/` for the daily run. To enroll a certificate you created with `genkey` / `gencsr` / `getone`, link its CSR into `by-hook/dns/` or `by-hook/http/` to use the default hook, or into `by-hook/<dns|http>/<hook-filename>.d/` to select another script from `hooks/<dns|http>/`.

The current certificate for `certs/example.rsa.csr` is `certs/example.rsa.crt`. A hook that writes the PEM beside the CSR path is also recognized.

Subject Alternate Name files end with `.san` and live in `certs/`. A bare line is a DNS name. `DNS:` and `IP:` are explicit. Wildcards are DNS names. [RFC 8738](https://www.rfc-editor.org/rfc/rfc8738) uses an `ip` identifier and HTTP-01. DNS-01 cannot validate an address. Let's Encrypt also requires its `shortlived` profile for an IP certificate. That profile is not sent to any other directory.

`example.san`:

```
example.com
example.net
*.example.com
IP:192.0.2.1

```

```Shell
acmectl.py quickstart
acmectl.py genkey NAME [--mode rsa|ecdsa|both]
acmectl.py gencsr NAME
acmectl.py getone NAME (--dns [SCRIPT] | --http [SCRIPT])
acmectl.py unattended [--dry-run]
acmectl.py revoke CERT [--reason N]
acmectl.py ari CERT
acmectl.py profiles
```

`getone NAME --dns` uses `DNS_HOOK`. Put the name before the hook flag. `--dry-run` prints `ISSUE`, `RENEW`, or `SKIP` and does not sign. `-t` uses the Let's Encrypt staging directory. `-e` selects another directory named in the config (`LE_PROD`, `LE_STAGING`, `BUYPASS`, `ZEROSSL`, `SECTIGO`).

The timer runs `unattended` once a day. A certificate inside its ARI window is renewed. If the CA has no renewal window, a certificate within `RENEW_THRESHOLD` days of expiry is renewed. Anything else is left alone. A CSR with no certificate yet is issued.

# Testing with Pebble

Pebble accepts an `ip` identifier. Its HTTP-01 check requests `http://<address>:<httpPort>/.well-known/acme-challenge/<token>` and, when that address is already an IP, dials it directly. TLS-ALPN-01 has its own IP path. DNS-01 still treats the value as a hostname, which RFC 8738 does not allow for an address.

Get Pebble by cloning `https://github.com/letsencrypt/pebble` or by downloading a release archive and unpacking it. From that directory, `docker compose up` starts Pebble and `pebble-challtestsrv`. Add an endpoint for `https://localhost:14000/dir` and select it with `-e`. Put an address Pebble can dial in the CSR, such as `127.0.0.1`, and serve the token on Pebble's HTTP port (5002 in the stock compose file). `pebble-challtestsrv`'s management API on port 8055 can install that token, so the test does not need a public HTTP listener.

 