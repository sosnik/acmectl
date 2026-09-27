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
* Supports HTTP-01 and DNS-01 challenges, allowing for wildcard certificates.  Will support `DNS-PERSIST-01` as soon as that is finalized.  
* Helper functions to generate keys and CSRs so that you don't have to remember how to do it / check docs every time you spin up a new server.
* Unattended mode issues any enrolled CSR that has no certificate yet, and renews a certificate when its ARI window is open. When the CA has no renewal window, renewal happens within `RENEW_THRESHOLD` days of expiry.
  * Supports a mix of hooks/validation methods.
* WONTFIX: I will assume that people running this script know enough to debug things themselves and won't need strict input validation for commands. 
* WONTFIX: I have made some attempts at cross-platform support, but only within my environments.  This Just Works(TM) with WSL on Windows and most Linux I run, I won't be doing native OSX / Windows support.  You can run a docker container, I guess.

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
Clone the repo, edit `acmectl.conf` as needed (pass `--config` to `acmectl` to use a different config location).  Some hook scripts require their own adjacent `<hook>.conf` file, other hook scripts require manual editing.  This process is deliberately not prescriptive, the idea is that the system is self-explanatory and simple enough that it can be tweaked to your environment.  

`acmectl.py` controls `acme_hooked.py`; `acme_hooked.py` is an ACMEv2 client which calls hook scripts to answer validation challenges.  Hooks live in the `hooks/<challenge-type>/` directory.  Optionally, some hooks MAY use an adjacent `<hookname>.conf` file to avoid checking credentials into version control, but you are welcome to integrate your hook scripts with whatever secrets manager your heart desires.  

The `certs/` directory holds private keys, CSRs, signed certificates, backups of signed certificates and `.san` files.  All files relating to one certificate pair MUST use a common base name.  Therefore, `certs/example.san` contains the 'Subject Alt Names' which will be used to generate the CSR `certs/example.<rsa|ecdsa|.csr` from the `certs/example.<rsa|ecdsa.key` private key.  The base name may be arbitrary but it is a good idea to be descriptive.  

A CSR SHOULD be linked from `certs/` to `by-hook/<type>/` (default hook) or `by-hook/<type>/<name>.d/` (specific hook name) for challenge type selection by the control script.  

The `.san` file contains a list of DNS or IP address identifiers, one per line, that are used to build the 'Subject Alternate Name' field of the CSR.  This is a convenience measure adapted from the upstream `acme-tiny` README so that the operator does not need to remember how to use `openssl` to issue certificate signing requests.  Technically speaking, it is possible to generate ACME certificates with a single Common Name instead of a list of Subject Alternate Names.  However, realistically, almost all certificates will use multiple names (if only because you want to use `www.example.com` and `example.com` on the same certificate) so the workflow revolves around the SAN, not the CN.

The `DNS:` prefix is optional; a bare line with no prefix is assumed to be a DNS name.  An `IP:` prefix is required for IPv4 and IPv6 addresses.

`example.san`:

```
example.com
example.net
*.example.com
IP:192.0.2.1

```

> [!NOTE]  
> Note regarding Let's Encrypt and IP address certificates:
> * Let's Encrypt now issues IP address certificates.  However
> * These certificates use the `shortlived` profile, which means they are only valid for less than six days (and should be renewed accordingly; test your pipeline).
> * Per the RFC, IP addresses are validated by talking to the server listening on that IP address, not DNS.  So you can't issue IP address certificates for private IP addresses or on systems without internet access.  

Some brief command explanations (use `--help` for more): 

```Shell
acmectl.py quickstart # Interactive quickstart akin to ssh-keygen, will generate missing certificates for you
acmectl.py genkey NAME [--mode rsa|ecdsa|both] # This can be used to generate an ACME account key, not just TLS keys
acmectl.py gencsr NAME # Generate CSRs for either or both RSA and ECDSA private keys corresponding to the NAME by using the identifiers in NAME.san
acmectl.py getone NAME (--dns [SCRIPT] | --http [SCRIPT]) # The [SCRIPT] is optional so long as a default hook script is defined in acmectl.conf
acmectl.py unattended [--dry-run] # Will attempt to check renewal for (and renew) all enrolled CSRs.  --dry-run will report on the action (skip/renew/issue) without actually doing it.   
acmectl.py revoke CERT [--reason N] # Revoke a certificate
acmectl.py ari CERT # Query ARI info 
acmectl.py info [--account] # 'At a glance' info about the relevant ACMEv2 directory, plus summary of the revocation reason codes, plus your ACME account info with --account 
```

Keep in mind that `NAME` must precede `--dns` (or `--http`) so that the hook path does not swallow the `NAME`.  Use `-t` to hit the Let's Encrypt staging directory. `-e` selects another directory named in the config (`LE_PROD`, `LE_STAGING`, `BUYPASS`, `ZEROSSL`, `SECTIGO`).  

The included systemd timer runs `unattended` once a day. A certificate inside its ARI window is renewed. If the CA has no renewal window, a certificate within `RENEW_THRESHOLD` days of expiry is renewed. Anything else is left alone. A CSR with no certificate yet is issued.  Think about how you will reload your nginx/web server relying on the re-issued certificate.  

# Testing with Pebble

See `tests/pebble/README.md`.  Note that current tests are confined to IP address certificate issuance.  Refer `TODO.MD`.  
