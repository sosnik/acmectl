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
* Unattended mode for bulk renewal of all of your certificates
* WONTFIX: I will assume that people running this script know enough to debug things themselves and won't need strict input validation for commands. 
# Quickstart
```Shell
sudo useradd -m acmectl
sudo visudo -f /etc/sudoers.d/acmectl
# add the following two lines:
#	# Allow acmectl account to reload nginx after renewing certs
#	acmectl ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx

# Forward Secrecy
openssl dhparam -out /home/acmectl/dhparam.pem 4096

# Create a file called <basename>.san in the certs/ directory listing domain names to be included in a certificate signing request, one per line and up to 100 entries. Then:
python3 acmectl.py quickstart <name>
# enable the service
sudo cp /home/acmectl/acmectl.timer /home/acmectl/acmectl.service /etc/systemd/system/
sudo systemctl enable acmectl.service
sudo systemctl start acmectl.service
```

# Usage
You can define default HTTP and DNS hooks in the `acmectl.conf` file.
For unattended use, link the CSRs from `certs/` into `by-hook/dns` or `by-hook/http/` as appropriate.

Subject Alternate Name configurations must end with `.san`, must be placed in the `certs/` folder, and list the desired alternate names for the certificate, one per line, 100 items max. Wildcards are supported.

`eaxample.san`:

```
example.com
example.net
*.example.com

```

CLI usage:

```Shell
usage: acmectl.py [-h] [-q] [-t] [-e {le_prod,le_staging,buypass,zerossl,sectigo}] {genkey,gencsr,getone,quickstart,qs,unattended} ...

Wrapper/convenience script for acme-hooked.py.

positional arguments:
  {genkey,gencsr,getone,quickstart,qs,unattended}
                        sub-command help
    genkey              Generate RSA and/or ECDSA key
    gencsr              Generate CSR
    getone              Get a single certificate
    quickstart, qs      Quickstart. Alias for genkey, gencsr, getone. Will also generate an account key if it doesn't exist.
    unattended          Renew certificates without user interaction

options:
  -h, --help            show this help message and exit
  -q, --quiet           suppress output except for errors
  -t, --test, --debug   test mode: enable verbose output and use LE staging endpoint
  -e {le_prod,le_staging,buypass,zerossl,sectigo}, --endpoint {le_prod,le_staging,buypass,zerossl,sectigo}
                        ACME directory endpoint to use (defined in acme.conf)
```

⚠️ Argument order is important for `getone` and `quickstart` when passing `--dns|http-[hook]` without a value and relying on the defaults.

Proper usage is: `acmectl.py [-t] getone [-h] name (--dns-hook [DNS_HOOK] | --http-hook [HTTP_HOOK])`

 