#!/usr/bin/env python3
#
# acme-hooked - a script to issue TLS certificates via ACME
# Copyright (C) 2015-2021 The acme-hooked authors.
# Copyright (C) 2024-2026 Nikita Sosnik
# Licensed under the MIT license.
# source: https://github.com/sosnik/acmectl/blob/master/acme_hooked.py

import argparse, subprocess, json, sys, base64, binascii, time, hashlib, re, textwrap, logging, importlib.util, os
from urllib.request import urlopen, Request

__all__ = ['sign_crts', 'list_profiles', 'get_cert_id'] ## don't forget: revocation, keychange, ari (placeholders below)

LOGGER = logging.getLogger(__name__)
DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

# === Helper functions ===
# helper function - run external commands
def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
    proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(cmd_input)
    if proc.returncode != 0:
        raise IOError("{0}\n{1}".format(err_msg, err))
    return out

# helper function to run hook scripts
def _do_hook(hook_list, cmd, argument_list, stdin=None, cmd_input=None, echo=False):
    cmd_list = hook_list + [cmd] + argument_list
    out = _cmd(cmd_list, stdin=stdin, cmd_input=cmd_input, err_msg="Hook Script Error")
    if echo and out:
        sys.stdout.write(out.decode('utf8'))
    elif out:
        LOGGER.info(out.decode('utf8').rstrip("\n"))

# helper functions - base64 encode for jose spec
def _b64(bytestring):
    return base64.urlsafe_b64encode(bytestring).decode('utf8').replace("=", "")

# helper function - make request and automatically parse json response
def _do_request(url, data=None, err_msg="Error", depth=0):
    try:
        resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acmectl"}))
        resp_data, resp_code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
    except IOError as error:
        resp_data = error.read().decode("utf8") if hasattr(error, "read") else str(error)
        resp_code, headers = getattr(error, "code", None), {}
    try:
        resp_data = json.loads(resp_data) # try to parse json results
    except ValueError:
        pass # ignore json parsing errors
    if depth < 100 and resp_code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
        raise IndexError(resp_data) # allow 100 retries for bad nonces
    if resp_code not in [200, 201, 204]:
        raise ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, resp_code, resp_data))
    return resp_data, resp_code, headers

# helper function - make signed requests
def _send_signed_request(url, payload, err_msg, directory, jwk, alg, acct_headers, account_key, nonce, depth=0):
    payload64 = "" if payload is None else _b64(json.dumps(payload).encode('utf8'))
    new_nonce = _do_request(directory['newNonce'])[2].get('Replay-Nonce') if nonce[0] is None else nonce[0]
    protected = {"url": url, "alg": alg, "nonce": new_nonce}
    protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
    protected64 = _b64(json.dumps(protected).encode('utf8'))
    protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
    out = _cmd(["openssl", "dgst", "-sha256", "-sign", account_key], stdin=subprocess.PIPE, cmd_input=protected_input, err_msg="OpenSSL Error")
    data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(out)})
    try:
        resp_data, resp_code, headers = _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        # Cache the nonce for the next request (every successful response carries one)
        if 'Replay-Nonce' in headers:
            nonce[0] = headers['Replay-Nonce']
        return resp_data, resp_code, headers
    except IndexError:  # badNonce
        nonce[0] = None  # force fresh nonce on retry
        return _send_signed_request(url, payload, err_msg, directory, jwk, alg, acct_headers, account_key, nonce, depth=(depth + 1))

# helper function - poll until complete
# Accepts optional sender (3-arg callable) so sign_crts can pass a context-closing wrapper.
def _poll_until_not(url, pending_statuses, err_msg, sender=None):
    if sender is None:
        sender = lambda u, p, e: _send_signed_request(u, p, e, None, None, None, None, None, [None])
    result, _, _ = sender(url, None, err_msg)
    start_time = time.time()
    while result['status'] in pending_statuses:
        assert (time.time() - start_time < 3600), "Polling timeout" # 1 hour timeout
        time.sleep(2)
        result, _, _ = sender(url, None, err_msg)
    return result

def list_profiles(directory_url=DEFAULT_DIRECTORY_URL):
    """Informative command: print supported profiles."""
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    meta = directory.get("meta", {})
    profiles = meta.get("profiles", {})
    if not profiles:
        LOGGER.info("No profiles advertised by this directory.")
        return
    LOGGER.info("Supported ACME profiles:")
    for name, desc in profiles.items():
        LOGGER.info(f"  {name}: {desc}")

def get_cert_id(cert_path):
    """Return the ARI CertID (RFC 9773) for a PEM certificate."""

    # AKI keyIdentifier
    out = _cmd(["openssl", "x509", "-in", cert_path, "-noout", "-ext", "authorityKeyIdentifier"], err_msg="Failed to read AKI")
    m = re.search(r"([0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}", out.decode("utf8"), re.DOTALL)
    if not m:
        raise ValueError("No Authority Key Identifier found in certificate")
    aki_bytes = binascii.unhexlify(m.group(0).replace(":", ""))
    # Serial number (including any leading zero byte required by DER)
    out = _cmd(["openssl", "x509", "-in", cert_path, "-noout", "-serial"],
               err_msg="Failed to read serial")
    serial_hex = out.decode("utf8").strip().split("=", 1)[1]
    serial_bytes = binascii.unhexlify(serial_hex)
    
    return f"{_b64(aki_bytes)}.{_b64(serial_bytes)}"

def sign_crts(account_key, csr, disable_check=False, directory_url=DEFAULT_DIRECTORY_URL, contact=None, hook=None, challenge_type=None, profile=None, replaces=None):
    crts, requests, orders, directory, acct_headers, alg, jwk, nonce = [], [], [], None, None, None, None, [None] # nonce is mutable list for reuse across signed requests

    # parse account key to get public key
    LOGGER.info("Parsing account key.")
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    alg = "RS256"
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # get the ACME directory of urls
    LOGGER.info("Getting directory.")
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    LOGGER.info("Directory found.")

    # Obtain a nonce once up front; subsequent responses will supply the next nonce (optimization)
    nonce[0] = _do_request(directory['newNonce'])[2].get('Replay-Nonce')

    # create account, update contact details (if any), and set the global key identifier
    LOGGER.info("Registering account.")
    reg_payload = {"termsOfServiceAgreed": True}
    if contact is not None:
        reg_payload.update({"contact": contact})
    # newAccount uses acct_headers=None (triggers jwk instead of kid) + the pre-fetched nonce list
    account, resp_code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering", directory, jwk, alg, None, account_key, nonce)
    LOGGER.info("Registered." if resp_code == 201 else "Already registered.")
    if contact is not None and resp_code != 201 and not set(contact) == set(account['contact']):
        account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details", directory, jwk, alg, acct_headers, account_key, nonce)
        LOGGER.info("Updated contact details: %s.", "; ".join(account['contact']))

    # Local short-form sender (closes over directory/jwk/alg/acct_headers/account_key/nonce).
    # All post-account signed requests (newOrder, auths, challenges, finalize, downloads) use this.
    def _send(url, payload, err_msg):
        return _send_signed_request(url, payload, err_msg, directory, jwk, alg, acct_headers, account_key, nonce)

    # find domains
    for csrfile in csr:
        LOGGER.info("Parsing CSR %s.", csrfile)
        out = _cmd(["openssl", "req", "-in", csrfile, "-noout", "-text"], err_msg="Error loading {0}".format(csrfile))
        domains = set([])
        common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", out.decode('utf8'))
        if common_name is not None:
            domains.add(common_name.group(1))
        subject_alt_names = re.search(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n", out.decode('utf8'), re.MULTILINE | re.DOTALL)
        if subject_alt_names is not None:
            for san in subject_alt_names.group(1).split(", "):
                if san.startswith("DNS:"):
                    domains.add(san[4:])
        LOGGER.info("Found domains: %s.", ", ".join(domains))

        # create a new order
        LOGGER.info("Creating new order.")
        order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        if profile:
            order_payload["profile"] = profile
            LOGGER.info("Requesting profile: %s", profile)
        if replaces:
            order_payload["replaces"] = replaces
            LOGGER.info("Requesting replacement of CertID: %s", replaces)

        order, _, order_headers = _send(directory['newOrder'], order_payload, "Error creating new order")
        LOGGER.info("Order created. Server selected profile: %s", order['profile']) if 'profile' in order else LOGGER.info("Order created.")
        orders += [(order, order_headers, csrfile)]

        # get the authorizations that need to be completed
        for auth_url in order['authorizations']:
            authorization, _, _ = _send(auth_url, None, "Error getting challenges")
            domain = authorization['identifier']['value']
            if authorization['status'] == 'valid':
                LOGGER.info("Domain %s already verified. Skipping.", domain)
                continue
            LOGGER.info("Setting up challenge for %s.", domain)

            # find the correct challenge type and hook script
            if challenge_type == 'http': # HTTP-01
                challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
                token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
                content = "{0}.{1}".format(token, thumbprint)
            elif challenge_type == 'dns': # DNS-01
                challenge = [c for c in authorization['challenges'] if c['type'] == "dns-01"][0]
                token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
                keyauthorization = "{0}.{1}".format(token, thumbprint)
                content = _b64(hashlib.sha256(keyauthorization.encode('utf8')).digest())

            # call hook script
            _do_hook(hook, "setup", [domain, token, content])
            requests += [(domain, token, content, challenge['url'], auth_url, order)]

    # call hook script to activate challenge
    _do_hook(hook, "activate", [])
    LOGGER.info("Activated challenges.")

    # check that the challenge is in place and accessible
    if not disable_check:
        for (domain, token, content, challenge_url, auth_url, order) in requests:
            try:
                LOGGER.info("checking challenge for domain %s", domain)
                _do_hook(hook, "check", [domain, token, content])
            except IOError:
                LOGGER.error("Check failed for domain %s.", domain)
                orders = [(o, oh, c) for (o, oh, c) in orders if o != order] # remove the failed order

    # says the challenge is ready for checking
    for (domain, token, content, challenge_url, auth_url, order) in requests:
        LOGGER.info("Notifying that challenge for %s is ready.", domain)
        _send(challenge_url, {}, "Error submitting challenges: {0}".format(domain))

    # check that they challenge has been completed
    for (domain, token, content, challenge_url, auth_url, order) in requests:
        LOGGER.info("Verifying %s.", domain)
        authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain), sender=_send)
        if authorization['status'] != "valid":
            LOGGER.error("Challenge did not pass for %s: %s", domain, authorization)
            orders = [(o, oh, c) for (o, oh, c) in orders if o != order] # remove the failed order
        else:
            LOGGER.info("Domain %s verified.", domain)

        # remove challenge
        LOGGER.info("removing challenge for domain %s", domain)
        _do_hook(hook, "remove", [domain, token, content])

    # finish the cleanup
    _do_hook(hook, "finish", [])

    # finalize each order where all challenges passed
    finalize_urls = [] 

    for (order, order_headers, csrfile) in orders:
        LOGGER.info("Signing certificate for CSR %s.", csrfile)
        csr_der = _cmd(["openssl", "req", "-in", csrfile, "-outform", "DER"], err_msg="DER Export Error")

        # Only finalize each order once (multiple CSRs can be signed by the same order)
        if order['finalize'] not in finalize_urls:
            _send(order['finalize'], {"csr": _b64(csr_der)}, "Error finalizing order")
            finalize_urls.append(order['finalize'])

        # poll the order to monitor when it's done
        order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status", sender=_send)
        if order['status'] != "valid":
            raise ValueError("Order failed: {0}".format(order))

        # download the certificate
        certificate_pem, _, _ = _send(order['certificate'], None, "Certificate download failed")
        LOGGER.info("Certificate signed for %s.", csrfile)
        crts += [(csrfile, certificate_pem)]

    # output result via the hook scripts
    for (csr, crt) in crts:
        _do_hook(hook, 'write', [csr], stdin=subprocess.PIPE, cmd_input=crt.encode('utf8'), echo=True)

def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate via  
            the ACME protocol. It can be called from the CLI or as a module.  
            This script runs on your server, has access to your account key, and the
            internet. It's short. PLEASE READ THROUGH IT, so that you can trust it."""
                                    )
    )

    # Common options available to *all* subcommands (including future placeholders).
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress output except for errors")
    parser.add_argument("--directory-url", default=DEFAULT_DIRECTORY_URL, help="certificate authority directory url, default is Let's Encrypt production")

    subparsers = parser.add_subparsers(dest="command", required=True, title="commands")

    # === SIGN ===
    sign_parser = subparsers.add_parser("sign", help="Issue/renew certificate(s)")
    sign_parser.add_argument("--disable-check", default=False, action="store_true", help="disable checking whether ACME challenge is ready for verification")
    sign_parser.add_argument("--account-key", required=True, help="path to your ACME account private key")
    sign_parser.add_argument("--contact", metavar="CONTACT", default=None, nargs="*", help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key")
    sign_parser.add_argument("--csr", required=True, action="append", help="path to your certificate signing request, can be given multiple times")
    sign_parser.add_argument("--profile", help="ACME profile name (see 'profiles' command). Optional; server chooses default if omitted.")
    sign_parser.add_argument("--replaces", help="RFC 9773 CertID of certificate to replace (for renewal). Optional; if omitted, a new certificate will be issued instead of renewing an existing one.")
    hookgroup = sign_parser.add_mutually_exclusive_group(required=True)
    hookgroup.add_argument("--dns-hook", help="the hook script to call for DNS-01 type challenges")
    hookgroup.add_argument("--http-hook", help="the hook script to call for HTTP-01 type challenges")

    # === PROFILES ===
    profiles_parser = subparsers.add_parser("profiles", help="List supported profiles")

    # === CERTID (for ARI in control script) ===
    certid_parser = subparsers.add_parser("certid", help="Compute ARI CertID (RFC 9773) from a certificate")
    certid_parser.add_argument("certificate", help="path to PEM certificate")  # positional: the only argument for this command

    # === Placeholders for future features (keep minimal to preserve auditability) ===
    subparsers.add_parser("revoke", help="Revoke certificate (ACME revokeCert; placeholder - not implemented)")
    subparsers.add_parser("keychange", help="Account key rollover (ACME keyChange; placeholder - not implemented)")
    ari_parser = subparsers.add_parser("ari", help="Query ARI renewal window (RFC 9773; relies on certid)")
    ari_parser.add_argument("certificate", help="path to PEM certificate (computes CertID internally)")

    args = parser.parse_args(argv)

    logging.basicConfig(format='%(message)s', level=logging.ERROR if args.quiet else logging.INFO)

    if args.command == "profiles":
        list_profiles(args.directory_url)
    elif args.command == "certid":
        print(get_cert_id(args.certificate))
    elif args.command == "sign":
        challenge_type = "http" if args.http_hook else "dns"
        hook = [args.http_hook] if args.http_hook else [args.dns_hook]
        sign_crts(
            account_key=args.account_key,
            csr=args.csr,
            disable_check=args.disable_check,
            directory_url=args.directory_url,
            contact=args.contact,
            hook=hook,
            challenge_type=challenge_type,
            profile=args.profile,
            replaces=args.replaces
        )
    elif args.command == "revoke":
        raise NotImplementedError("revoke not implemented (placeholder per plan; see TODO.md and RFC 8555 §7.6)")
    elif args.command == "keychange":
        raise NotImplementedError("keychange not implemented (placeholder per plan; see TODO.md and RFC 8555 §7.3.5)")
    elif args.command == "ari":
        # Demonstrate reliance on get_cert_id + surface a usable CertID immediately.
        cid = get_cert_id(args.certificate)
        print(f"CertID: {cid}")
        raise NotImplementedError("ari query not implemented (placeholder; directory['renewalInfo'] + GET will be added later)")

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])