#!/usr/bin/env python3
#
# acme-hooked - a script to issue TLS certificates via ACME
# Copyright (C) 2015-2021 The acme-hooked authors.
# Copyright (C) 2024-2026 Nikita Sosnik
# Licensed under the MIT license.
# source: https://github.com/sosnik/acmectl/blob/master/acme_hooked.py

import argparse, subprocess, json, sys, base64, binascii, time, hashlib, re, textwrap, logging, os
from urllib.request import urlopen, Request

__all__ = ['sign_crts', 'get_directory', 'lookup_account', 'get_cert_id', 'get_ari', 'revoke_cert', 'REVOCATION_REASONS']

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

# Four attempts. Sleep 1s, then 2s, then 4s, or a numeric Retry-After below 60s.
# badNonce is retried immediately by _send_signed_request and does not use these waits.
def _do_request(url, data=None, err_msg="Error", depth=0):
    delay = 1
    for attempt in range(4):
        headers = {}
        try:
            resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acmectl"}), timeout=30)
            resp_data, resp_code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as error:
            resp_data = error.read().decode("utf8") if hasattr(error, "read") else str(error)
            resp_code, headers = getattr(error, "code", None), getattr(error, "headers", None) or {}
        try:
            resp_data = json.loads(resp_data) # try to parse json results
        except ValueError:
            pass # ignore json parsing errors
        if depth < 100 and resp_code == 400 and isinstance(resp_data, dict) and resp_data.get("type") == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data) # allow 100 retries for bad nonces
        if resp_code in (200, 201, 204):
            return resp_data, resp_code, headers
        retryable = resp_code is None or resp_code in (429, 500, 502, 503)
        if retryable and attempt < 3:
            wait = delay
            retry_after = headers.get("Retry-After") if hasattr(headers, "get") else None
            if retry_after is not None and str(retry_after).isdigit():
                wait = min(int(retry_after), 60)
            LOGGER.info("Retrying request in %ss after HTTP %s.", wait, resp_code)
            time.sleep(wait)
            delay *= 2
            continue
        failure = ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, resp_code, resp_data))
        if isinstance(resp_data, dict):
            failure.body = resp_data
        raise failure

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

def get_directory(directory_url=DEFAULT_DIRECTORY_URL):
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    if not isinstance(directory, dict):
        raise ValueError("ACME directory was not a JSON object")
    return directory

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

def get_ari(cert_path, directory_url=DEFAULT_DIRECTORY_URL):
    """Return ARI renewal info for a PEM certificate (RFC 9773).

    Keys: certId, suggestedWindow, explanationURL, retryAfter.
    """
    cid = get_cert_id(cert_path)
    directory = get_directory(directory_url)
    base = directory.get("renewalInfo")
    if not base:
        raise ValueError("This ACME directory does not advertise renewalInfo (RFC 9773 ARI not supported by CA)")
    ari_url = base.rstrip("/") + "/" + cid
    resp, _, headers = _do_request(ari_url, err_msg="Error fetching ARI renewal info")
    if not isinstance(resp, dict):
        raise ValueError("ARI renewal info was not JSON")
    return {
        "certId": cid,
        "suggestedWindow": resp.get("suggestedWindow"),
        "explanationURL": resp.get("explanationURL"),
        "retryAfter": headers.get("Retry-After"),
    }

def _account_jwk(account_key):
    """Return (jwk, alg) for an RSA account key."""
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="OpenSSL Error")
    pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
    pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE | re.DOTALL).groups()
    pub_exp = "{0:x}".format(int(pub_exp))
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    jwk = {
        "e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
        "kty": "RSA",
        "n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
    }
    return jwk, "RS256"

def lookup_account(account_key, directory_url=DEFAULT_DIRECTORY_URL):
    """Return url, status, and contact for an existing account, or None.

    Posts onlyReturnExisting and does not create an account.
    """
    jwk, alg = _account_jwk(account_key)
    directory = get_directory(directory_url)
    nonce = [None]
    try:
        account, _, headers = _send_signed_request(
            directory["newAccount"], {"onlyReturnExisting": True}, "Error looking up account",
            directory, jwk, alg, None, account_key, nonce)
    except ValueError as error:
        body = getattr(error, "body", None)
        if isinstance(body, dict) and str(body.get("type", "")).endswith(":accountDoesNotExist"):
            return None
        raise
    if not isinstance(account, dict):
        raise ValueError("Account lookup was not a JSON object")
    return {
        "url": headers.get("Location"),
        "status": account.get("status"),
        "contact": account.get("contact") or [],
    }

def _open_account(account_key, directory_url, contact=None):
    """Parse the account key, fetch the directory, and register. Returns (directory, thumbprint, send)."""
    LOGGER.info("Parsing account key.")
    jwk, alg = _account_jwk(account_key)
    thumbprint = _b64(hashlib.sha256(json.dumps(jwk, sort_keys=True, separators=(',', ':')).encode('utf8')).digest())

    LOGGER.info("Getting directory.")
    directory = get_directory(directory_url)
    LOGGER.info("Directory found.")
    nonce = [None]
    nonce[0] = _do_request(directory['newNonce'])[2].get('Replay-Nonce')

    LOGGER.info("Registering account.")
    reg_payload = {"termsOfServiceAgreed": True}
    if contact is not None:
        reg_payload.update({"contact": contact})
    account, resp_code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering", directory, jwk, alg, None, account_key, nonce)
    LOGGER.info("Registered." if resp_code == 201 else "Already registered.")
    if contact is not None and resp_code != 201 and not set(contact) == set(account['contact']):
        account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details", directory, jwk, alg, acct_headers, account_key, nonce)
        LOGGER.info("Updated contact details: %s.", "; ".join(account['contact']))

    def send(url, payload, err_msg):
        return _send_signed_request(url, payload, err_msg, directory, jwk, alg, acct_headers, account_key, nonce)
    return directory, thumbprint, send

def _identifiers(text):
    """Return (identifiers, dns_names) from `openssl req -text` output."""
    identifiers, seen, domains = [], set(), []

    def add(kind, value):
        if (kind, value) in seen:
            return
        seen.add((kind, value))
        identifiers.append({"type": kind, "value": value})
        if kind == "dns":
            domains.append(value)

    common_name = re.search(r"Subject:.*? CN\s?=\s?([^\s,;/]+)", text)
    if common_name is not None:
        add("dns", common_name.group(1))
    alt_names = re.search(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n", text, re.MULTILINE | re.DOTALL)
    if alt_names is not None:
        for san in alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                add("dns", san[4:])
            elif san.startswith("IP Address:") or san.startswith("IP:"):
                add("ip", san.split(":", 1)[1].strip())
    return identifiers, domains

def _replaces_for(replaces, csrfile):
    """replaces is a CertID string for every CSR, or a dict of CSR path to CertID."""
    if isinstance(replaces, dict):
        return replaces.get(csrfile) or None
    return replaces

def sign_crts(account_key, csr, disable_check=False, directory_url=DEFAULT_DIRECTORY_URL, contact=None, hook=None, challenge_type=None, profile=None, replaces=None):
    """Issue each CSR. replaces is a CertID for every order, or a dict of CSR path to CertID."""
    directory, thumbprint, _send = _open_account(account_key, directory_url, contact)
    failures = []
    # RFC 8555 §7.4: one order, one CSR, posted to that order's finalize URL
    # while the order is "ready". Finish this order before opening the next
    # one, or the CA returns the order that is still open. A previous order
    # leaves the next order's authorizations already valid (§7.1.3).
    for csrfile in csr:
        requests = []
        try:
            LOGGER.info("Parsing CSR %s.", csrfile)
            out = _cmd(["openssl", "req", "-in", csrfile, "-noout", "-text"], err_msg="Error loading {0}".format(csrfile))
            identifiers, _ = _identifiers(out.decode('utf8'))
            LOGGER.info("Found identifiers: %s.", ", ".join(item["value"] for item in identifiers))
            order_profile = profile
            LOGGER.info("Creating new order.")
            order_payload = {"identifiers": identifiers}
            if order_profile:
                order_payload["profile"] = order_profile
                LOGGER.info("Requesting profile: %s", order_profile)
            cert_id = _replaces_for(replaces, csrfile)
            if cert_id:
                order_payload["replaces"] = cert_id
                LOGGER.info("Requesting replacement of CertID: %s", cert_id)
            order, _, order_headers = _send(directory['newOrder'], order_payload, "Error creating new order")
            order_url, finalize_url = str(order_headers['Location']), str(order['finalize'])
            LOGGER.info("Order created. Server selected profile: %s", order['profile']) if 'profile' in order else LOGGER.info("Order created.")
            for auth_url in order['authorizations']:
                authorization, _, _ = _send(auth_url, None, "Error getting challenges")
                domain = authorization['identifier']['value']
                if authorization['status'] == 'valid':
                    LOGGER.info("Domain %s already verified. Skipping.", domain)
                    continue
                LOGGER.info("Setting up challenge for %s.", domain)
                if challenge_type == 'http':
                    challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
                    token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
                    content = "{0}.{1}".format(token, thumbprint)
                elif challenge_type == 'dns':
                    challenge = [c for c in authorization['challenges'] if c['type'] == "dns-01"][0]
                    token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
                    content = _b64(hashlib.sha256("{0}.{1}".format(token, thumbprint).encode('utf8')).digest())
                elif challenge_type == 'onion-csr-01':
                    # Hook prints the base64 DER CSR. It is posted as the challenge response.
                    challenge = [c for c in authorization['challenges'] if c['type'] == "onion-csr-01"][0]
                    token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
                    hook_out = _cmd(hook + ["setup", domain, token, ""], err_msg="Hook Script Error")
                    content = hook_out.decode('utf8').strip() if hook_out else ""
                else:
                    raise ValueError("Unknown challenge type: {0}".format(challenge_type))
                if challenge_type != 'onion-csr-01':
                    _do_hook(hook, "setup", [domain, token, content])
                requests.append((domain, token, content, challenge['url'], auth_url))
            if requests:
                _do_hook(hook, "activate", [])
                LOGGER.info("Activated challenges.")
                if not disable_check:
                    for (domain, token, content, challenge_url, auth_url) in requests:
                        LOGGER.info("checking challenge for domain %s", domain)
                        _do_hook(hook, "check", [domain, token, content])
                for (domain, token, content, challenge_url, auth_url) in requests:
                    LOGGER.info("Notifying that challenge for %s is ready.", domain)
                    _send(challenge_url, {}, "Error submitting challenges: {0}".format(domain))
                for (domain, token, content, challenge_url, auth_url) in requests:
                    LOGGER.info("Verifying %s.", domain)
                    authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain), sender=_send)
                    if authorization['status'] != "valid":
                        raise ValueError("Challenge did not pass for {0}: {1}".format(domain, authorization))
                    LOGGER.info("Domain %s verified.", domain)
                    _do_hook(hook, "remove", [domain, token, content])
                _do_hook(hook, "finish", [])
            LOGGER.info("Signing certificate for CSR %s.", csrfile)
            csr_der = _cmd(["openssl", "req", "-in", csrfile, "-outform", "DER"], err_msg="DER Export Error")
            _send(finalize_url, {"csr": _b64(csr_der)}, "Error finalizing order")
            finished = _poll_until_not(order_url, ["pending", "processing"], "Error checking order status", sender=_send)
            if finished['status'] != "valid":
                raise ValueError("Order failed: {0}".format(finished))
            certificate_pem, _, _ = _send(str(finished['certificate']), None, "Certificate download failed")
            LOGGER.info("Certificate signed for %s.", csrfile)
            _do_hook(hook, 'write', [csrfile], stdin=subprocess.PIPE, cmd_input=certificate_pem.encode('utf8'), echo=True)
        except (ValueError, OSError, AssertionError, IndexError, KeyError) as error:
            LOGGER.error("Could not issue %s: %s", csrfile, error)
            failures.append(csrfile)
            for (domain, token, content, challenge_url, auth_url) in requests:
                try:
                    _do_hook(hook, "remove", [domain, token, content])
                except OSError as remove_error:
                    LOGGER.error("Could not remove challenge for %s: %s", domain, remove_error)
            if requests:
                try:
                    _do_hook(hook, "finish", [])
                except OSError as finish_error:
                    LOGGER.error("Finish failed: %s", finish_error)

    if failures:
        unique = []
        for item in failures:
            if item not in unique:
                unique.append(item)
        raise RuntimeError("Certificate issuance failed for: {0}".format(", ".join(str(item) for item in unique)))

# RFC 8555 section 7.6 refers to RFC 5280 section 5.3.1 for these codes. The CA does not need to publish these in the directory, so they are hard-coded here, but the CA must issue a descriptive error if it rejects one of these reasons. 
REVOCATION_REASONS = (
    (0, "unspecified"),
    (1, "keyCompromise"),
    (2, "cACompromise"),
    (3, "affiliationChanged"),
    (4, "superseded"),
    (5, "cessationOfOperation"),
    (6, "certificateHold"),
    (8, "removeFromCRL"),
    (9, "privilegeWithdrawn"),
    (10, "aACompromise"),
)

def _reason_name(reason):
    code = int(reason)
    for number, name in REVOCATION_REASONS:
        if number == code:
            return name
    return None

def _revocation_failure(reason, error):
    """Short revocation error. The problem detail lists the codes the CA allows."""
    body = getattr(error, "body", None)
    problem = detail = ""
    if isinstance(body, dict):
        problem = str(body.get("type") or "")
        detail = str(body.get("detail") or "")
    if reason is None:
        head = "Revocation failed"
    else:
        name = _reason_name(reason)
        head = "Revocation failed for reason {0} ({1})".format(int(reason), name or int(reason))
    parts = [head]
    if problem:
        parts.append(problem)
    if detail:
        parts.append(detail)
    if len(parts) == 1:
        parts.append("the CA rejected the request")
    return ": ".join(parts)

def revoke_cert(account_key, certificate, directory_url=DEFAULT_DIRECTORY_URL, reason=None):
    """Revoke a PEM certificate with the ACME account key (RFC 8555 section 7.6)."""
    directory, _, send = _open_account(account_key, directory_url)
    der = _cmd(["openssl", "x509", "-in", certificate, "-outform", "DER"], err_msg="DER export error")
    payload = {"certificate": _b64(der)}
    if reason is not None:
        payload["reason"] = int(reason)
    try:
        send(directory["revokeCert"], payload, "Error revoking certificate")
    except ValueError as error:
        raise ValueError(_revocation_failure(reason, error)) from None
    if reason is None:
        LOGGER.info("Revoked %s.", certificate)
    else:
        name = _reason_name(reason)
        if name:
            LOGGER.info("Revoked %s: %s (%s).", certificate, name, int(reason))
        else:
            LOGGER.info("Revoked %s: %s.", certificate, int(reason))

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
    sign_parser.add_argument("--profile", help="ACME profile name advertised by the directory. Optional; server chooses default if omitted.")
    sign_parser.add_argument("--replaces", help="RFC 9773 CertID applied to every order in this invocation. The Python API also accepts a dict of CSR path to CertID.")
    hookgroup = sign_parser.add_mutually_exclusive_group(required=True)
    hookgroup.add_argument("--dns-hook", help="the hook script to call for DNS-01 type challenges")
    hookgroup.add_argument("--http-hook", help="the hook script to call for HTTP-01 type challenges")

    # === CERTID (for ARI in control script) ===
    certid_parser = subparsers.add_parser("certid", help="Compute ARI CertID (RFC 9773) from a certificate")
    certid_parser.add_argument("certificate", help="path to PEM certificate")  # positional: the only argument for this command

    revoke_parser = subparsers.add_parser("revoke", help="Revoke a certificate with the account key")
    revoke_parser.add_argument("--account-key", required=True, help="path to your ACME account private key")
    revoke_parser.add_argument("certificate", help="path to the PEM certificate")
    revoke_parser.add_argument("--reason", type=int, help="RFC 5280 reason code; the CA rejects an unknown code")
    subparsers.add_parser("keychange", help="Account key rollover (ACME keyChange; not implemented)")
    ari_parser = subparsers.add_parser("ari", help="Query ARI renewal window (RFC 9773; relies on certid)")
    ari_parser.add_argument("certificate", help="path to PEM certificate (computes CertID internally)")

    args = parser.parse_args(argv)

    logging.basicConfig(format='%(message)s', level=logging.ERROR if args.quiet else logging.INFO)

    if args.command == "certid":
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
        revoke_cert(args.account_key, args.certificate, args.directory_url, args.reason)
    elif args.command == "keychange":
        raise NotImplementedError("keychange not implemented (see TODO.md and RFC 8555 section 7.3.5)")
    elif args.command == "ari":
        data = get_ari(args.certificate, args.directory_url)
        window = data.get("suggestedWindow") or {}
        LOGGER.info("Suggested renewal window for %s: %s to %s", args.certificate, window.get("start"), window.get("end"))
        if data.get("explanationURL"):
            LOGGER.info("Explanation: %s", data["explanationURL"])
        if data.get("retryAfter"):
            LOGGER.info("Retry-After: %s", data["retryAfter"])
        LOGGER.info("CertID: %s", data.get("certId"))

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])