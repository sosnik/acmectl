#!/usr/bin/env python

# acme-hooked - a script to issue TLS certificates via ACME
# Copyright (C) 2015-2021 The acme-hooked authors.
# Licensed under the MIT license, see LICENSE.

import argparse, subprocess, json, sys, base64, binascii, time, hashlib, re, textwrap, logging
from urllib.request import urlopen, Request

LOGGER = logging.getLogger(__name__)
DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

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

def get_crt(account_key, csr, disable_check=False, directory_url=DEFAULT_DIRECTORY_URL, contact=None, hook=None, challenge_type=None):
    ret, requests, orders, directory, acct_headers, alg, jwk = [], [], [], None, None, None, None # global variables

    # helper functions - base64 encode for jose spec
    def _b64(bytestring):
        return base64.urlsafe_b64encode(bytestring).decode('utf8').replace("=", "")

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            resp = urlopen(Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}))
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
            raise ValueError("{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
        return resp_data, resp_code, headers

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode('utf8'))
        new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
        protected = {"url": url, "alg": alg, "nonce": new_nonce}
        protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')
        out = _cmd(["openssl", "dgst", "-sha256", "-sign", account_key], stdin=subprocess.PIPE, cmd_input=protected_input, err_msg="OpenSSL Error")
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(out)})
        try:
            return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        except IndexError: # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # helper function - poll until complete
    def _poll_until_not(url, pending_statuses, err_msg):
        result, start_time = None, time.time()
        while result is None or result['status'] in pending_statuses:
            assert (time.time() - start_time < 3600), "Polling timeout" # 1 hour timeout
            time.sleep(0 if result is None else 2)
            result, _, _ = _send_signed_request(url, None, err_msg)
        return result

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

    # create account, update contact details (if any), and set the global key identifier
    LOGGER.info("Registering account.")
    reg_payload = {"termsOfServiceAgreed": True}
    if contact is not None:
        reg_payload.update({"contact": contact})
    account, code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering")
    LOGGER.info("Registered." if code == 201 else "Already registered.")
    if contact is not None and code != 201:
        account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details")
        LOGGER.info("Updated contact details: %s.", "; ".join(account['contact']))

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
        order, _, order_headers = _send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
        LOGGER.info("Order created.")
        orders += [(order, order_headers, csrfile)]

        # get the authorizations that need to be completed
        for auth_url in order['authorizations']:
            authorization, _, _ = _send_signed_request(auth_url, None, "Error getting challenges")
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

    # say the challenge is ready for checking
    for (domain, token, content, challenge_url, auth_url, order) in requests:
        _send_signed_request(challenge_url, {}, "Error submitting challenges: {0}".format(domain))
        LOGGER.info("Verifying %s.", domain)
        authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain))
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
    for (order, order_headers, csrfile) in orders:
        LOGGER.info("Signing certificate for CSR %s.", csrfile)
        csr_der = _cmd(["openssl", "req", "-in", csrfile, "-outform", "DER"], err_msg="DER Export Error")
        _send_signed_request(order['finalize'], {"csr": _b64(csr_der)}, "Error finalizing order")

        # poll the order to monitor when it's done
        order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
        if order['status'] != "valid":
            raise ValueError("Order failed: {0}".format(order))

        # download the certificate
        certificate_pem, _, _ = _send_signed_request(order['certificate'], None, "Certificate download failed")
        LOGGER.info("Certificate signed for %s.", csrfile)
        ret += [(csrfile, certificate_pem)]

    return ret

def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate via the ACME protocol. 
            the ACME protocol. This script runs on your server, has access to your account key, and the
            internet. It's short. PLEASE READ TRHOUGH IT, so that you can trust it.""")
    )
    parser.add_argument("--quiet", action="store_true", help="suppress output except for errors")
    parser.add_argument("--disable-check", default=False, action="store_true", help="disable checking whether ACME challenge is ready for verification")

    parser.add_argument("--account-key", required=True, help="path to your ACSD account private key")
    parser.add_argument("--contact", metavar="CONTACT", default=None, nargs="*", help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key")
    parser.add_argument("--csr", required=True, action='append', help="path to your certificate signing request, can be given multiple times")

    cagroup = parser.add_mutually_exclusive_group()
    cagroup.add_argument("--directory-url", default=DEFAULT_DIRECTORY_URL, help="certificate authority directory url, default is Let's Encrypt")

    hookgroup = parser.add_mutually_exclusive_group(required=True)
    hookgroup.add_argument("--dns-hook", help="the hook script to call for DNS-01 type challenges")
    hookgroup.add_argument("--http-hook", help="the hook script to call for HTTP-01 type challenges")

    args = parser.parse_args(argv)
    logging.basicConfig(format='%(message)s', level=logging.ERROR if args.quiet else logging.INFO)

    challenge_type = 'http' if args.http_hook else 'dns'
    hook = [args.http_hook] if args.http_hook else [args.dns_hook]

    # sign the csrs
    crts = get_crt(args.account_key, args.csr, disable_check=args.disable_check, directory_url=args.directory_url, contact=args.contact, hook=hook, challenge_type=challenge_type)

    # output result via the hook scripts
    for (csr, crt) in crts:
        _do_hook(hook, 'write', [csr], stdin=subprocess.PIPE, cmd_input=crt.encode('utf8'), echo=True)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
