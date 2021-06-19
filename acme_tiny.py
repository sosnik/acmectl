#!/usr/bin/env python

# acme-hooked - a script to issue TLS certificates via ACME
# Copyright (C) 2015-2021 The acme-hooked authors.
# Licensed under the MIT license, see LICENSE.

import acme_hooked
import argparse, sys, textwrap, logging, os

LOGGER = logging.getLogger(__name__)
DEFAULT_CA = "https://acme-v02.api.letsencrypt.org"
DEFAULT_DIRECTORY_URL = "{0}/directory".format(DEFAULT_CA)

def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from Let's Encrypt using
            the ACME protocol. It will need to be run on your server and have access to your private
            account key, so PLEASE READ THROUGH IT! It's only ~200 lines, so it won't take long.

            Example Usage:
            python acme_tiny.py --account-key ./account.key --csr ./domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > signed_chain.crt

            Example Crontab Renewal (once per month):
            0 0 1 * * python /path/to/acme_tiny.py --account-key /path/to/account.key --csr /path/to/domain.csr --acme-dir /usr/share/nginx/html/.well-known/acme-challenge/ > /path/to/signed_chain.crt 2>> /var/log/acme_tiny.log
            """)
    )
    parser.add_argument("--account-key", required=True, help="path to your Let's Encrypt account private key")
    parser.add_argument("--csr", required=True, help="path to your certificate signing request")
    parser.add_argument("--acme-dir", required=True, help="path to the .well-known/acme-challenge/ directory")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="suppress output except for errors")
    parser.add_argument("--disable-check", default=False, action="store_true", help="disable checking if the challenge file is hosted correctly before telling the CA")

    cagroup = parser.add_mutually_exclusive_group()
    cagroup.add_argument("--directory-url", default=DEFAULT_DIRECTORY_URL, help="certificate authority directory url, default is Let's Encrypt")
    cagroup.add_argument("--ca", help=argparse.SUPPRESS)
    parser.add_argument("--contact", metavar="CONTACT", default=None, nargs="*", help="Contact details (e.g. mailto:aaa@bbb.com) for your account-key")

    args = parser.parse_args(argv)
    logging.basicConfig(format="%(message)s", level=logging.ERROR if args.quiet else logging.INFO)

    # deprecation handling for acme-tiny
    if(args.ca):
        LOGGER.warning('THE --ca OPTION IS DEPRECATED! USE --directory-url INSTEAD!')
        args.directory_url = "{0}/directory".format(args.ca)

    # create the hook from the acme_tiny_hook compatiblity hook script
    script = os.path.join(os.path.dirname(__file__), 'hooks', 'acme_tiny.sh')
    hook = [script, args.acme_dir]

    # sign the certificates in the CSR (using the http challenge)
    acme_hooked.sign_crts(args.account_key, [args.csr], disable_check=args.disable_check, directory_url=args.directory_url, contact=args.contact, hook=hook, challenge_type='http')

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
