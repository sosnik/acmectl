import os, subprocess, sys, logging, argparse, configparser

LOGGER = logging.getLogger(__name__)

# Process config
config = configparser.ConfigParser()
if not os.path.isfile('acmectl.conf'):
    LOGGER.critical("No adjacent config file found. Get it from the repo at https://github.com/sosnik/acmectl/.")
    exit(127)
config.read('acmectl.conf')
options = config['general']
endpoints = config['endpoints']

# set BASEDIR from config (if set), otherwise from current working directory
BASEDIR = options['WORKDIR'] if options["WORKDIR"] else os.getcwd()

def die(message):
    LOGGER.error(message)
    exit(1)

def genkey(mode="both", name="", curve=options["CURVE"]):
    if mode == "rsa" or mode == "both":
        subprocess.run(['openssl', 'genrsa', '4096'], stdout=open(os.path.join(BASEDIR, 'certs', f'{name}.rsa.key'), 'w'))

    if mode == "ecdsa" or mode == "both":
        ecparam = subprocess.run(['openssl', 'ecparam', '-genkey', '-name', curve], capture_output=True)
        if ecparam.returncode == 0:
            eckey = subprocess.run(['openssl', 'ec', '-out', os.path.join(BASEDIR, 'certs', f'{name}.ecdsa.key')], input=ecparam.stdout, capture_output=True)
            if eckey.returncode == 0:
                LOGGER.info(eckey.stdout.decode())
            else:
                LOGGER.info(eckey.stderr.decode())
        else:
            LOGGER.info(ecparam.stderr.decode())


def gencsr(name):
    if not os.path.isfile(os.path.join(BASEDIR, 'certs', f'{name}.san')):
        die(f"Cannot read SAN file {name}.san")

    with open(os.path.join(BASEDIR, 'certs', f'{name}.san'), 'r') as file:
        SANEXT = 'subjectAltName = ' + ','.join(['DNS:' + line.strip() for line in file])

    if os.path.isfile(os.path.join(BASEDIR, 'certs', f'{name}.rsa.key')):
        subprocess.run(['openssl', 'req', '-new', '-sha256', '-key', os.path.join(BASEDIR, 'certs', f'{name}.rsa.key'), '-subj', '/', '-addext', SANEXT], stdout=open(os.path.join(BASEDIR, 'certs', f'{name}.rsa.csr'), 'w'))

    if os.path.isfile(os.path.join(BASEDIR, 'certs', f'{name}.ecdsa.key')):
        subprocess.run(['openssl', 'req', '-new', '-sha256', '-key', os.path.join(BASEDIR, 'certs', f'{name}.ecdsa.key'), '-subj', '/', '-addext', SANEXT], stdout=open(os.path.join(BASEDIR, 'certs', f'{name}.ecdsa.csr'), 'w'))


def getone(name, use_hook, endpoint):
    csrs = ""
    if os.path.isfile(os.path.join(BASEDIR, 'certs', f'{name}.rsa.csr')):
        csrs += f"--csr {os.path.join(BASEDIR, 'certs', f'{name}.rsa.csr')} "
    if os.path.isfile(os.path.join(BASEDIR, 'certs', f'{name}.ecdsa.csr')):
        csrs += f"--csr {os.path.join(BASEDIR, 'certs', f'{name}.ecdsa.csr')} "

    # subprocess.run() needs each argument to be a separate list element; some of my parameters are already pre-prepared arguments and will break the subprocess.run() call
    cmdline = f"python3 acme_hooked.py --account-key {options['LE_ACCOUNT_KEY']} {use_hook} {csrs}--directory {endpoint}"
    subprocess.run(cmdline.split(' '))

def quickstart(name, use_hook, endpoint):
    # If there is no account key, generate one
    if not os.path.isfile(os.path.join(BASEDIR, options["LE_ACCOUNT_KEY"])):
        subprocess.run(['openssl', 'genrsa', '4096'], stdout=open(os.path.join(BASEDIR, options["LE_ACCOUNT_KEY"]), 'w'))

    # if there is no dhparam file, generate one
    if not os.path.isfile(os.path.join(BASEDIR, 'certs', 'dhparam.pem')):
        subprocess.run(['openssl', 'dhparam', '4096'], stdout=open(os.path.join(BASEDIR, 'certs', 'dhparam.pem'), 'w'))

    genkey("both", name)
    gencsr(name)
    getone(name, use_hook, endpoint)

def unattended(endpoint):
    # traverse BASEDIR/by-hook/dns and build a list of csrs that will be called with the default dns hook
    use_with_dns_hook = " ".join([f"--csr {os.path.join(root, file)}" for root, dirs, files in os.walk(os.path.join(BASEDIR, 'by-hook', 'dns')) for file in files if file.endswith('.csr')])
    # traverse BASEDIR/by-hook/http and build a list of csrs that will be called with the default dns hook
    use_with_http_hook = " ".join([f"--csr {os.path.join(root, file)}" for root, dirs, files in os.walk(os.path.join(BASEDIR, 'by-hook', 'http')) for file in files if file.endswith('.csr')])

    if use_with_dns_hook:
        cmdline = f"python3 acme_hooked.py --account-key {options['LE_ACCOUNT_KEY']} --dns-hook {os.path.join(BASEDIR, 'hooks', 'dns', options['DNS_HOOK'])} {use_with_dns_hook} --directory {endpoint}"
        subprocess.run(cmdline.split(' '))
    if use_with_http_hook:
        cmdline = f"python3 acme_hooked.py --account-key {options['LE_ACCOUNT_KEY']} --http-hook {os.path.join(BASEDIR, 'hooks', 'http', options['HTTP_HOOK'])} {use_with_http_hook} --directory {endpoint}"
        subprocess.run(cmdline.split(' '))

def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""Wrapper/convenience script for acme-hooked.py."""
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress output except for errors")
    parser.add_argument("-t", "--test", "--debug", action="store_true", help="test mode: enable verbose output and use LE staging endpoint")
    parser.add_argument("-e", "--endpoint", choices=dict(config.items("endpoints")).keys(), default="LE_PROD", help="ACME directory endpoint to use")

    subparsers = parser.add_subparsers(dest="command", help="sub-command help")

    hook_parser = argparse.ArgumentParser(add_help=False)
    hookgroup = hook_parser.add_mutually_exclusive_group(required=True)
    hookgroup.add_argument("--dns-hook",  "--dns",  const=options["DNS_HOOK"],  nargs='?', help="the hook script to call for DNS-01 type challenges (leave empty for default)")
    hookgroup.add_argument("--http-hook", "--http", const=options["HTTP_HOOK"], nargs='?', help="the hook script to call for HTTP-01 type challenges (leave empty for default)")

    genkey_parser = subparsers.add_parser("genkey", help="Generate RSA and/or ECDSA key")
    genkey_parser.add_argument("name", help="base name (usually domain)")
    genkey_parser.add_argument("--mode", choices=["rsa", "ecdsa", "both"], default="both", help="key type to generate")
    genkey_parser.add_argument("--curve", default=config["general"]["CURVE"], help="curve for ECDSA key")

    gencsr_parser = subparsers.add_parser("gencsr", help="Generate CSR")
    gencsr_parser.add_argument("name", help="base name (usually domain)")

    # Define usage text explicitly because order of arguments matters. Upstream bug: https://github.com/python/cpython/issues/53584
    # nargs='?' will 'steal' positional arguments (which makes sense, not sure how they will fix that bug). 
    # One solution would be if argparse (or another library, but I am reluctant to use those) supported --arg=value syntax
    getone_usage = """usage: acmectl.py [-t] getone [-h] name (--dns-hook [DNS_HOOK] | --http-hook [HTTP_HOOK])"""
    getone_parser = subparsers.add_parser("getone", parents=[hook_parser], help="Get a single certificate", usage=getone_usage)
    getone_parser.add_argument("name", help="base name (usually domain)")

    qs_usage = """usage: acmectl.py [-t] quickstart|qs [-h] name (--dns-hook [DNS_HOOK] | --http-hook [HTTP_HOOK])"""
    quickstart_parser = subparsers.add_parser("quickstart", aliases=["qs"], parents=[hook_parser], help="Quickstart. Alias for genkey, gencsr, getone. Will also generate an account key if it doesn't exist.", usage=qs_usage)
    quickstart_parser.add_argument("name", help="base name (usually domain)")

    unattended_parser = subparsers.add_parser("unattended", help="Renew certificates without user interaction")

    args = parser.parse_args(argv)

    endpoint = endpoints["LE_STAGING"] if args.test else endpoints[args.endpoint] 

    if args.command and (args.command == "getone" or args.command == "quickstart"):
        hook_type = "dns" if args.dns_hook else "http"
        use_hook = "--" + hook_type + "-hook " + os.path.join(BASEDIR, "hooks", hook_type, args.http_hook or args.dns_hook)
        LOGGER.info(f"Using {hook_type} hook: {use_hook}")

    LOGGER.info(f"Startup configuration:\n\tendpoint: {endpoint}\n\ttest mode: {args.test}")

    # Map commands to functions
    if args.command == "genkey":
        genkey(args.mode, args.name, args.curve)
    elif args.command == "gencsr":
        gencsr(args.name)
    elif args.command == "getone":
        getone(args.name, use_hook, endpoint)
    elif args.command == "unattended":
        unattended(endpoint)
    elif args.command == "quickstart":
        quickstart(args.name, use_hook, endpoint)
    else:
        parser.print_help()
        exit(1)

    logging.basicConfig(format='[acmectl] %(message)s', level=logging.ERROR if args.quiet else logging.INFO)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])