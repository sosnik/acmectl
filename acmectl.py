#!/usr/bin/env python3
"""Issue and renew TLS certificates. Talks to the CA through acme_hooked, in this process."""

import argparse
import configparser
import datetime
import logging
import os
import subprocess
import sys

import acme_hooked

LOGGER = logging.getLogger("acmectl")

def die(message):
    LOGGER.error(message)
    sys.exit(1)

def load_config(path):
    if not os.path.isfile(path):
        sys.stderr.write("Config not found: {0}\n".format(path))
        sys.exit(127)
    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read(path)
    general = parser["general"]
    workdir = general["WORKDIR"].strip() or os.path.dirname(os.path.abspath(path))
    return parser, workdir

def workpath(workdir, path):
    return path if os.path.isabs(path) else os.path.join(workdir, path)

def conf_text(cfg, key):
    return cfg["general"].get(key, "").strip()

def contact_list(cfg):
    raw = conf_text(cfg, "CONTACT")
    if not raw:
        return None
    return [item.strip() for item in raw.split(",") if item.strip()]

def resolved_profile(cfg, override):
    return override or conf_text(cfg, "PROFILE") or None

def account_key(cfg, workdir):
    return workpath(workdir, cfg["general"]["LE_ACCOUNT_KEY"])

def hook_path(workdir, kind, script):
    return script if os.path.isabs(script) else os.path.join(workdir, "hooks", kind, script)

def write_private_key(cmd, dest):
    """Run an OpenSSL command that prints a private key on stdout. Mode 0600."""
    parent = os.path.dirname(dest)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = dest + ".tmp"
    old = os.umask(0o077)
    try:
        with open(tmp, "wb") as out:
            result = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE)
        if result.returncode != 0:
            die(result.stderr.decode(errors="replace").strip() or "OpenSSL failed: {0}".format(" ".join(cmd)))
        os.replace(tmp, dest)
    finally:
        os.umask(old)
        if os.path.exists(tmp):
            os.remove(tmp)
    os.chmod(dest, 0o600)
    message = result.stderr.decode(errors="replace").strip()
    if message:
        LOGGER.info(message)

def genkey(workdir, mode, name, curve):
    certs = os.path.join(workdir, "certs")
    os.makedirs(certs, exist_ok=True)
    if mode in ("rsa", "both"):
        write_private_key(["openssl", "genrsa", "4096"], os.path.join(certs, name + ".rsa.key"))
    if mode in ("ecdsa", "both"):
        ecparam = subprocess.run(["openssl", "ecparam", "-genkey", "-name", curve], capture_output=True)
        if ecparam.returncode != 0:
            die(ecparam.stderr.decode(errors="replace").strip() or "ECDSA parameter generation failed")
        dest = os.path.join(certs, name + ".ecdsa.key")
        old = os.umask(0o077)
        try:
            eckey = subprocess.run(["openssl", "ec", "-out", dest], input=ecparam.stdout, capture_output=True)
        finally:
            os.umask(old)
        if eckey.returncode != 0:
            if os.path.isfile(dest):
                os.remove(dest)
            die(eckey.stderr.decode(errors="replace").strip() or "ECDSA key generation failed")
        os.chmod(dest, 0o600)
        if eckey.stderr.strip():
            LOGGER.info(eckey.stderr.decode(errors="replace").strip())

def _san_part(item):
    """A .san line is DNS:name, IP:address, or a bare DNS name."""
    if item.upper().startswith("IP:"):
        return "IP:" + item.split(":", 1)[1].strip()
    if item.upper().startswith("DNS:"):
        return "DNS:" + item.split(":", 1)[1].strip()
    return "DNS:" + item

def csr_has_ip(path):
    result = subprocess.run(["openssl", "req", "-in", path, "-noout", "-text"], capture_output=True, text=True)
    if result.returncode != 0:
        raise OSError(result.stderr.strip() or "Cannot read {0}".format(path))
    return "IP Address:" in result.stdout

def profile_for(directory_url, profile, has_ip):
    # Let's Encrypt issues IP certificates only under its shortlived profile.
    # RFC 8738 does not define a profile. Other directories, including Pebble, keep the caller's choice.
    if has_ip and not profile and "letsencrypt.org" in directory_url:
        LOGGER.info("Let's Encrypt IP certificate; requesting the shortlived profile.")
        return "shortlived"
    return profile

def gencsr(workdir, name):
    san_path = os.path.join(workdir, "certs", name + ".san")
    if not os.path.isfile(san_path):
        die("Cannot read SAN file {0}".format(san_path))
    with open(san_path) as handle:
        names = [line.strip() for line in handle if line.strip()]
    if not names:
        die("SAN file {0} is empty".format(san_path))
    extension = "subjectAltName = " + ",".join(_san_part(item) for item in names)
    wrote = False
    for kind in ("rsa", "ecdsa"):
        key = os.path.join(workdir, "certs", "{0}.{1}.key".format(name, kind))
        if not os.path.isfile(key):
            continue
        csr = os.path.join(workdir, "certs", "{0}.{1}.csr".format(name, kind))
        with open(csr, "wb") as out:
            result = subprocess.run(
                ["openssl", "req", "-new", "-sha256", "-key", key, "-subj", "/", "-addext", extension],
                stdout=out, stderr=subprocess.PIPE)
        if result.returncode != 0:
            die(result.stderr.decode(errors="replace").strip() or "CSR generation failed for {0}".format(key))
        wrote = True
    if not wrote:
        die("No key found for {0}. Run genkey first.".format(name))

def cert_for(workdir, csr):
    """Current PEM for a CSR: certs/<basename>.crt, else the .crt beside the CSR."""
    name = os.path.basename(csr)
    if name.endswith(".csr"):
        name = name[:-4]
    canonical = os.path.join(workdir, "certs", name + ".crt")
    if os.path.isfile(canonical):
        return canonical
    if csr.endswith(".csr"):
        sibling = csr[:-4] + ".crt"
        if os.path.isfile(sibling):
            return sibling
    return None

def csrs_for(workdir, name):
    found = []
    for kind in ("rsa", "ecdsa"):
        path = os.path.join(workdir, "certs", "{0}.{1}.csr".format(name, kind))
        if os.path.isfile(path):
            found.append(path)
    if not found:
        die("No CSR for {0}".format(name))
    return found

def window_open(start):
    when = datetime.datetime.fromisoformat(start.replace("Z", "+00:00"))
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when <= datetime.datetime.now(datetime.timezone.utc)

def decide(cert, directory_url, threshold_days, ari_state):
    """Return ("issue", "renew", or "skip") and a CertID when renewing.

    An ARI window overrides the local threshold. ari_state["ok"] becomes False
    for the rest of the run when the CA does not advertise renewalInfo.
    """
    if cert is None:
        return "issue", None
    if ari_state["ok"] is not False:
        try:
            info = acme_hooked.get_ari(cert, directory_url)
            ari_state["ok"] = True
            start = (info.get("suggestedWindow") or {}).get("start")
            if start:
                if window_open(start):
                    return "renew", info.get("certId")
                return "skip", None
        except ValueError as error:
            if "does not advertise renewalInfo" in str(error):
                ari_state["ok"] = False
                LOGGER.info("CA has no renewalInfo. Using the local expiry threshold.")
            else:
                LOGGER.error("ARI lookup failed, using local threshold: %s", error)
        except OSError as error:
            LOGGER.error("ARI lookup failed, using local threshold: %s", error)
    seconds = int(threshold_days) * 86400
    result = subprocess.run(
        ["openssl", "x509", "-in", cert, "-noout", "-checkend", str(seconds)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        return "renew", acme_hooked.get_cert_id(cert)
    return "skip", None

def discover(workdir, cfg):
    """Group CSR paths by (dns|http, hook script).

    by-hook/<kind>/<hook-filename>.d/*.csr selects that hook.
    A *.csr placed directly in by-hook/<kind>/ uses the config default.
    When the same file is in both places, the .d directory wins.
    """
    groups = {}
    claimed = set()
    for kind, key in (("dns", "DNS_HOOK"), ("http", "HTTP_HOOK")):
        root = os.path.join(workdir, "by-hook", kind)
        if not os.path.isdir(root):
            continue
        default_hook = hook_path(workdir, kind, cfg["general"][key])
        specific, flat = [], []
        for entry in os.scandir(root):
            if entry.is_dir() and entry.name.endswith(".d"):
                specific.append(entry)
            elif entry.is_file() and entry.name.endswith(".csr"):
                flat.append(entry.path)
        for entry in specific:
            script = hook_path(workdir, kind, entry.name[:-2])
            found = []
            for csr in os.scandir(entry.path):
                if not (csr.is_file() and csr.name.endswith(".csr")):
                    continue
                real = os.path.realpath(csr.path)
                if real in claimed:
                    continue
                claimed.add(real)
                found.append(csr.path)
            if found:
                groups.setdefault((kind, script), []).extend(found)
        bucket = []
        for path in flat:
            real = os.path.realpath(path)
            if real in claimed:
                continue
            claimed.add(real)
            bucket.append(path)
        if bucket:
            groups.setdefault((kind, default_hook), []).extend(bucket)
    return groups

def issue(cfg, workdir, directory_url, kind, hook, csrs, profile, replaces):
    acme_hooked.sign_crts(
        account_key=account_key(cfg, workdir),
        csr=csrs,
        directory_url=directory_url,
        contact=contact_list(cfg),
        hook=[hook],
        challenge_type=kind,
        profile=profile,
        replaces=replaces or None,
    )

def getone(cfg, workdir, name, kind, script, directory_url, profile):
    hook = hook_path(workdir, kind, script)
    if not os.path.isfile(hook):
        die("Missing hook script: {0}".format(hook))
    csrs = csrs_for(workdir, name)
    has_ip = any(csr_has_ip(csr) for csr in csrs)
    if has_ip and kind != "http":
        die("IP identifiers require an HTTP-01 hook (RFC 8738).")
    profile = profile_for(directory_url, resolved_profile(cfg, profile), has_ip)
    replaces = {}
    for csr in csrs:
        cert = cert_for(workdir, csr)
        if cert:
            replaces[csr] = acme_hooked.get_cert_id(cert)
            LOGGER.info("Replacing %s", cert)
    issue(cfg, workdir, directory_url, kind, hook, csrs, profile, replaces)

def enroll(workdir, kind, script, csr, default_script):
    """Link a CSR into by-hook so the daily run can find it."""
    hook_name = os.path.basename(script)
    if hook_name == os.path.basename(default_script):
        dest_dir = os.path.join(workdir, "by-hook", kind)
    else:
        dest_dir = os.path.join(workdir, "by-hook", kind, hook_name + ".d")
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, os.path.basename(csr))
    if os.path.lexists(dest):
        LOGGER.info("Already enrolled: %s", dest)
        return
    os.symlink(os.path.relpath(os.path.abspath(csr), dest_dir), dest)
    LOGGER.info("Enrolled %s", dest)

def ensure_account_key(cfg, workdir):
    dest = account_key(cfg, workdir)
    if os.path.isfile(dest):
        return dest
    LOGGER.info("Generating account key %s", dest)
    write_private_key(["openssl", "genrsa", "4096"], dest)
    return dest

def ensure_dhparam(workdir):
    dest = os.path.join(workdir, "certs", "dhparam.pem")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.isfile(dest):
        LOGGER.info("dhparam exists: %s", dest)
        return
    LOGGER.info("Generating %s. This can take a while.", dest)
    tmp = dest + ".tmp"
    try:
        with open(tmp, "w") as out:
            result = subprocess.run(["openssl", "dhparam", "4096"], stdout=out, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            die(result.stderr.strip() or "dhparam generation failed")
        os.replace(tmp, dest)
    finally:
        if os.path.isfile(tmp):
            os.remove(tmp)

def ask(label, default=None):
    suffix = " [{0}]".format(default) if default else ""
    try:
        value = input("{0}{1}: ".format(label, suffix)).strip()
    except EOFError:
        die("quickstart needs a terminal")
    return value or default

def ask_names():
    print("Names, one per line. Prefix an address with IP:. End with an empty line.")
    names = []
    while True:
        try:
            line = input().strip()
        except EOFError:
            break
        if not line:
            break
        names.append(line)
    if not names:
        die("At least one name is required")
    return names

def quickstart(cfg, workdir, directory_url):
    if not sys.stdin.isatty():
        die("quickstart is interactive. Use genkey, gencsr, and getone from a script.")
    name = ask("Certificate name")
    if not name:
        die("Certificate name is required")
    names = ask_names()
    mode = ask("Key type (rsa, ecdsa, both)", "both")
    if mode not in ("rsa", "ecdsa", "both"):
        die("Key type must be rsa, ecdsa, or both")
    has_ip = any(item.upper().startswith("IP:") for item in names)
    kind = ask("Challenge type (dns or http)", "http" if has_ip else "dns")
    if kind not in ("dns", "http"):
        die("Challenge type must be dns or http")
    if has_ip and kind != "http":
        die("IP identifiers require an HTTP-01 hook (RFC 8738).")
    default_hook = cfg["general"]["DNS_HOOK" if kind == "dns" else "HTTP_HOOK"]
    script = ask("Hook script", default_hook)
    san_path = os.path.join(workdir, "certs", name + ".san")
    os.makedirs(os.path.dirname(san_path), exist_ok=True)
    with open(san_path, "w", newline="\n") as handle:
        handle.write("\n".join(names) + "\n")
    LOGGER.info("Wrote %s", san_path)
    ensure_account_key(cfg, workdir)
    ensure_dhparam(workdir)
    curve = cfg["general"]["CURVE"]
    for key_kind in (("rsa", "ecdsa") if mode == "both" else (mode,)):
        key = os.path.join(workdir, "certs", "{0}.{1}.key".format(name, key_kind))
        if os.path.isfile(key):
            LOGGER.info("Key exists: %s", key)
        else:
            genkey(workdir, key_kind, name, curve)
    gencsr(workdir, name)
    for csr in csrs_for(workdir, name):
        enroll(workdir, kind, script, csr, default_hook)
    getone(cfg, workdir, name, kind, script, directory_url, None)

def report(action, csr, hook, dry_run):
    line = "{0} {1} via {2}".format(action.upper(), csr, hook)
    if dry_run:
        print(line)
    else:
        LOGGER.info(line)

def unattended(cfg, workdir, directory_url, dry_run=False):
    LOGGER.info("Directory %s", directory_url)
    threshold = int(cfg["general"]["RENEW_THRESHOLD"])
    ari_state = {"ok": None}
    failed = False
    profile = resolved_profile(cfg, None)
    for (kind, hook), csrs in discover(workdir, cfg).items():
        hook_ok = os.path.isfile(hook)
        if not hook_ok:
            LOGGER.error("Missing hook script: %s", hook)
            failed = True
        due, replaces = [], {}
        group_has_ip = False
        for csr in csrs:
            try:
                action, cert_id = decide(cert_for(workdir, csr), directory_url, threshold, ari_state)
            except (OSError, ValueError) as error:
                LOGGER.error("Could not decide %s: %s", csr, error)
                failed = True
                continue
            report(action, csr, hook, dry_run)
            if action == "skip":
                continue
            if csr_has_ip(csr):
                if kind != "http":
                    LOGGER.error("IP identifiers require an HTTP-01 hook (RFC 8738): %s", csr)
                    failed = True
                    continue
                group_has_ip = True
            due.append(csr)
            if cert_id:
                replaces[csr] = cert_id
        if dry_run or not due or not hook_ok:
            continue
        try:
            issue(cfg, workdir, directory_url, kind, hook, due, profile_for(directory_url, profile, group_has_ip), replaces)
        except (RuntimeError, OSError, ValueError) as error:
            LOGGER.error("Hook group %s failed: %s", hook, error)
            failed = True
    if failed:
        sys.exit(1)

def show_info(directory_url, account_path=None, with_account=False):
    """Print a short summary of one ACME directory. with_account looks up an existing account."""
    directory = acme_hooked.get_directory(directory_url)
    meta = directory.get("meta") if isinstance(directory.get("meta"), dict) else {}
    print("Directory: {0}".format(directory_url))
    profiles = meta.get("profiles") if isinstance(meta.get("profiles"), dict) else {}
    print("Profiles: {0}".format(", ".join(str(name) for name in profiles) or "none"))
    caa = meta.get("caaIdentities")
    if isinstance(caa, list) and caa:
        print("CAA: {0}".format(", ".join(str(item) for item in caa)))
    print("ARI: {0}".format("yes" if directory.get("renewalInfo") else "no"))
    external = bool(meta.get("externalAccountRequired"))
    print("External account required: {0}".format("yes" if external else "no"))
    if external:
        print("This client does not send an external account binding.")
    for key in ("subdomainAuthAllowed", "onionCAARequired", "delegation-enabled", "allow-certificate-get"):
        if meta.get(key) is True:
            print("{0}: yes".format(key))
    if meta.get("auto-renewal"):
        print("auto-renewal: yes")
    print("Revocation reasons:")
    for code, name in acme_hooked.REVOCATION_REASONS:
        print("  {0} {1}".format(code, name))
    if with_account:
        show_account(account_path, directory_url)

def show_account(account_path, directory_url):
    """Print an existing account. A missing key or a missing account is not a failure."""
    if not account_path or not os.path.isfile(account_path):
        print("Account key is not present: {0}".format(account_path))
        return
    account = acme_hooked.lookup_account(account_path, directory_url)
    if account is None:
        print("No account for this key at this directory.")
        return
    print("Account: {0}".format(account.get("url") or ""))
    print("status: {0}".format(account.get("status") or ""))
    contact = account.get("contact") or []
    print("contact: {0}".format(", ".join(contact) if contact else "none"))

def show_ari(cert, directory_url):
    data = acme_hooked.get_ari(cert, directory_url)
    window = data.get("suggestedWindow") or {}
    LOGGER.info("Suggested renewal window for %s: %s to %s", cert, window.get("start"), window.get("end"))
    if data.get("explanationURL"):
        LOGGER.info("Explanation: %s", data["explanationURL"])
    if data.get("retryAfter"):
        LOGGER.info("Retry-After: %s", data["retryAfter"])
    LOGGER.info("CertID: %s", data.get("certId"))

def chosen_hook(args, cfg):
    if args.dns is not False:
        return "dns", args.dns or cfg["general"]["DNS_HOOK"]
    return "http", args.http or cfg["general"]["HTTP_HOOK"]

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    pre = argparse.ArgumentParser(add_help=False)
    default_config = os.path.join(os.path.dirname(os.path.abspath(__file__)), "acmectl.conf")
    pre.add_argument("--config", default=default_config)
    pre_args, _ = pre.parse_known_args(argv)
    cfg, workdir = load_config(pre_args.config)
    endpoints = dict(cfg.items("endpoints"))

    parser = argparse.ArgumentParser(description="Issue and renew TLS certificates via ACME.")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress output except errors")
    parser.add_argument("-t", "--test", "--debug", action="store_true", help="use the Let's Encrypt staging directory")
    parser.add_argument("-e", "--endpoint", choices=sorted(endpoints), default="LE_PROD", help="directory named in the config file")
    parser.add_argument("--config", default=pre_args.config, help="path to acmectl.conf")
    sub = parser.add_subparsers(dest="command")

    key = sub.add_parser("genkey", help="generate an RSA key, an ECDSA key, or both")
    key.add_argument("name", help="base name, usually the primary domain")
    key.add_argument("--mode", choices=("rsa", "ecdsa", "both"), default="both")
    key.add_argument("--curve", default=cfg["general"]["CURVE"])

    csr = sub.add_parser("gencsr", help="generate CSRs from certs/NAME.san")
    csr.add_argument("name", help="base name, usually the primary domain")

    hooks = argparse.ArgumentParser(add_help=False)
    group = hooks.add_mutually_exclusive_group(required=True)
    group.add_argument("--dns", nargs="?", const=None, default=False, help="DNS-01 hook script; omit the value to use DNS_HOOK")
    group.add_argument("--http", nargs="?", const=None, default=False, help="HTTP-01 hook script; omit the value to use HTTP_HOOK")
    one = sub.add_parser("getone", parents=[hooks], help="issue or replace one name now")
    one.add_argument("name", help="base name, usually the primary domain")
    one.add_argument("--profile", help="ACME profile; defaults to PROFILE in the config, or the CA default")
    one.usage = "acmectl.py getone NAME (--dns [SCRIPT] | --http [SCRIPT])"

    sub.add_parser("quickstart", aliases=["qs"], help="interactive setup and issuance; takes no arguments")
    renew = sub.add_parser("unattended", help="issue missing certificates and renew those that are due")
    renew.add_argument("--dry-run", action="store_true", help="print ISSUE, RENEW, or SKIP; do not sign")
    revoke = sub.add_parser("revoke", help="revoke a certificate with the account key")
    revoke.add_argument("certificate", help="path to the PEM certificate")
    revoke.add_argument("--reason", type=int, help="RFC 5280 reason code; see info")
    info = sub.add_parser("info", help="summarize the selected directory")
    info.add_argument("--account", action="store_true", help="look up the existing account; does not create one")
    ari = sub.add_parser("ari", help="print the ARI renewal window for a certificate")
    ari.add_argument("certificate", help="path to the PEM certificate")

    args = parser.parse_args(argv)
    logging.basicConfig(format="%(name)s: %(message)s", level=logging.ERROR if args.quiet else logging.INFO)
    if "LE_STAGING" not in endpoints or "LE_PROD" not in endpoints:
        die("Config endpoints must define LE_PROD and LE_STAGING")
    directory_url = endpoints["LE_STAGING"] if args.test else endpoints[args.endpoint]

    try:
        if args.command == "genkey":
            genkey(workdir, args.mode, args.name, args.curve)
        elif args.command == "gencsr":
            gencsr(workdir, args.name)
        elif args.command == "getone":
            kind, script = chosen_hook(args, cfg)
            getone(cfg, workdir, args.name, kind, script, directory_url, args.profile)
        elif args.command in ("quickstart", "qs"):
            quickstart(cfg, workdir, directory_url)
        elif args.command == "unattended":
            unattended(cfg, workdir, directory_url, args.dry_run)
        elif args.command == "revoke":
            acme_hooked.revoke_cert(account_key(cfg, workdir), args.certificate, directory_url, args.reason)
        elif args.command == "info":
            path = account_key(cfg, workdir) if args.account else None
            show_info(directory_url, path, args.account)
        elif args.command == "ari":
            show_ari(args.certificate, directory_url)
        else:
            parser.print_help()
            sys.exit(1)
    except (RuntimeError, OSError, ValueError) as error:
        LOGGER.error("%s", error)
        sys.exit(1)

if __name__ == "__main__":
    main()
