# Todo
## Realistic

- [x] Implement the new [renewal API](https://datatracker.ietf.org/doc/rfc9773/)
  - The client sends `replaces` (one CertID for every CSR in a call, or a dict of CSR path to CertID). The wrapper reads the ARI window.
  - The timer is daily. Unattended renews when the window is open, otherwise when expiry is inside `RENEW_THRESHOLD` days.
- [ ] Implement notifications/alerts that connect into the rest of my monitoring stack
- [ ] Consider the upstream TODO for acme-hooked
- [x] Support supplying a different config file for `acmectl` (`--config`)
- [x] Support alternate hooks for unattended mode
  - `by-hook/<dns|http>/<hook-filename>.d/*.csr` selects that hook. Flat `*.csr` files still use `DNS_HOOK` / `HTTP_HOOK`.
- [x] Implement profile selection
- [ ] Document running this with cron/alternate init systems not just systemd - I have some hosts running Alpine and I might play with OpenBSD
- [ ] At the same time document systemd templating / drop-ins for dynamic configyuration on my main hosts? 
- [x] Support revocation
- [ ] Support DNS-PERSIST-01 when it finally arrives (promised Q2 2026)

acmectl wrapper script
- [x] Redesign: in-process client, one signing call per hook group, ARI-or-threshold scheduling
- [x] Interactive `quickstart` with no arguments
- [x] Logging is configured before any work; the config path is beside the script unless `--config` is set
- [x] Unattended mode issues a CSR that has no certificate and renews one that is due
- [ ] Alerting (ntfy, wall, or a notify hook) when renewal fails
- 



## Aspirational

- [ ] consider rewriting acme-hooked (and, consequently, acmectl) in shell instead of python to minimize dependencies (even though python is ubuquitous)
- [ ] consider python hook scripts
- [x] Call acme-hooked as a python module rather than as a subprocess
- [ ] Ansible playbook or at least a normal quickstart config script to set up the user account etc

## Upstream
From the [upstream acme_hooked TODO](https://raw.githubusercontent.com/mmorak/acme-hooked/refs/heads/master/TODO.md):

### Security

- [ ] all tokens received from the web should be validated

### Improvements

- [x] ~~wildcard domain certificates - maybe they just work(TM)?~~ They do just work(TM)
- [x] don't get new nonce every time, it's always supplied by each request (except the first)
- [x] poll-until-not can be optimized (request first, wait/assert later)
- [x] retry requests: 4 attempts, 30s socket timeout, waits of 1s then 2s then 4s (or numeric Retry-After when it is under 60s)
- [ ] log account ID(?)
- [ ] testing against [pebble](https://github.com/letsencrypt/pebble)
- [ ] continuous integration
- [x] ~~windows/mac support~~ WONTFIX. Use Linux.  Alternatively: Works on WSL for me. 
- [ ] turn hook argument in python into a python function
- [ ] convert bash scripts to POSIX shell

### Interesting Additions (Possibly With Trade-offs)

- ~~[ ] switch from openssl + subprocess to some crypto library (check how common this dependency is)~~ WONTFIX.  The idea of this script is to be minimal and auditable.  Adding external dependencies means you need to trust or audit yet another thing.  Whereas OpenSSL will be both ubiquitous and necessary for other services that you're going to use with this script (nginx, etc).

## Hook Scripts
- [x] Fix certificate paths

## Standards compliance

- [ ] [DNS-PERSIST-01](https://letsencrypt.org/2026/02/18/dns-persist-01) - this standard is WIP, originally due to hit production in Q2 2026 which is almost over at time of writing.  No point adding implementation until finalized.
- [x] [ACME Profiles extension](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/) - currently "just works(TM)".  I've added profile query and profile selection but I don't validate the newOrder response because I don't see much of a need for that.   
- [ ] [RFC 8738 / IP Identifier Validation Extension](https://www.rfc-editor.org/rfc/rfc8738.html) - changes needed.  The challenge methods are the same but the payload is different IIUC (i.e. identifier:ip, instead of identifier:dns)
- [ ] [RFC 8555 (main) missing features](https://www.rfc-editor.org/rfc/rfc8555.html) - some features from the principal RFC are not implemented.  I might not add them for minimalizm but if I do a catalogue is not unwarranted
  - [ ] KeyChange
  - [ ] Account deactivation
  - [ ] Email change (although that's not relevant now that email notifications have been disabled) 
  - [x] Certificate Revocation
  - [ ] ...
  - [ ] TLS-ALPN-1 challenge (probably not; breaks auditability)
- [x] [RFC 9773 - ARI](https://datatracker.ietf.org/doc/rfc9773/)
  - [x] Can build certificate ID used by ARI
  - [x] Implemented the `replaces` mechanism
  - [x] Fetch suggested renewal window
  - [x] Implement wrapper controls that take advantage of ARI (renew once the window is open; batch due CSRs that share a hook) 
- [ ] [RFC 9799 - ACME for .onion domains](https://datatracker.ietf.org/doc/rfc9799/) - later, much later but should be easy enough because HTTP challenge
- [ ] [RFC 8823 - ACME for S/MIME certificates](https://datatracker.ietf.org/doc/rfc8823/) - this looks cool and would be useful to me but this is not a Standard and I don't know of anyone actively using or allowing this extension.
- [ ] [RFC 9115 - Delegated Certificates](https://datatracker.ietf.org/doc/rfc9115/) and [RFC 8739 STAR certificates](https://datatracker.ietf.org/doc/rfc8739/) - investigate these. 