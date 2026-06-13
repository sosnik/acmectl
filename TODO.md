# Todo
## Realistic

- [ ] Implement the new [renewal API](https://datatracker.ietf.org/doc/draft-ietf-acme-ari/)
  - This requires two parts.  Alterations to the acmectl script to fetch renewal information and alterations to the client script to supply the `replaces` field in newOrder requests
  - And will require rethinking the timer/unattended mode
- [ ] Implement notifications/alerts that connect into the rest of my monitoring stack
- [ ] Consider the upstream TODO for acme-hooked
- [ ] Support supplying a different config file for `acmectl`
- [ ] Support alternate hooks for unattended mode
  - At the moment I am considering a `by-hook/<type>/<hook>.d/` directory structure
- [x] Implement profile selection
- [ ] Document running this with cron/alternate init systems not just systemd - I have some hosts running Alpine and I might play with OpenBSD
- [ ] At the same time document systemd templating / drop-ins for dynamic configyuration on my main hosts? 
- [ ] Support revocation
- [ ] Support DNS-PERSIST-01 when it finally arrives (promised Q2 2026)

## Aspirational

- [ ] consider rewriting acme-hooked (and, consequently, acmectl) in shell instead of python to minimize dependencies (even though python is ubuquitous)
- [ ] consider python hook scripts
- [ ] Call acme-hooked as a python module rather than as a subprocess
- [ ] Ansible playbook or at least a normal quickstart config script to set up the user account etc

## Upstream
From the [upstream acme_hooked TODO](https://raw.githubusercontent.com/mmorak/acme-hooked/refs/heads/master/TODO.md):

### Security

- [ ] all tokens received from the web should be validated

### Improvements

- [x] ~~wildcard domain certificates - maybe they just work(TM)?~~ They do just work(TM)
- [x] don't get new nonce every time, it's always supplied by each request (except the first)
- [x] poll-until-not can be optimized (request first, wait/assert later)
- [ ] retry requests (-do-request) several times (how often?) + timeout (how long?) + wait (how long?)
- [ ] log account ID(?)
- [ ] testing against pebble
- [ ] continuous integration
- [x] ~~windows/mac support~~ WONTFIX. Use Linux.  Alternatively: Works on WSL for me. 
- [ ] turn hook argument in python into a python function
- [ ] convert bash scripts to POSIX shell

### Interesting Additions (Possibly With Trade-offs)

- ~~[ ] switch from openssl + subprocess to some crypto library (check how common this dependency is)~~ WONTFIX.  The idea of this script is to be minimal and auditable.  Adding external dependencies means you need to trust or audit yet another thing.  Whereas OpenSSL will be both ubiquitous and necessary for other services that you're going to use with this script (nginx, etc).

## Hook Scripts
- [x] Fix certificate paths