# Todo
## Realistic

- [ ] Implement the new [renewal API](https://datatracker.ietf.org/doc/draft-ietf-acme-ari/)
- [ ] Implement notifications/alerts that connect into the rest of my monitoring stack
- [ ] Consider the upstream TODO for acme-hooked
- [ ] Support supplying a different config file for `acmectl`
- [ ] Support alternate hooks for unattended mode

## Aspirational

- [ ] consider rewriting acme-hooked (and, consequently, acmectl) in shell instead of python to minimize dependencies (even though python is ubuquitous)
- [ ] consider python hook scripts
- [ ] Call acme-hooked as a python module rather than as a subprocess