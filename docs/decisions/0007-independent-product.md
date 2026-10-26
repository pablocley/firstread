# ADR-0007 · firstread is an independent product

Status: accepted

firstread is not tied to any one hosting company. Any platform running an MTA plus Dovecot can run
it; the first deployment is one customer among future ones.

Consequences:

- No platform-specific names, domains, panels or assumptions in code or defaults. Brands, free-mail
  providers, reason texts, thresholds, keyword prefix and modes are data files per deployment.
- Integration targets are protocols and widely deployed components (Dovecot Sieve and events,
  milter, `doveadm`, IMAP), not a specific control panel.
- Multi-tenancy (organisations, per-organisation opt-ins) is a first-class concept, because hosting
  platforms serve many customers.
- Cross-deployment features (the commons) are optional and governed separately from any one operator.
