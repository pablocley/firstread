# L2: the real Dovecot stack

The setup used for the L2 cases of docs/13-lab.md: Dovecot and Pigeonhole from the distribution
packages, one LMTP listener, the two global Sieve scripts of docs/12-interfaces.md section 4.1.1,
a user with a personal rule, and `firstread-filter` behind a wrapper in `sieve_filter_bin_dir`.
Paths assume `/srv/l2` and a `vmail` user; `cases.py` delivers each case over LMTP and reads back
the stored folder, flags and firstread headers with `doveadm fetch`. The wrappers in `bin/` must
be executable (`chmod 755`).

Results on Dovecot 2.3.21 / Pigeonhole 0.5.21: docs/measurements/2026-10-26-lab-v0.md.
