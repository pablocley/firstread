# L2: the real Dovecot stack

The setup used for the L2 cases of docs/13-lab.md: Dovecot and Pigeonhole from the distribution
packages, one LMTP listener, the two global Sieve scripts of docs/12-interfaces.md section 4.1.1,
a user with a personal rule, and `firstread-filter` behind a wrapper in `sieve_filter_bin_dir`.
Hook D: IMAP on 127.0.0.1:1143 with IMAPSieve; moving mail into Junk, out of Junk (not to Trash)
and appending to Sent run `sieve/report-*.sieve`, which pipe the message to
`pipe-bin/firstread-feedback` (`firstread feedback` to the daemon's feedback socket). Paths
assume `/srv/l2` and a `vmail` user; `cases.py` delivers each case over LMTP, moves mail over IMAP
for the hook D cases, and reads back the stored folder, flags and firstread headers with
`doveadm`. `setup.sh` copies the wrappers and makes them executable.

Results on Dovecot 2.3.21 / Pigeonhole 0.5.21: `lab/results/l2-dovecot-2.3.21.txt`,
docs/measurements/2026-10-26-lab-v0.md and docs/measurements/2026-10-27-mailbox-memory.md.
