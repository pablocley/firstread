#!/bin/sh
# L2 setup: Dovecot + Pigeonhole from the distribution packages, under /srv/l2, for lab/l2/cases.py.
# Run as root from the repository root after `cargo build --release`. Tested on Ubuntu 24.04
# (Dovecot 2.3.21, Pigeonhole 0.5.21). Safe to run again.
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
L2=/srv/l2

if ! command -v dovecot >/dev/null; then
  apt-get update -q
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q dovecot-core dovecot-lmtpd dovecot-imapd dovecot-sieve
fi
id vmail >/dev/null 2>&1 || useradd -r -U -d "$L2/mail" -s /usr/sbin/nologin vmail
uid=$(id -u vmail)

mkdir -p "$L2/run" "$L2/mail/alice" "$L2/mail/rules" "$L2/bin" "$L2/bin-real" "$L2/sieve" "$L2/msgs"
sed "s/^first_valid_uid = .*/first_valid_uid = $uid/" "$REPO/lab/l2/dovecot.conf" > "$L2/dovecot.conf"
cp "$REPO"/lab/l2/sieve/before.sieve "$REPO"/lab/l2/sieve/before-decline.sieve \
   "$REPO"/lab/l2/sieve/before-slow.sieve "$REPO"/lab/l2/sieve/after.sieve "$L2/sieve/"
cp "$REPO"/lab/l2/bin/* "$L2/bin/" && chmod 755 "$L2"/bin/*
cp "$REPO/target/release/firstread-filter" "$L2/bin-real/" && chmod 755 "$L2/bin-real/firstread-filter"
cp "$REPO"/lab/l2/msgs/*.eml "$L2/msgs/"
cp "$REPO/lab/l2/combiner.json" "$REPO/lab/l2/lmtp_send.py" "$L2/"
cp "$REPO/lab/l2/sieve/user-rules.sieve" "$L2/mail/rules/active.sieve"
chown -R vmail:vmail "$L2/mail" "$L2/sieve"

for s in "$L2"/sieve/*.sieve "$L2/mail/rules/active.sieve"; do
  sievec -c "$L2/dovecot.conf" "$s"
done
chown -R vmail:vmail "$L2/mail" "$L2/sieve"

if doveadm -c "$L2/dovecot.conf" reload 2>/dev/null; then
  echo "dovecot reloaded"
else
  dovecot -c "$L2/dovecot.conf"
  echo "dovecot started"
fi
echo "now: python3 -I lab/l2/cases.py"
