"""L2: deliver over real Dovecot LMTP with the global Sieve scripts and read back what was stored.

Run lab/l2/setup.sh first (as root). Tier 0 only, with the hand-set fixture combiner in
lab/l2/combiner.json, so the result does not depend on any lab training run. The daemon runs with
mailbox memory; the hook D cases move mail over IMAP and check what the next delivery decides.
"""
import glob, imaplib, json, os, re, shutil, subprocess, sys, time

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
CONF = "/srv/l2/dovecot.conf"
D = ["doveadm", "-c", CONF]
DAEMON = [os.path.join(REPO, "target", "release", "firstreadd"), "--socket", "/srv/l2/run/firstread.sock",
          "--combiner", "/srv/l2/combiner.json", "--deployment", "lab-l2", "--mac-key", "l2-test-key",
          "--junk-threshold", "0.9900990099009901", "--data-class", "public",
          "--memory", "/srv/l2/memory", "--feedback-socket", "/srv/l2/run/feedback.sock",
          "--records", "/srv/l2/records.jsonl"]
shutil.rmtree("/srv/l2/memory", ignore_errors=True)
for f in ["/srv/l2/records.jsonl"]:
    if os.path.exists(f):
        os.unlink(f)


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def start_daemon(shadow=False):
    if os.path.exists("/srv/l2/run/firstread.sock"):
        os.unlink("/srv/l2/run/firstread.sock")
    p = subprocess.Popen(DAEMON + (["--shadow"] if shadow else []), stderr=open("/srv/l2/daemon.log", "a"))
    while not (os.path.exists("/srv/l2/run/firstread.sock") and os.path.exists("/srv/l2/run/feedback.sock")):
        time.sleep(0.05)
    os.chmod("/srv/l2/run/firstread.sock", 0o666)
    os.chmod("/srv/l2/run/feedback.sock", 0o666)
    return p


def set_before(name):
    conf = open(CONF).read()
    conf = re.sub(r"sieve_before = .*", f"sieve_before = /srv/l2/sieve/{name}.sieve", conf)
    open(CONF, "w").write(conf)
    sh(D + ["reload"])
    time.sleep(1.0)


def clear(user):
    for mb in ["INBOX", "Junk", "Later", "Acme", "Trash", "Sent", "Archief"]:
        sh(D + ["expunge", "-u", user, "mailbox", mb, "all"])


def deliver(user, msg):
    t = time.time()
    r = sh([sys.executable, "/srv/l2/lmtp_send.py", "/srv/l2/run/lmtp", f"{user}@lab.invalid", "sender@example.org", f"/srv/l2/msgs/{msg}.eml"])
    return r.stdout.strip() + r.stderr.strip()[-200:], time.time() - t


def stored(user):
    out = []
    for mb in ["INBOX", "Junk", "Later", "Acme", "Trash"]:
        r = sh(D + ["fetch", "-u", user, "flags hdr", "mailbox", mb, "all"])
        for block in r.stdout.split("\f"):
            if "hdr:" not in block:
                continue
            flags = re.search(r"flags: (.*)", block).group(1).strip()
            hdr = block.split("hdr:", 1)[1]
            fr = [l.strip() for l in hdr.splitlines() if l.lower().startswith("x-firstread")]
            out.append((mb, flags, fr))
    return out


def case(title, user, msg, before="before", daemon=True, shadow=False):
    set_before(before)
    clear(user)
    p = start_daemon(shadow) if daemon else None
    res, secs = deliver(user, msg)
    if p:
        p.terminate()
        p.wait()
    print(f"\n## {title}\n  delivery: {res} ({secs:.1f}s)")
    for mb, flags, fr in stored(user):
        print(f"  stored in {mb}; flags [{flags}]")
        for h in fr:
            print(f"    {h[:110]}")


case("A normal: ham with forged X-Firstread-Folder: junk and Keywords: $IsTrusted", "alice", "ham")
case("B normal: spam with forged Folder: inbox and an obsolete-spelling Keywords header", "alice", "spam")
case("C user rule files it: spam whose subject matches the user's own rule", "rules", "acme_spam")
case("D user rule files it: ham whose subject matches the user's own rule", "rules", "acme_ham")
case("E daemon down: ham with forged Folder: junk", "alice", "ham", daemon=False)
case("F filter declines (exit 1): ham with forged Folder: junk", "alice", "ham", before="before-decline")
case("S shadow mode: spam with forged Folder: inbox", "alice", "spam", shadow=True)
#case("G filter killed at sieve_filter_exec_timeout (3 s): ham with forged Folder: junk", "alice", "ham", before="before-slow")
set_before("before")


def hanging_daemon_case():
    import socket, threading
    set_before("before")
    clear("alice")
    p = "/srv/l2/run/firstread.sock"
    if os.path.exists(p):
        os.unlink(p)
    s = socket.socket(socket.AF_UNIX)
    s.bind(p)
    s.listen(5)
    os.chmod(p, 0o666)
    held = []
    threading.Thread(target=lambda: [held.append(s.accept()) for _ in iter(int, 1)], daemon=True).start()
    res, secs = deliver("alice", "ham")
    print(f"\n## H daemon accepts but never answers: ham with forged Folder: junk\n  delivery: {res} ({secs:.1f}s)")
    for mb, flags, fr in stored("alice"):
        print(f"  stored in {mb}; flags [{flags}]")
        for h in fr:
            print(f"    {h[:110]}")
    s.close()


hanging_daemon_case()


# Hook D: the owner's actions over IMAP teach the mailbox's memory; the next delivery shows it.
def imap(user):
    # The same login name as delivery uses (USER at LMTP is the full address), so IMAPSieve's
    # imap.user names the same mailbox memory.
    c = imaplib.IMAP4("127.0.0.1", 1143)
    c.login(f"{user}@lab.invalid", "x")
    return c


def uid_of(c, msgid):
    typ, data = c.uid("SEARCH", None, "HEADER", "Message-ID", msgid)
    uids = data[0].split()
    return uids[0] if uids else None


def move(user, src, dst, msgid, how="MOVE"):
    c = imap(user)
    c.select(src)
    uid = uid_of(c, msgid)
    if uid is None:
        c.logout()
        return f"{msgid} not in {src}"
    if how == "MOVE":
        c.uid("MOVE", uid, dst)
    else:
        c.uid("COPY", uid, dst)
        c.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        c.expunge()
    c.logout()
    time.sleep(0.3)
    return f"{how} {src} -> {dst}"


def append_sent(user, path):
    c = imap(user)
    c.append("Sent", "(\\Seen)", None, open(path, "rb").read())
    c.logout()
    time.sleep(0.3)


def where(user, msgid):
    for mb in ["INBOX", "Junk", "Trash", "Sent", "Archief"]:
        r = sh(D + ["search", "-u", user, "mailbox", mb, "header", "Message-ID", msgid])
        if r.stdout.strip():
            return mb
    return "nowhere"


def label_events():
    n = 0
    for f in glob.glob("/srv/l2/memory/*.events.jsonl"):
        n += sum(1 for l in open(f) if '"kind":"label"' in l)
    return n


def hook_d_cases():
    set_before("before")
    clear("dora")
    p = start_daemon()
    try:
        print("\n## M hook D: the owner's moves teach the next delivery (user dora)")
        deliver("dora", "news1")
        print(f"  news1 from nieuws@winkel.example, unknown sender: {where('dora', 'news1@winkel.example')}")
        print(f"  owner: {move('dora', 'Junk', 'INBOX', 'news1@winkel.example')}")
        deliver("dora", "news2")
        print(f"  news2, same sender after the rescue: {where('dora', 'news2@winkel.example')}")
        deliver("dora", "friend1")
        print(f"  friend1 from pieter@vriend.example: {where('dora', 'friend1@vriend.example')}")
        print(f"  owner: {move('dora', 'INBOX', 'Junk', 'friend1@vriend.example', how='COPY')} (COPY, then expunge)")
        deliver("dora", "friend2")
        print(f"  friend2, same sender after the owner junked one: {where('dora', 'friend2@vriend.example')}")
        deliver("dora", "other1")
        print(f"  other1 from promo@ander.example: {where('dora', 'other1@ander.example')}")
        print(f"  owner: {move('dora', 'Junk', 'Trash', 'other1@ander.example')} (deleting junk teaches nothing)")
        deliver("dora", "other2")
        print(f"  other2, same sender: {where('dora', 'other2@ander.example')}")
        append_sent("dora", "/srv/l2/msgs/sent1.eml")
        print("  owner: APPEND to Sent, a message to contact@partner.example")
        deliver("dora", "contact1")
        rec = [json.loads(l) for l in open("/srv/l2/records.jsonl")]
        last = rec[-1]["features"]
        print(f"  contact1, the reply: {where('dora', 'reply1@partner.example')}; "
              f"wrote_to_sender_unverified={last['mailbox.wrote_to_sender_unverified']:.0f} "
              f"reply_to_sent={last['mailbox.reply_to_sent']:.0f} first_contact={last['mailbox.first_contact']:.0f} "
              "(no DKIM in the fixtures, so the unverified record)")
        deliver("dora", "letter1")
        print(f"  letter1 from nieuwsbrief@krant.example: {where('dora', 'letter1@krant.example')}")
        print(f"  owner: {move('dora', 'INBOX', 'Archief', 'letter1@krant.example')} (filing it away)")
        deliver("dora", "letter2")
        print(f"  letter2, same sender, would be junk on its content: {where('dora', 'letter2@krant.example')}")
        print(f"  label events learned: {label_events()} (the owner's two Junk moves and the filing; firstread's own filing into Junk at delivery is not an IMAP action)")
        print(f"  snapshots in the records: {[r['provenance'].get('snapshot') for r in rec if r['input']['recipient'].startswith('dora')]}")
    finally:
        p.terminate()
        p.wait()


hook_d_cases()
