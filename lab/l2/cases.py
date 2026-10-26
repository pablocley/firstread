"""L2: deliver over real Dovecot LMTP with the global Sieve scripts and read back what was stored."""
import os, re, subprocess, sys, time

CONF = "/srv/l2/dovecot.conf"
D = ["doveadm", "-c", CONF]
DAEMON = ["/home/claude/firstread/target/release/firstreadd", "--socket", "/srv/l2/run/firstread.sock",
          "--combiner", "/srv/l2/combiner.json", "--deployment", "lab-l2", "--mac-key", "l2-test-key",
          "--junk-threshold", "0.9900990099009901", "--data-class", "public"]


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def start_daemon(shadow=False):
    if os.path.exists("/srv/l2/run/firstread.sock"):
        os.unlink("/srv/l2/run/firstread.sock")
    p = subprocess.Popen(DAEMON + (["--shadow"] if shadow else []), stderr=open("/srv/l2/daemon.log", "a"))
    while not os.path.exists("/srv/l2/run/firstread.sock"):
        time.sleep(0.05)
    os.chmod("/srv/l2/run/firstread.sock", 0o666)
    return p


def set_before(name):
    conf = open(CONF).read()
    conf = re.sub(r"sieve_before = .*", f"sieve_before = /srv/l2/sieve/{name}.sieve", conf)
    open(CONF, "w").write(conf)
    sh(D + ["reload"])
    time.sleep(1.0)


def clear(user):
    for mb in ["INBOX", "Junk", "Later", "Acme"]:
        sh(D + ["expunge", "-u", user, "mailbox", mb, "all"])


def deliver(user, msg):
    t = time.time()
    r = sh([sys.executable, "/srv/l2/lmtp_send.py", "/srv/l2/run/lmtp", f"{user}@lab.invalid", "sender@example.org", f"/srv/l2/msgs/{msg}.eml"])
    return r.stdout.strip() + r.stderr.strip()[-200:], time.time() - t


def stored(user):
    out = []
    for mb in ["INBOX", "Junk", "Later", "Acme"]:
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
