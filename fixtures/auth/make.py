"""Generate the DKIM / DMARC fixtures: synthetic messages signed with throw-away keys by dkimpy (an
independent implementation), the public keys and policies as a DNS recording, and what each
message must verify as. Private keys are generated in a temporary directory and discarded.

Usage: python3 -I fixtures/auth/make.py        (needs dkimpy and PyNaCl; openssl on PATH)

Writes, next to this file: <case>.eml, dns.jsonl, expected.json. Re-running makes new keys and
new signatures; expected.json stays the same.
"""
import base64
import json
import os
import subprocess
import tempfile
import time

import dkim
import nacl.encoding
import nacl.signing

HERE = os.path.dirname(os.path.abspath(__file__))

BASE = (b"From: Alice <alice@signer.example>\r\n"
        b"To: bob@rcpt.example\r\n"
        b"Subject: Factuur oktober\r\n"
        b"Date: Mon, 26 Oct 2026 10:00:00 +0100\r\n"
        b"Message-ID: <f1@signer.example>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Hallo Bob,\r\n"
        b"\r\n"
        b"In de bijlage  de factuur voor oktober.   \r\n"
        b"\r\n\r\n")
HEADERS = [b"from", b"to", b"subject", b"date", b"message-id", b"mime-version", b"content-type"]


def rsa(bits, d):
    pem = os.path.join(d, f"rsa{bits}.pem")
    subprocess.run(["openssl", "genrsa", "-traditional", "-out", pem, str(bits)], check=True, capture_output=True)
    der = subprocess.run(["openssl", "rsa", "-in", pem, "-pubout", "-outform", "DER"], check=True,
                         capture_output=True).stdout
    return open(pem, "rb").read(), base64.b64encode(der).decode()


def ed25519():
    sk = nacl.signing.SigningKey.generate()
    priv = base64.b64encode(bytes(sk))
    pub = sk.verify_key.encode(encoder=nacl.encoding.Base64Encoder).decode()
    return priv, pub


class Expiring(dkim.DKIM):
    """dkimpy has no x= option; add one before the header is signed."""
    expires = None

    def gen_header(self, fields, include_headers, canon_policy, header_name, pk, standardize=False):
        if self.expires is not None:
            fields.insert(len(fields) - 3, (b"x", str(self.expires).encode()))
        return super().gen_header(fields, include_headers, canon_policy, header_name, pk, standardize)


def sign(msg, selector, domain, key, alg=b"rsa-sha256", canon=(b"relaxed", b"relaxed"), length=False,
         headers=HEADERS, expires=None):
    d = Expiring(msg)
    d.expires = expires
    sig = d.sign(selector, domain, key, signature_algorithm=alg, canonicalize=canon, include_headers=headers,
                 length=length)
    return sig + msg


def main():
    with tempfile.TemporaryDirectory() as tmp:
        k2048, p2048 = rsa(2048, tmp)
        k1024, p1024 = rsa(1024, tmp)
        k512, p512 = rsa(512, tmp)
        ked, ped = ed25519()
        kother, pother = rsa(2048, tmp)

    dns = [
        ("rsa2048._domainkey.signer.example", f"v=DKIM1; k=rsa; p={p2048}"),
        ("rsa1024._domainkey.signer.example", f"v=DKIM1; k=rsa; p={p1024}"),
        ("rsa512._domainkey.signer.example", f"v=DKIM1; k=rsa; p={p512}"),
        ("ed._domainkey.signer.example", f"v=DKIM1; k=ed25519; p={ped}"),
        ("testing._domainkey.signer.example", f"v=DKIM1; t=y; p={p2048}"),
        ("revoked._domainkey.signer.example", "v=DKIM1; p="),
        ("rsa2048._domainkey.other.example", f"v=DKIM1; k=rsa; p={pother}"),
        ("_dmarc.signer.example", "v=DMARC1; p=reject; rua=mailto:dmarc@signer.example"),
    ]
    absent = ["missing._domainkey.signer.example", "_dmarc.other.example", "_dmarc.rcpt.example"]
    with open(os.path.join(HERE, "dns.jsonl"), "w") as f:
        for name, txt in dns:
            f.write(json.dumps({"type": "TXT", "name": name, "result": "records", "records": [txt]}) + "\n")
        for name in absent:
            f.write(json.dumps({"type": "TXT", "name": name, "result": "no_records"}) + "\n")

    t_sig = int(time.time())
    t0 = t_sig + 60  # the delivery time every case is verified at, unless set
    cases = {}

    def case(name, msg, dkim_, dmarc_, identity, at=None, why=""):
        at = t0 if at is None else at
        open(os.path.join(HERE, f"{name}.eml"), "wb").write(msg)
        cases[name] = {"dkim": dkim_, "dmarc": dmarc_, "identity": identity, "at": at, "why": why}

    rel = sign(BASE, b"rsa2048", b"signer.example", k2048)
    case("rsa2048-relaxed", rel, ["pass"], "pass", True, why="aligned rsa-sha256, relaxed/relaxed")
    case("rsa2048-simple", sign(BASE, b"rsa2048", b"signer.example", k2048, canon=(b"simple", b"simple")),
         ["pass"], "pass", True, why="simple/simple")
    case("rsa1024", sign(BASE, b"rsa1024", b"signer.example", k1024), ["pass"], "pass", True,
         why="1024-bit keys are still valid (RFC 8301)")
    case("rsa512", sign(BASE, b"rsa512", b"signer.example", k512), ["permerror"], "unaligned", False,
         why="keys under 1024 bits are not accepted")
    case("ed25519", sign(BASE, b"ed", b"signer.example", ked, alg=b"ed25519-sha256"), ["pass"], "pass", True,
         why="ed25519-sha256 (RFC 8463)")
    case("lf-endings", rel.replace(b"\r\n", b"\n"), ["pass"], "pass", True,
         why="stored with bare LF; verified as CRLF")
    case("body-changed", rel.replace(b"oktober.", b"november."), ["fail"], "unaligned", False,
         why="body hash mismatch")
    case("subject-changed", rel.replace(b"Subject: Factuur oktober", b"Subject: Factuur november"), ["fail"],
         "unaligned", False, why="signed header changed")
    forged = BASE.replace(b"Message-ID: <f1@", b"Message-ID: <f2@")
    case("third-party-signer", sign(forged, b"rsa2048", b"other.example", kother), ["pass"], "unaligned", False,
         why="valid signature by another domain: not the From identity")
    case("sha1", sign(BASE, b"rsa2048", b"signer.example", k2048, alg=b"rsa-sha1"), ["permerror"], "unaligned",
         False, why="rsa-sha1 must not be considered valid (RFC 8301)")
    lsig = sign(BASE, b"rsa2048", b"signer.example", k2048, length=True)
    case("length-appended", lsig + b"KLIK HIER: http://evil.example/\r\n", ["pass"], "unaligned", False,
         why="l= signature with text appended: passes, but verifies no identity")
    case("length-exact", lsig, ["pass"], "pass", True, why="l= equal to the body length")
    case("testing-key", sign(BASE, b"testing", b"signer.example", k2048), ["permerror"], "unaligned", False,
         why="t=y keys must not be treated differently from unsigned mail")
    case("revoked-key", sign(BASE, b"revoked", b"signer.example", k2048), ["permerror"], "unaligned", False,
         why="empty p=")
    case("no-key", sign(BASE, b"missing", b"signer.example", k2048), ["permerror"], "unaligned", False,
         why="no key record")
    case("key-not-recorded", sign(BASE, b"unrecorded", b"signer.example", k2048), ["temperror"], "temperror",
         False, why="a name the recording does not hold is a temporary error, never 'no record'")
    case("extra-from-on-top", b"From: CEO <ceo@signer.example>\r\n" + rel, ["pass"], "unusable", False,
         why="a second From added above a signed message")
    case("unsigned", BASE, [], "unaligned", False, why="no signature")
    exp = sign(BASE, b"rsa2048", b"signer.example", k2048, expires=t_sig + 3600)
    case("expiring-valid", exp, ["pass"], "pass", True, at=t_sig + 60, why="x= after the delivery time")
    # dkimpy allows 10 hours of clock skew past x=; firstread allows none. Judged past both.
    case("expiring-expired", exp, ["permerror"], "unaligned", False, at=t_sig + 3600 + 36000 + 60,
         why="x= before the delivery time")
    json.dump(cases, open(os.path.join(HERE, "expected.json"), "w"), indent=1, sort_keys=True)

    # The oracle: dkimpy's own verdict on the first signature of every case, from the same DNS.
    records = {}
    for line in open(os.path.join(HERE, "dns.jsonl")):
        r = json.loads(line)
        records[r["name"]] = r.get("records", [None])[0]

    def dnsfunc(name, timeout=5):
        v = records.get(name.decode().rstrip("."))
        return v.encode() if v else None

    disagree = []
    for name, c in cases.items():
        msg = open(os.path.join(HERE, f"{name}.eml"), "rb").read()
        if not c["dkim"]:
            continue
        real = time.time
        time.time = lambda at=c["at"]: at
        try:
            ok = dkim.verify(msg, dnsfunc=dnsfunc)
        finally:
            time.time = real
        want = c["dkim"][0] == "pass"
        if ok != want:
            disagree.append((name, ok, c["dkim"][0]))
    print(f"{len(cases)} cases; dkimpy disagrees with the expected first-signature result on: {disagree}")


if __name__ == "__main__":
    main()
