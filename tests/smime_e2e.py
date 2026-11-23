"""S/MIME interoperability against OpenSSL, in both directions.

  smime_e2e.py pki DIR
      writes a test CA, user certificates and .p12 files into DIR
  smime_e2e.py run BASE DIR SINK_DIR IMAP_PORT
      signs in as demouser@example.com and checks:
      - messages signed and encrypted by `openssl cms` are verified and
        decrypted by Postern (clear-signed, opaque, BER streaming, CRLF and
        LF line ends, AES-256, 3DES, RSA-OAEP, sign-then-encrypt, EC keys,
        tampering, unknown signer, wrong sender, not for us)
      - messages Postern signs and encrypts are accepted by `openssl cms`
      - drafts, forwarding from an encrypted message, the error cases

The gateway must run with POSTERN_SMIME_CA_FILE=DIR/ca.crt, and the SMTP
sink with SINK_DIR so sent messages can be read back.
"""
import base64, imaplib, json, os, subprocess, sys, time
import requests

passed = []


def ok(name, cond, detail=""):
    if not cond:
        print(f"FAIL  {name}  {detail}")
        sys.exit(1)
    passed.append(name)
    print(f"ok    {name}")


def ssl(*args, input=None, check=True):
    r = subprocess.run(["openssl", *args], input=input, capture_output=True)
    if check and r.returncode != 0:
        raise SystemExit(f"openssl {' '.join(args)} failed: {r.stderr.decode()}")
    return r


# ---- test PKI ---------------------------------------------------------------

def leaf(d, name, email, ec=False, self_signed=False, ca="ca"):
    key, csr, crt, ext = (f"{d}/{name}.{x}" for x in ("key", "csr", "crt", "ext"))
    if ec:
        ssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key)
        usage = "digitalSignature,keyAgreement"
    else:
        ssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key)
        usage = "digitalSignature,keyEncipherment"
    ssl("req", "-new", "-key", key, "-subj", f"/CN={name.title()}/emailAddress={email}", "-out", csr)
    with open(ext, "w") as f:
        f.write(f"basicConstraints=CA:FALSE\nkeyUsage=critical,{usage}\nextendedKeyUsage=emailProtection\n"
                f"subjectAltName=email:{email}\nsubjectKeyIdentifier=hash\n")
        if not self_signed:
            f.write("authorityKeyIdentifier=keyid\n")
    if self_signed:
        ssl("x509", "-req", "-in", csr, "-signkey", key, "-days", "365", "-sha256", "-extfile", ext, "-out", crt)
    else:
        ssl("x509", "-req", "-in", csr, "-CA", f"{d}/{ca}.crt", "-CAkey", f"{d}/{ca}.key", "-CAcreateserial",
            "-days", "365", "-sha256", "-extfile", ext, "-out", crt)


def make_pki(d):
    os.makedirs(d, exist_ok=True)
    ssl("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", f"{d}/ca.key", "-out", f"{d}/ca.crt",
        "-days", "3650", "-subj", "/CN=Postern Test CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    leaf(d, "demo", "demouser@example.com")
    leaf(d, "alice", "alice@example.com")
    leaf(d, "mallory", "alice@example.com", self_signed=True)
    leaf(d, "ec", "ec@example.com", ec=True)
    common = ["-passout", "pass:secret", "-certfile", f"{d}/ca.crt"]
    ssl("pkcs12", "-export", "-inkey", f"{d}/demo.key", "-in", f"{d}/demo.crt", *common, "-out", f"{d}/demo.p12")
    ssl("pkcs12", "-export", "-inkey", f"{d}/demo.key", "-in", f"{d}/demo.crt", *common,
        "-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "sha1", "-out", f"{d}/demo-legacy.p12")
    ssl("pkcs12", "-export", "-inkey", f"{d}/alice.key", "-in", f"{d}/alice.crt", *common, "-out", f"{d}/alice.p12")
    ssl("pkcs12", "-export", "-inkey", f"{d}/ec.key", "-in", f"{d}/ec.crt", *common, "-out", f"{d}/ec.p12")
    print("pki written to", d)


if sys.argv[1] == "pki":
    make_pki(sys.argv[2])
    sys.exit(0)

BASE, D, SINK, IMAP_PORT = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
H = {"x-postern": "1"}
s = requests.Session()
r = s.post(f"{BASE}/api/login", json={"email": "demouser@example.com", "password": "demopass"}, headers=H)
ok("sign in", r.status_code == 200, r.text)
boxes = s.get(f"{BASE}/api/mailboxes").json()["mailboxes"]
role = {b["role"]: b["id"] for b in boxes if b["role"]}
if "drafts" not in role:  # pymap's demo account has none
    s.post(f"{BASE}/api/mailboxes/create", json={"name": "Drafts"}, headers=H)
    boxes = s.get(f"{BASE}/api/mailboxes").json()["mailboxes"]
    role = {b["role"]: b["id"] for b in boxes if b["role"]}
INBOX, SENT, DRAFTS = role["inbox"], role["sent"], role["drafts"]

# ---- importing the key --------------------------------------------------------

def imp(path, password="secret"):
    with open(path, "rb") as f:
        return s.post(f"{BASE}/api/smime/import", files={"file": (os.path.basename(path), f.read())},
                      data={"password": password}, headers=H)

r = imp(f"{D}/demo.p12", "wrong")
ok("import: wrong password refused", r.status_code == 400 and "password" in r.json()["message"], r.text)
r = imp(f"{D}/demo.p12")
ok("import: modern .p12 (AES, PBKDF2)", r.status_code == 200, r.text)
j = r.json()
ok("import: certificate matches the address", j["email_match"] and j["can_decrypt"], j)
ok("import: own certificate trusted via the test CA", j["cert"]["trust"] == "trusted", j["cert"])
SEALED = j["sealed"]
r = imp(f"{D}/demo-legacy.p12")
ok("import: legacy .p12 (3DES, SHA-1 MAC)", r.status_code == 200 and r.json()["email_match"], r.text)
r = imp(f"{D}/alice.p12")
ok("import: someone else's key is flagged", r.status_code == 200 and not r.json()["email_match"], r.text)
r = imp(f"{D}/ec.p12")
ok("import: EC key can sign but not decrypt", r.status_code == 200 and not r.json()["can_decrypt"], r.text)
ok("import: sealed key is opaque", "BEGIN" not in SEALED and len(SEALED) > 100)
KH = {**H, "x-postern-key": SEALED}
ok("status: key usable", s.get(f"{BASE}/api/smime/status", headers=KH).json()["key"] == "ok")
ok("status: damaged key reported", s.get(f"{BASE}/api/smime/status", headers={**H, "x-postern-key": SEALED[:-8] + "AAAAAAAA"}).json()["key"] == "invalid")

# ---- certificates for the address book ----------------------------------------

def certs(data):
    return s.post(f"{BASE}/api/smime/certs", json={"data": base64.b64encode(data).decode()}, headers=H)

alice_pem = open(f"{D}/alice.crt", "rb").read()
r = certs(alice_pem)
c = r.json()["certs"][0] if r.status_code == 200 else {}
ok("certs: PEM read", r.status_code == 200 and c.get("emails") == ["alice@example.com"], r.text)
ok("certs: trusted, can encrypt", c["trust"] == "trusted" and c["can_encrypt"] and c["key"] == "RSA 2048", c)
ALICE_DER = c["der"]
der = ssl("x509", "-in", f"{D}/alice.crt", "-outform", "DER").stdout
ok("certs: DER read", certs(der).json()["certs"][0]["fingerprint"] == c["fingerprint"])
p7 = ssl("crl2pkcs7", "-nocrl", "-certfile", f"{D}/alice.crt", "-certfile", f"{D}/ca.crt", "-outform", "DER").stdout
ok("certs: .p7c bundle read", len(certs(p7).json()["certs"]) == 2)
r = certs(open(f"{D}/mallory.crt", "rb").read())
ok("certs: self-signed is untrusted", r.json()["certs"][0]["trust"] == "untrusted", r.text)
ok("certs: garbage refused", certs(b"hello world").status_code == 400)

# ---- messages from OpenSSL ---------------------------------------------------

def imap():
    im = imaplib.IMAP4("127.0.0.1", IMAP_PORT)
    im.login("demouser", "demopass")
    return im


def append(raw):
    im = imap()
    im.append("INBOX", "", imaplib.Time2Internaldate(time.time()), raw)
    im.logout()


def entity(text, html=None, attachment=None):
    if html is None and attachment is None:
        return f"Content-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n".encode()
    b = "b1"
    parts = [f"--{b}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n"]
    kind = "mixed" if attachment else "alternative"
    if html:
        parts.append(f"--{b}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}\r\n")
    if attachment:
        name, data = attachment
        enc = base64.b64encode(data).decode()
        parts.append(f"--{b}\r\nContent-Type: application/pdf; name=\"{name}\"\r\nContent-Disposition: attachment; filename=\"{name}\"\r\n"
                     f"Content-Transfer-Encoding: base64\r\n\r\n{enc}\r\n")
    return (f"Content-Type: multipart/{kind}; boundary=\"{b}\"\r\n\r\n" + "".join(parts) + f"--{b}--\r\n").encode()


def cms(op, data, subject, sender="alice@example.com", extra=(), crlf=True):
    # Recipient certificates are positional, so they come last.
    args = ["cms", op, "-from", sender, "-to", "demouser@example.com", "-subject", subject]
    if crlf:
        args.append("-crlfeol")
    return ssl(*args, *extra, input=data).stdout


def find(subject, mailbox=INBOX, tries=20):
    for _ in range(tries):
        page = s.get(f"{BASE}/api/messages", params={"mailbox": mailbox, "limit": 100}).json()
        for m in page["items"]:
            if m["subject"] == subject:
                return m
        time.sleep(0.25)
    raise SystemExit(f"message {subject!r} not found in {mailbox}")


def view(subject, key=True, mailbox=INBOX, headers=None):
    m = find(subject, mailbox)
    hdr = headers if headers is not None else (KH if key else H)
    return m, s.get(f"{BASE}/api/message", params={"mailbox": mailbox, "id": m["id"]}, headers=hdr).json()


alice = ["-signer", f"{D}/alice.crt", "-inkey", f"{D}/alice.key"]
plain = entity("Hello from Alice")
append(cms("-sign", plain, "S1 clear-signed", extra=alice))
append(cms("-sign", plain, "S1b clear-signed LF", extra=alice, crlf=False))
append(cms("-sign", plain, "S2 opaque", extra=[*alice, "-nodetach"]))
append(cms("-sign", plain, "S3 streamed BER", extra=[*alice, "-nodetach", "-stream"]))
tampered = cms("-sign", plain, "S4 tampered", extra=alice).replace(b"Hello from Alice", b"Hello from Malice")
append(tampered)
append(cms("-sign", plain, "S5 self-signed", extra=["-signer", f"{D}/mallory.crt", "-inkey", f"{D}/mallory.key"]))
append(cms("-sign", plain, "S6 wrong sender", sender="bob@example.com", extra=alice))
append(cms("-sign", entity("EC hello"), "S7 EC", sender="ec@example.com", extra=["-signer", f"{D}/ec.crt", "-inkey", f"{D}/ec.key"]))

demo = [f"{D}/demo.crt"]
append(cms("-encrypt", plain, "E1 AES-256", extra=["-aes256", *demo]))
append(cms("-encrypt", plain, "E2 3DES", extra=["-des3", *demo]))
append(cms("-encrypt", plain, "E3 OAEP", extra=["-aes128", "-recip", f"{D}/demo.crt", "-keyopt", "rsa_padding_mode:oaep",
                                                "-keyopt", "rsa_oaep_md:sha256", "-keyopt", "rsa_mgf1_md:sha256"]))
append(cms("-encrypt", plain, "E4 streamed BER", extra=["-aes256", "-stream", *demo]))
inner_signed = ssl("cms", "-sign", "-signer", f"{D}/alice.crt", "-inkey", f"{D}/alice.key", "-crlfeol", input=plain).stdout
append(cms("-encrypt", inner_signed, "E5 signed and encrypted", extra=["-aes256", *demo]))
PDF = b"%PDF-1.4 test attachment\n" * 20
append(cms("-encrypt", entity("See attached", attachment=("report.pdf", PDF)), "E6 attachment", extra=["-aes256", *demo]))
append(cms("-encrypt", plain, "E7 not for us", extra=["-aes256", f"{D}/alice.crt"]))
append(cms("-encrypt", entity("plain part", html="<p>Secret <b>HTML</b> <img src=\"https://tracker.example/x.png\"></p>"),
           "E8 HTML", extra=["-aes256", *demo]))

m, v = view("S1 clear-signed")
sig = v["security"]["signed"]
ok("in: clear-signed verified", sig["status"] == "valid", sig)
ok("in: signer trusted and matches From", sig["trust"] == "trusted" and sig["signer_matches_from"], sig)
ok("in: signer certificate reported", sig["signer"]["emails"] == ["alice@example.com"] and sig["signed_at"], sig)
ok("in: content shown, signature part hidden", "Hello from Alice" in v["text"] and not v["attachments"], v)
ok("in: list marks it signed", m["security"] == "signed", m)
_, v = view("S1b clear-signed LF")
ok("in: LF line ends canonicalized", v["security"]["signed"]["status"] == "valid", v["security"])
_, v = view("S2 opaque")
ok("in: opaque signed verified", v["security"]["signed"]["status"] == "valid" and "Hello from Alice" in v["text"], v)
_, v = view("S3 streamed BER")
ok("in: BER (indefinite length) verified", v["security"]["signed"]["status"] == "valid", v["security"])
_, v = view("S4 tampered")
ok("in: tampering detected", v["security"]["signed"]["status"] == "invalid", v["security"])
_, v = view("S5 self-signed")
sig = v["security"]["signed"]
ok("in: unknown signer: valid but untrusted", sig["status"] == "valid" and sig["trust"] == "untrusted", sig)
_, v = view("S6 wrong sender")
ok("in: signer differs from sender", v["security"]["signed"]["status"] == "valid" and not v["security"]["signed"]["signer_matches_from"], v["security"])
_, v = view("S7 EC")
sig = v["security"]["signed"]
ok("in: ECDSA P-256 verified", sig["status"] == "valid" and sig["trust"] == "trusted" and sig["signer"]["key"] == "EC P-256", sig)

m, v = view("E1 AES-256")
enc = v["security"]["encrypted"]
ok("in: AES-256 decrypted", enc["status"] == "decrypted" and enc["algorithm"] == "AES-256-CBC" and "Hello from Alice" in v["text"], v)
ok("in: list marks it encrypted, no preview", m["security"] == "encrypted" and m["preview"] == "", m)
_, v = view("E1 AES-256", key=False)
ok("in: without the key: notice only", v["security"]["encrypted"]["status"] == "no_key" and v["text"] == "" and not v["attachments"], v)
_, v = view("E1 AES-256", headers={**H, "x-postern-key": SEALED[:-8] + "AAAAAAAA"})
ok("in: unusable key reported", v["key_invalid"] and v["security"]["encrypted"]["status"] == "no_key", v)
_, v = view("E2 3DES")
ok("in: 3DES decrypted", v["security"]["encrypted"]["algorithm"] == "3DES-CBC" and "Hello from Alice" in v["text"], v["security"])
_, v = view("E3 OAEP")
ok("in: RSA-OAEP (SHA-256) decrypted", v["security"]["encrypted"]["status"] == "decrypted" and "Hello" in v["text"], v["security"])
_, v = view("E4 streamed BER")
ok("in: BER encrypted decrypted", v["security"]["encrypted"]["status"] == "decrypted", v["security"])
_, v = view("E5 signed and encrypted")
ok("in: sign-then-encrypt: decrypted and verified", v["security"]["encrypted"]["status"] == "decrypted"
   and v["security"]["signed"]["status"] == "valid" and v["security"]["signed"]["trust"] == "trusted", v["security"])
m6, v = view("E6 attachment")
att = [a for a in v["attachments"] if a["name"] == "report.pdf"]
ok("in: attachment inside encrypted message listed", len(att) == 1, v["attachments"])
q = {"mailbox": INBOX, "id": m6["id"], "part": att[0]["part"]}
r = s.get(f"{BASE}/api/message/part", params=q, headers=KH)
ok("in: attachment decrypted on download", r.status_code == 200 and r.content == PDF)
r = s.get(f"{BASE}/api/message/part", params=q)
ok("in: download within the cache window needs no key", r.status_code == 200 and r.content == PDF)
_, v = view("E7 not for us")
ok("in: encrypted for someone else", v["security"]["encrypted"]["status"] == "not_for_you", v["security"])
m8, v = view("E8 HTML")
r = s.get(f"{BASE}/api/message/html", params={"mailbox": INBOX, "id": m8["id"]}, headers=KH)
ok("in: encrypted HTML rendered, remote image removed", r.status_code == 200 and "<b>HTML</b>" in r.text and "tracker.example" not in r.text, r.text[:300])

# ---- messages to OpenSSL ------------------------------------------------------

def send(meta, key=True, files=()):
    form = [("meta", (None, json.dumps({"sent_mailbox": SENT, "drafts_mailbox": DRAFTS, **meta})))]
    for name, data in files:
        form.append(("file", (name, data, "application/octet-stream")))
    return s.post(f"{BASE}/api/send", files=form, headers=KH if key else H)


def last_sent():
    files = sorted((f for f in os.listdir(SINK) if f.endswith(".eml")), key=lambda f: int(f[:-4]))
    return open(os.path.join(SINK, files[-1]), "rb").read()


def verify_with_openssl(raw):
    with open(f"{D}/check.eml", "wb") as f:
        f.write(raw)
    return ssl("cms", "-verify", "-CAfile", f"{D}/ca.crt", "-in", f"{D}/check.eml", check=False)


TEXT = "Grüße aus Postern\nA line with trailing spaces   \nFrom here on\n.\n-- \nSignature"
r = send({"to": "alice@example.com", "subject": "O1 signed", "text": TEXT, "smime": {"sign": True}})
ok("out: signed message sent", r.status_code == 200, r.text)
raw = last_sent()
ok("out: multipart/signed with SHA-256", b"multipart/signed" in raw and b"micalg=sha-256" in raw)
v = verify_with_openssl(raw)
ok("out: OpenSSL verifies the signature and chain", v.returncode == 0, v.stderr.decode())
ok("out: OpenSSL sees the text", "Grüße".encode() in v.stdout or b"Gr=C3=BC=C3=9Fe" in v.stdout, v.stdout[:400])
_, v = view("O1 signed")
ok("out: Postern verifies its own signature", v["security"]["signed"]["status"] == "valid" and v["security"]["signed"]["trust"] == "trusted", v["security"])

r = send({"to": "Alice <alice@example.com>", "subject": "O2 signed and encrypted", "text": "Top secret",
          "smime": {"sign": True, "encrypt": True, "certs": [ALICE_DER]}})
ok("out: signed and encrypted message sent", r.status_code == 200, r.text)
raw = last_sent()
ok("out: enveloped-data, no plaintext on the wire", b"smime-type=enveloped-data" in raw and b"Top secret" not in raw)
with open(f"{D}/enc.eml", "wb") as f:
    f.write(raw)
d = ssl("cms", "-decrypt", "-recip", f"{D}/alice.crt", "-inkey", f"{D}/alice.key", "-in", f"{D}/enc.eml", check=False)
ok("out: OpenSSL decrypts with the recipient's key", d.returncode == 0 and b"multipart/signed" in d.stdout, d.stderr.decode())
v = verify_with_openssl(d.stdout)
ok("out: inner signature verifies in OpenSSL", v.returncode == 0 and b"Top secret" in v.stdout, v.stderr.decode())
d2 = ssl("cms", "-decrypt", "-recip", f"{D}/demo.crt", "-inkey", f"{D}/demo.key", "-in", f"{D}/enc.eml", check=False)
ok("out: the sender can decrypt too (own copy)", d2.returncode == 0)
_, v = view("O2 signed and encrypted", mailbox=SENT)
ok("out: Sent copy decrypted and verified", v["security"]["encrypted"]["status"] == "decrypted"
   and v["security"]["signed"]["status"] == "valid" and "Top secret" in v["text"], v["security"])

r = send({"to": "alice@example.com", "subject": "O3 encrypted only", "text": "With a file",
          "smime": {"encrypt": True, "certs": [ALICE_DER]}}, files=[("notes.txt", b"attached notes\n")])
ok("out: encrypted message with attachment sent", r.status_code == 200, r.text)
with open(f"{D}/enc3.eml", "wb") as f:
    f.write(last_sent())
d = ssl("cms", "-decrypt", "-recip", f"{D}/alice.crt", "-inkey", f"{D}/alice.key", "-in", f"{D}/enc3.eml", check=False)
ok("out: OpenSSL finds the attachment", d.returncode == 0 and b"notes.txt" in d.stdout and b"multipart/signed" not in d.stdout, d.stderr.decode())

before = len(os.listdir(SINK))
r = send({"to": "bob@example.com", "subject": "O4", "text": "x", "smime": {"encrypt": True, "certs": [ALICE_DER]}})
ok("out: missing certificate refused, names the address", r.status_code == 400 and "bob@example.com" in r.json()["message"], r.text)
r = send({"to": "alice@example.com", "bcc": "carl@example.com", "subject": "O5", "text": "x", "smime": {"encrypt": True, "certs": [ALICE_DER]}})
ok("out: Bcc with encryption refused", r.status_code == 400 and "Bcc" in r.json()["message"], r.text)
r = send({"to": "alice@example.com", "subject": "O6", "text": "x", "smime": {"sign": True}}, key=False)
ok("out: signing without a key refused", r.status_code == 400, r.text)
r = s.post(f"{BASE}/api/send", files=[("meta", (None, json.dumps({"to": "alice@example.com", "subject": "O7", "text": "x", "smime": {"sign": True}})))],
           headers={**H, "x-postern-key": SEALED[:-8] + "AAAAAAAA"})
ok("out: unusable key refused with a clear message", r.status_code == 400 and "again" in r.json()["message"], r.text)
ok("out: nothing was sent for the refused ones", len(os.listdir(SINK)) == before)

r = send({"to": "alice@example.com", "subject": "O8 encrypted draft", "text": "draft secret", "draft": True,
          "smime": {"encrypt": True, "certs": [ALICE_DER]}})
ok("draft: saved", r.status_code == 200, r.text)
im = imap()
im.select("Drafts")
typ, data = im.search(None, "SUBJECT", '"O8 encrypted draft"')
ids = data[0].split()
typ, data = im.fetch(ids[-1], "(RFC822)")
im.logout()
draft_raw = data[0][1]
ok("draft: stored encrypted on the server", b"enveloped-data" in draft_raw and b"draft secret" not in draft_raw)
_, v = view("O8 encrypted draft", mailbox=DRAFTS)
ok("draft: readable with the key", "draft secret" in v["text"], v)

r = send({"to": "alice@example.com", "subject": "O9 forwarded", "text": "fwd",
          "forward": {"mailbox": INBOX, "id": m6["id"], "parts": [att[0]["part"]]}})
ok("forward: attachment taken from an encrypted message", r.status_code == 200, r.text)
raw = last_sent()
ok("forward: attachment content intact", base64.b64encode(PDF)[:60] in raw.replace(b"\r\n", b""))

ec_sealed = imp(f"{D}/ec.p12").json()["sealed"]
r = s.post(f"{BASE}/api/send", headers={**H, "x-postern-key": ec_sealed},
           files=[("meta", (None, json.dumps({"to": "alice@example.com", "subject": "O10 EC signed", "text": "ec", "sent_mailbox": SENT, "smime": {"sign": True}})))])
ok("out: EC key signs (ECDSA P-256)", r.status_code == 200, r.text)
v = verify_with_openssl(last_sent())
ok("out: OpenSSL verifies the ECDSA signature", v.returncode == 0, v.stderr.decode())

print(f"\nALL {len(passed)} S/MIME CHECKS PASSED")
