"""End-to-end test of the Postern API against a live mail server.

Works for both back ends. It signs in, sends real messages, reads them back,
moves, flags, searches and deletes them, and checks the security behaviour
(cross-site checks, cookie flags, sanitised HTML, response headers).

usage: e2e.py --base http://127.0.0.1:8080 --email U --password P
              [--smtp-log FILE] [--imap HOST:PORT:USER:PASS] [--evil-subject S]
              [--admin http://127.0.0.1:8081 --binary PATH --data-dir DIR]
"""
import argparse, imaplib, json, os, subprocess, sys, time
import requests

ap = argparse.ArgumentParser()
ap.add_argument("--base", required=True)
ap.add_argument("--email", required=True)
ap.add_argument("--password", required=True)
ap.add_argument("--smtp-log")
ap.add_argument("--imap")
ap.add_argument("--evil-subject", default="Newsletter")
ap.add_argument("--admin")
ap.add_argument("--binary")
ap.add_argument("--data-dir")
ap.add_argument("--skip-rate-limit", action="store_true")
ap.add_argument("--any-domain", action="store_true", help="the server list uses the \"*\" domain: no address is refused up front")
ap.add_argument("--trash-name", help="use (and create) this folder as trash; for servers whose Trash is read-only")
A = ap.parse_args()
B = A.base
H = {"x-postern": "1"}
passed = []


def ok(name, cond, detail=""):
    if not cond:
        print(f"FAIL  {name}  {detail}")
        sys.exit(1)
    passed.append(name)
    print(f"ok    {name}")


EVIL = (
    "From: News <news@example.com>\r\nTo: {to}\r\nSubject: {subj}\r\n"
    "Message-ID: <evil1@example.com>\r\nMIME-Version: 1.0\r\n"
    'Content-Type: multipart/related; boundary="rel"\r\n\r\n'
    "--rel\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    '<p>Hello <b>reader</b><script>window.pwned=1</script>'
    '<img src="https://tracker.example/p.gif"><img src="cid:logo1" onerror="window.pwned=2">'
    '<a href="javascript:window.pwned=3">x</a><form action="https://evil.example"><input name=p></form></p>\r\n'
    "--rel\r\nContent-Type: image/png\r\nContent-ID: <logo1>\r\nContent-Transfer-Encoding: base64\r\n\r\n"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==\r\n"
    "--rel--\r\n"
)

s = requests.Session()

# ---- before sign-in ---------------------------------------------------------
r = s.get(f"{B}/api/config")
ok("public config", r.status_code == 200 and r.json()["configured"] is True)
ok("api needs a session", s.get(f"{B}/api/me").status_code == 401)
ok("mailboxes need a session", s.get(f"{B}/api/mailboxes").status_code == 401)
cred = {"email": A.email, "password": A.password}
ok("POST without custom header is refused", s.post(f"{B}/api/login", json=cred).status_code == 403)
ok("POST from another origin is refused",
   s.post(f"{B}/api/login", json=cred, headers={**H, "Origin": "https://evil.example"}).status_code == 403)
ok("POST marked cross-site is refused",
   s.post(f"{B}/api/login", json=cred, headers={**H, "Sec-Fetch-Site": "cross-site"}).status_code == 403)
r = s.post(f"{B}/api/login", json={"email": A.email, "password": "wrong-password"}, headers=H)
ok("wrong password", r.status_code == 401 and r.json()["error"] == "bad_credentials")
r = s.post(f"{B}/api/login", json={"email": "someone@not-configured.example", "password": "x"}, headers=H)
if A.any_domain:
    ok("any domain is passed to the server, which refuses it", r.status_code == 401 and r.json()["error"] == "bad_credentials")
else:
    ok("unknown domain", r.status_code == 403 and r.json()["error"] == "unknown_domain")
r = s.post(f"{B}/api/login", json={"email": "no-at-sign", "password": "x"}, headers=H)
ok("malformed address", r.status_code == 401)

r = s.get(f"{B}/")
ok("app shell served", r.status_code == 200 and "text/html" in r.headers["content-type"])
csp = r.headers.get("content-security-policy", "")
ok("app shell policy", "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
   and "require-trusted-types-for 'script'" in csp, csp)
ok("app shell headers", r.headers.get("x-content-type-options") == "nosniff"
   and r.headers.get("referrer-policy") == "no-referrer" and r.headers.get("x-frame-options") == "DENY"
   and r.headers.get("cross-origin-opener-policy") == "same-origin")
ok("unknown path is 404", s.get(f"{B}/no/such/file.js").status_code == 404)
ok("health", s.get(f"{B}/healthz").text == "ok")

# ---- sign-in ----------------------------------------------------------------
r = s.post(f"{B}/api/login", json=cred, headers=H)
ok("sign-in", r.status_code == 200, r.text)
setc = r.headers.get("set-cookie", "")
ok("cookie flags", "HttpOnly" in setc and "SameSite=Strict" in setc and "Path=/" in setc, setc)
cookie_value = setc.split(";")[0].split("=", 1)[1]
ok("cookie hides credentials", A.password not in cookie_value and A.email.split("@")[0] not in cookie_value)
me = s.get(f"{B}/api/me").json()
ok("me", me["email"] == A.email.lower() and me["protocol"] in ("imap", "jmap"), str(me))
PROTO = me["protocol"]

tampered = cookie_value[:-3] + ("AAA" if not cookie_value.endswith("AAA") else "BBB")
name = setc.split("=", 1)[0]
ok("tampered cookie is refused", requests.get(f"{B}/api/me", cookies={name: tampered}).status_code == 401)


def boxes():
    r = s.get(f"{B}/api/mailboxes")
    assert r.status_code == 200, r.text
    return r.json()["mailboxes"]


def by_role(role):
    return next((m for m in boxes() if m["role"] == role), None)


def by_name(n):
    return next((m for m in boxes() if m["name"] == n), None)


def listing(mailbox, q=None):
    params = {"mailbox": mailbox}
    if q:
        params["q"] = q
    r = s.get(f"{B}/api/messages", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def find(mailbox, subject, tries=30):
    for _ in range(tries):
        for m in listing(mailbox)["items"]:
            if m["subject"] == subject:
                return m
        time.sleep(0.2)
    return None


def send(meta, files=()):
    return s.post(f"{B}/api/send", headers=H,
                  files=[("meta", (None, json.dumps(meta), "application/json"))] +
                        [("file", f) for f in files])


inbox, sent, trash = by_role("inbox"), by_role("sent"), by_role("trash")
ok("special folders found", inbox and sent and trash, str(boxes()))
drafts = by_role("drafts")
if not drafts:
    r = s.post(f"{B}/api/mailboxes/create", json={"name": "Drafts"}, headers=H)
    ok("create Drafts", r.status_code == 200, r.text)
    drafts = by_role("drafts")
ok("drafts folder", drafts is not None)
if A.trash_name:
    if not by_name(A.trash_name):
        s.post(f"{B}/api/mailboxes/create", json={"name": A.trash_name}, headers=H)
    trash = by_name(A.trash_name)
IN, SENT, TRASH, DRAFTS = inbox["id"], sent["id"], trash["id"], drafts["id"]

page = listing(IN)
ok("inbox lists messages", page["total"] >= 1 and len(page["items"]) >= 1)
first = page["items"][0]
ok("summary fields", all(k in first for k in
                         ("id", "subject", "from", "date", "seen", "flagged", "preview", "attachment", "size")))
dates = [m["date"] for m in page["items"] if m["date"]]
ok("newest first", dates == sorted(dates, reverse=True), str(dates))

# ---- folders ----------------------------------------------------------------
FOLDER = "Prüfung – Tests"
for stale in (FOLDER, "Renamed äöü"):
    old = by_name(stale)
    if old:
        s.post(f"{B}/api/mailboxes/delete", json={"id": old["id"]}, headers=H)
r = s.post(f"{B}/api/mailboxes/create", json={"name": FOLDER}, headers=H)
ok("create folder with non-ASCII name", r.status_code == 200 and by_name(FOLDER) is not None, r.text)
r = s.post(f"{B}/api/mailboxes/create", json={"name": "bad\r\nname"}, headers=H)
ok("folder name with line break refused", r.status_code == 400)
r = s.post(f"{B}/api/mailboxes/rename", json={"id": by_name(FOLDER)["id"], "name": "Renamed äöü"}, headers=H)
ok("rename folder", r.status_code == 200 and by_name("Renamed äöü") and not by_name(FOLDER), r.text)
FID = by_name("Renamed äöü")["id"]

# ---- send and receive -------------------------------------------------------
token = f"tok{int(time.time() * 1000)}"
subject = f"Grüße {token} ☃"
blob = bytes(range(256)) * 40
if A.smtp_log and os.path.exists(A.smtp_log):
    os.remove(A.smtp_log)
r = send({"from_name": "Demo Üser", "to": f"Me Myself <{A.email}>", "cc": "copy@example.org",
          "bcc": "hidden@example.org", "subject": subject,
          "text": f"Hello,\n\nthis is the body {token}.\näöü\n", "sent_mailbox": SENT},
         files=[("data ü.bin", blob, "application/octet-stream")])
ok("send", r.status_code == 200 and r.json()["ok"], r.text)
if A.smtp_log:
    env = json.loads(open(A.smtp_log).read().strip().splitlines()[-1])
    ok("envelope has every recipient incl. bcc",
       sorted(env["rcpt"]) == sorted([A.email, "copy@example.org", "hidden@example.org"]), str(env))
    ok("envelope sender", env["from"] == A.email)
got = find(IN, subject)
ok("message arrives in the inbox", got is not None)
ok("arrives unread with attachment mark", got["seen"] is False and got["attachment"] is True, str(got))
ok("preview from body", token in got["preview"], got["preview"])
ok("sender name encoded and decoded", got["from"][0]["name"] == "Demo Üser", str(got["from"]))
v = s.get(f"{B}/api/message", params={"mailbox": IN, "id": got["id"]}).json()
ok("view text", f"this is the body {token}" in v["text"] and "äöü" in v["text"])
ok("view recipients", v["to"][0]["email"] == A.email and v["cc"][0]["email"] == "copy@example.org")
ok("received copy has no Bcc", v["bcc"] == [])
ok("view attachment", len(v["attachments"]) == 1 and v["attachments"][0]["name"] == "data ü.bin"
   and v["attachments"][0]["size"] == len(blob), str(v["attachments"]))
r = s.get(f"{B}/api/message/part", params={"mailbox": IN, "id": got["id"], "part": v["attachments"][0]["part"]})
ok("attachment bytes identical", r.content == blob)
ok("attachment is a download", r.headers["content-type"] == "application/octet-stream"
   and r.headers["content-disposition"].startswith("attachment")
   and r.headers.get("x-content-type-options") == "nosniff"
   and "sandbox" in r.headers.get("content-security-policy", ""), str(r.headers))
r = s.get(f"{B}/api/message/part", params={"mailbox": IN, "id": got["id"], "part": v["attachments"][0]["part"], "inline": 1})
ok("non-image is never served inline", r.headers["content-type"] == "application/octet-stream")
ok("unknown part", s.get(f"{B}/api/message/part", params={"mailbox": IN, "id": got["id"], "part": 0}).status_code == 404)
copy = find(SENT, subject)
ok("copy filed in Sent", copy is not None and copy["seen"] is True, str(copy))
cv = s.get(f"{B}/api/message", params={"mailbox": SENT, "id": copy["id"]}).json()
ok("Sent copy keeps Bcc", [a["email"] for a in cv["bcc"]] == ["hidden@example.org"], str(cv["bcc"]))
raw = s.get(f"{B}/api/message/raw", params={"mailbox": IN, "id": got["id"]})
ok("raw download", b"Subject:" in raw.content and raw.headers["content-disposition"].startswith("attachment")
   and b"hidden@example.org" not in raw.content)
rawv = s.get(f"{B}/api/message/raw", params={"mailbox": IN, "id": got["id"], "view": 1})
ok("raw view is plain text", rawv.headers["content-type"].startswith("text/plain")
   and rawv.headers.get("x-content-type-options") == "nosniff")

r = send({"to": "", "subject": "no recipients", "text": "x", "sent_mailbox": SENT})
ok("send without recipients refused", r.status_code == 400)
r = send({"to": "not an address", "subject": "x", "text": "x"})
ok("send to invalid address refused", r.status_code == 400)
r = requests.post(f"{B}/api/send", cookies=s.cookies, files=[("meta", (None, "{}", "application/json"))])
ok("send without custom header refused", r.status_code == 403)

# ---- reply ------------------------------------------------------------------
rsubj = f"Re: {subject}"
r = send({"to": A.email, "subject": rsubj, "text": "reply body", "sent_mailbox": SENT,
          "in_reply_to": v["message_id"], "references": v["references"] + [v["message_id"]],
          "answered": {"mailbox": IN, "id": got["id"]}})
ok("send reply", r.status_code == 200, r.text)
reply = find(IN, rsubj)
ok("reply arrives", reply is not None)
rv = s.get(f"{B}/api/message", params={"mailbox": IN, "id": reply["id"]}).json()
ok("reply references the original", v["message_id"] in rv["references"], str(rv["references"]))
again = next(m for m in listing(IN)["items"] if m["id"] == got["id"])
ok("original flagged as answered", again["answered"] is True)

# ---- forward with the original attachment -----------------------------------
fsubj = f"Fwd: {subject}"
r = send({"to": A.email, "subject": fsubj, "text": "see attachment", "sent_mailbox": SENT,
          "forward": {"mailbox": IN, "id": got["id"], "parts": [v["attachments"][0]["part"]]}})
ok("forward", r.status_code == 200, r.text)
fw = find(IN, fsubj)
fv = s.get(f"{B}/api/message", params={"mailbox": IN, "id": fw["id"]}).json()
ok("forward carries the attachment", len(fv["attachments"]) == 1 and fv["attachments"][0]["size"] == len(blob))

# ---- flags ------------------------------------------------------------------
def flag(mailbox, ids, name, on):
    return s.post(f"{B}/api/flags", json={"mailbox": mailbox, "ids": ids, "flag": name, "on": on}, headers=H)


def row(mailbox, mid):
    return next((m for m in listing(mailbox)["items"] if m["id"] == mid), None)


unread_before = by_role("inbox")["unread"]
ok("mark read", flag(IN, [got["id"]], "seen", True).status_code == 200 and row(IN, got["id"])["seen"] is True)
ok("unread count drops", by_role("inbox")["unread"] == unread_before - 1)
ok("mark unread", flag(IN, [got["id"]], "seen", False).status_code == 200 and row(IN, got["id"])["seen"] is False)
ok("star", flag(IN, [got["id"]], "flagged", True).status_code == 200 and row(IN, got["id"])["flagged"] is True)
ok("unstar", flag(IN, [got["id"]], "flagged", False).status_code == 200 and row(IN, got["id"])["flagged"] is False)
ok("unknown flag refused", flag(IN, [got["id"]], "deleted", True).status_code == 400)
ok("empty id list refused", flag(IN, [], "seen", True).status_code == 400)
bad_ids = ["1:*", "1 OR 2", "1\r\nA1 LOGOUT", "../x", "a/b"]
ok("malformed ids refused", all(flag(IN, [b], "seen", True).status_code == 400 for b in bad_ids))
ok("malformed folder refused", flag("IN\r\nBOX", [got["id"]], "seen", True).status_code == 400)

# ---- search -----------------------------------------------------------------
res = listing(IN, q=token)
ok("search finds by body or subject", res["total"] >= 1 and any(m["id"] == got["id"] for m in res["items"]), str(res["total"]))
ok("search with no match", listing(IN, q="zzz-no-such-text-zzz")["total"] == 0)
ok("search survives quotes and umlauts", s.get(f"{B}/api/messages", params={"mailbox": IN, "q": 'a"b\\c ü'}).status_code == 200)

# ---- hostile HTML -----------------------------------------------------------
if A.imap:
    host, port, user, pw = A.imap.split(":")
    im = imaplib.IMAP4(host, int(port))
    im.login(user, pw)
    im.append("INBOX", "", imaplib.Time2Internaldate(time.time()),
              EVIL.format(to=A.email, subj=A.evil_subject).encode())
    im.logout()
evil = find(IN, A.evil_subject)
ok("hostile message present", evil is not None)
ev = s.get(f"{B}/api/message", params={"mailbox": IN, "id": evil["id"]}).json()
ok("hostile message flagged as HTML with remote images", ev["has_html"] and ev["remote_images"] and ev["can_load_images"])
h0 = s.get(f"{B}/api/message/html", params={"mailbox": IN, "id": evil["id"]})
low = h0.text.lower()
ok("HTML body is cleaned", "<b>reader</b>" in low and all(x not in low for x in
   ("<script", "pwned", "onerror", "javascript:", "<form", "<input", "tracker.example")), low[-600:])
c0 = h0.headers["content-security-policy"]
ok("frame policy: no script, no remote", "default-src 'none'" in c0 and "script-src" not in c0
   and "img-src 'self' data:;" in c0 and "sandbox allow-same-origin" in c0 and "allow-scripts" not in c0
   and "frame-ancestors 'self'" in c0, c0)
h1 = s.get(f"{B}/api/message/html", params={"mailbox": IN, "id": evil["id"], "images": 1})
ok("images load only on request", "tracker.example/p.gif" in h1.text and "https:" in h1.headers["content-security-policy"]
   and "<script" not in h1.text.lower())
if A.imap:
    ok("inline image rewritten", "/api/message/cid?" in h0.text, h0.text[-500:])
    r = s.get(f"{B}/api/message/cid", params={"mailbox": IN, "id": evil["id"], "cid": "logo1"})
    ok("inline image served as sniffed PNG", r.status_code == 200 and r.headers["content-type"] == "image/png"
       and r.content.startswith(b"\x89PNG"))
    ok("unknown content id", s.get(f"{B}/api/message/cid", params={"mailbox": IN, "id": evil["id"], "cid": "nope"}).status_code == 404)

# ---- move, trash, destroy ---------------------------------------------------
def post(path, body):
    return s.post(f"{B}{path}", json=body, headers=H)


r = post("/api/move", {"mailbox": IN, "ids": [reply["id"]], "dest": FID})
ok("move to folder", r.status_code == 200 and find(IN, rsubj, tries=1) is None and find(FID, rsubj) is not None, r.text)
ok("move to same folder refused", post("/api/move", {"mailbox": IN, "ids": [got["id"]], "dest": IN}).status_code == 400)
r = post("/api/delete", {"mailbox": IN, "ids": [fw["id"]], "trash": TRASH})
ok("delete moves to trash", r.status_code == 200 and r.json()["permanent"] is False
   and find(IN, fsubj, tries=1) is None and find(TRASH, fsubj) is not None)
in_trash = find(TRASH, fsubj)
r = post("/api/delete", {"mailbox": TRASH, "ids": [in_trash["id"]], "trash": TRASH})
ok("delete inside trash is permanent", r.status_code == 200 and r.json()["permanent"] is True
   and find(TRASH, fsubj, tries=1) is None)

# ---- drafts -----------------------------------------------------------------
dsubj = f"Draft {token}"
r = send({"to": "later@example.org", "subject": dsubj, "text": "v1", "draft": True, "drafts_mailbox": DRAFTS})
ok("save draft", r.status_code == 200 and r.json()["draft"] is True, r.text)
d1 = find(DRAFTS, dsubj)
ok("draft stored with draft flag", d1 is not None and d1["draft"] is True, str(d1))
r = send({"to": "later@example.org", "subject": dsubj, "text": "v2", "draft": True, "drafts_mailbox": DRAFTS,
          "replace_draft": {"mailbox": DRAFTS, "id": d1["id"]}})
time.sleep(0.3)
ds = [m for m in listing(DRAFTS)["items"] if m["subject"] == dsubj]
ok("saving again replaces the draft", r.status_code == 200 and len(ds) == 1 and ds[0]["id"] != d1["id"], str(ds))
dv = s.get(f"{B}/api/message", params={"mailbox": DRAFTS, "id": ds[0]["id"]}).json()
ok("draft has the new text", dv["text"].strip() == "v2")
ok("nothing was sent for drafts", find(IN, dsubj, tries=2) is None)
post("/api/delete", {"mailbox": DRAFTS, "ids": [ds[0]["id"]]})

# ---- clean up and folder delete ----------------------------------------------
r = post("/api/mailboxes/delete", {"id": FID})
ok("delete folder", r.status_code == 200 and by_name("Renamed äöü") is None, r.text)
if PROTO == "imap":
    ok("inbox cannot be deleted", post("/api/mailboxes/delete", {"id": IN}).status_code == 400)
leftovers = [m["id"] for m in listing(IN)["items"] if token in m["subject"]] + [evil["id"]]
post("/api/delete", {"mailbox": IN, "ids": leftovers})
leftovers = [m["id"] for m in listing(SENT)["items"] if token in m["subject"]]
if leftovers:
    post("/api/delete", {"mailbox": SENT, "ids": leftovers})
ok("cleanup", not any(token in m["subject"] for m in listing(IN)["items"]))

# ---- sign-out ---------------------------------------------------------------
old = dict(s.cookies)
r = s.post(f"{B}/api/logout", headers=H)
ok("sign-out clears the cookie", r.status_code == 200 and "Max-Age=0" in r.headers.get("set-cookie", ""))
ok("session gone", s.get(f"{B}/api/me").status_code == 401)
ok("old cookie cannot be replayed", requests.get(f"{B}/api/me", cookies=old).status_code == 401)

# ---- admin console ----------------------------------------------------------
if A.admin:
    a = requests.Session()
    ok("admin api needs sign-in", a.get(f"{A.admin}/api/state").status_code == 401)
    ok("admin page served", a.get(f"{A.admin}/").status_code == 200)
    r = a.get(f"{A.admin}/login", params={"token": "0" * 48}, allow_redirects=False)
    ok("admin: wrong token refused", r.status_code in (302, 303) and "denied" in r.headers["location"]
       and "set-cookie" not in r.headers)
    env2 = dict(os.environ, POSTERN_DATA_DIR=A.data_dir, POSTERN_ADMIN_URL=A.admin)
    link = subprocess.run([A.binary, "admin-link"], env=env2, capture_output=True, text=True).stdout.splitlines()[0]
    r = a.get(link, allow_redirects=False)
    ok("admin: link signs in", r.status_code in (302, 303) and "postern_admin=" in r.headers.get("set-cookie", ""), str(r.headers))
    ok("admin: link works once", "denied" in requests.get(link, allow_redirects=False).headers["location"])
    st = a.get(f"{A.admin}/api/state")
    ok("admin state", st.status_code == 200 and len(st.json()["servers"]) >= 1)
    servers = st.json()["servers"]
    ok("admin: save needs custom header", a.post(f"{A.admin}/api/servers", json={"servers": servers}).status_code == 403)
    bad = [dict(servers[0], id="has space")]
    ok("admin: invalid config refused", a.post(f"{A.admin}/api/servers", json={"servers": bad}, headers=H).status_code == 400)
    extra = servers + [{"id": "extra", "domains": ["extra.example"], "protocol": "jmap", "jmap_url": "https://jmap.extra.example"}]
    r = a.post(f"{A.admin}/api/servers", json={"servers": extra}, headers=H)
    ok("admin: save", r.status_code == 200, r.text)
    ok("admin: file written", 'id = "extra"' in open(os.path.join(A.data_dir, "servers.toml")).read())
    r = requests.post(f"{B}/api/login", json={"email": "x@extra.example", "password": "x"}, headers=H)
    ok("new domain is live without restart", r.status_code != 403, r.text)
    r = a.post(f"{A.admin}/api/servers", json={"servers": servers}, headers=H)
    ok("admin: restore", r.status_code == 200)
    t = a.post(f"{A.admin}/api/test", json=servers[0], headers=H)
    ok("admin: connection test", t.status_code == 200 and all(c["ok"] for c in t.json()["checks"]), t.text)
    ok("admin not reachable through the public port", requests.get(f"{B}/api/state").status_code == 404)

# ---- rate limit (last: it locks this address out for a while) ----------------
if not A.skip_rate_limit:
    codes = [requests.post(f"{B}/api/login", json={"email": A.email, "password": "wrong"}, headers=H).status_code
             for _ in range(12)]
    ok("repeated failures are rate limited", codes[-1] == 429 and 401 in codes, str(codes))
    ok("limit also holds for the right password", requests.post(f"{B}/api/login", json=cred, headers=H).status_code == 429)

print(f"\nALL {len(passed)} CHECKS PASSED ({PROTO})")
