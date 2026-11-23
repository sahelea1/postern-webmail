"""A small in-memory JMAP server for tests (RFC 8620 core, RFC 8621 mail).

It is deliberately strict where clients tend to be sloppy: it checks the
`using` list, resolves result references, applies patch paths literally and
reports per-item errors the way the RFCs describe. It advertises its URLs on
a different host name than the one it listens on, like a server behind a
proxy would, so that origin pinning in the gateway is exercised.

usage: jmap_mock.py <port> <user> <password> <log-file>
"""
import base64, email, email.policy, hashlib, json, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, USER, PASSWORD, LOG = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
ACCOUNT = "acc1"
PUBLIC = "https://public-name.invalid"  # not reachable on purpose
CORE, MAIL, SUBMISSION = "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"

mailboxes = {
    "mb-inbox": {"name": "Inbox", "parentId": None, "role": "inbox", "sortOrder": 1},
    "mb-drafts": {"name": "Drafts", "parentId": None, "role": "drafts", "sortOrder": 2},
    "mb-sent": {"name": "Sent", "parentId": None, "role": "sent", "sortOrder": 3},
    "mb-trash": {"name": "Trash", "parentId": None, "role": "trash", "sortOrder": 4},
    "mb-archive": {"name": "Archive", "parentId": None, "role": "archive", "sortOrder": 5},
}
emails, blobs, counter = {}, {}, [0]


def new_id(prefix):
    counter[0] += 1
    return f"{prefix}{counter[0]}"


def store_blob(data):
    bid = "B" + hashlib.sha256(data).hexdigest()[:20]
    blobs[bid] = data
    return bid


def add_email(raw, mailbox_ids, keywords, received=None):
    eid = new_id("M")
    emails[eid] = {"blobId": store_blob(raw), "mailboxIds": dict(mailbox_ids), "keywords": dict(keywords),
                   "raw": raw, "receivedAt": received or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    return eid


def addresses(msg, header):
    out = []
    for h in msg.get_all(header, []):
        for a in getattr(h, "addresses", []):
            out.append({"name": a.display_name or None, "email": a.addr_spec})
    return out or None


def email_props(eid, props):
    e = emails[eid]
    msg = email.message_from_bytes(e["raw"], policy=email.policy.default)
    body = msg.get_body(preferencelist=("plain", "html"))
    text = body.get_content() if body else ""
    full = {
        "id": eid, "blobId": e["blobId"], "threadId": "T" + eid, "mailboxIds": e["mailboxIds"],
        "keywords": e["keywords"], "size": len(e["raw"]), "receivedAt": e["receivedAt"],
        "subject": str(msg["subject"]) if msg["subject"] is not None else None,
        "from": addresses(msg, "from"), "to": addresses(msg, "to"),
        "preview": " ".join(text.split())[:256], "hasAttachment": any(True for _ in msg.iter_attachments()),
    }
    if props is None:
        return full
    unknown = [p for p in props if p not in full]
    if unknown:
        raise MethodError("invalidArguments", f"unknown properties {unknown}")
    return {p: full[p] for p in set(props) | {"id"}}


class MethodError(Exception):
    def __init__(self, kind, description=""):
        self.kind, self.description = kind, description


def pointer(value, path):
    if path == "":
        return value
    cur = [value]
    for token in path.lstrip("/").split("/"):
        nxt = []
        for c in cur:
            if token == "*":
                nxt.extend(c)
            elif isinstance(c, list):
                nxt.append(c[int(token)])
            else:
                nxt.append(c[token.replace("~1", "/").replace("~0", "~")])
        cur = nxt
    return cur if "*" in path else cur[0]


def resolve_refs(args, done):
    out = {}
    for k, v in args.items():
        if k.startswith("#"):
            for name, result, call_id in done:
                if call_id == v["resultOf"] and name == v["name"]:
                    out[k[1:]] = pointer(result, v["path"])
                    break
            else:
                raise MethodError("invalidResultReference")
        else:
            out[k] = v
    return out


def need_account(args):
    if args.get("accountId") != ACCOUNT:
        raise MethodError("accountNotFound")


def apply_patch(obj, patch):
    for path, value in patch.items():
        parts = path.split("/")
        if parts[0] not in ("keywords", "mailboxIds"):
            raise KeyError(path)
        if len(parts) == 1:
            if not isinstance(value, dict):
                raise ValueError(path)
            obj[parts[0]] = dict(value)
        elif len(parts) == 2:
            if value is None:
                obj[parts[0]].pop(parts[1], None)
            elif value is True:
                obj[parts[0]][parts[1]] = True
            else:
                raise ValueError(path)
        else:
            raise KeyError(path)
    if not obj["mailboxIds"] or any(m not in mailboxes for m in obj["mailboxIds"]):
        raise ValueError("mailboxIds")


def m_mailbox_get(a):
    need_account(a)
    out = []
    for mid, m in mailboxes.items():
        if a.get("ids") is not None and mid not in a["ids"]:
            continue
        inside = [e for e in emails.values() if mid in e["mailboxIds"]]
        full = dict(m, id=mid, totalEmails=len(inside),
                    unreadEmails=sum(1 for e in inside if "$seen" not in e["keywords"]))
        props = a.get("properties")
        out.append(full if props is None else {p: full[p] for p in set(props) | {"id"}})
    return {"accountId": ACCOUNT, "state": "s", "list": out, "notFound": []}


def m_mailbox_set(a):
    need_account(a)
    r = {"accountId": ACCOUNT, "oldState": "s", "newState": "s", "created": {}, "updated": {}, "destroyed": [],
         "notCreated": {}, "notUpdated": {}, "notDestroyed": {}}
    for cid, obj in (a.get("create") or {}).items():
        name, parent = obj.get("name"), obj.get("parentId")
        if not name or (parent is not None and parent not in mailboxes):
            r["notCreated"][cid] = {"type": "invalidProperties"}
        elif any(m["name"] == name and m["parentId"] == parent for m in mailboxes.values()):
            r["notCreated"][cid] = {"type": "invalidProperties", "description": "a folder with this name exists"}
        else:
            mid = new_id("mb-")
            mailboxes[mid] = {"name": name, "parentId": parent, "role": None, "sortOrder": 10}
            r["created"][cid] = {"id": mid}
    for mid, patch in (a.get("update") or {}).items():
        if mid not in mailboxes:
            r["notUpdated"][mid] = {"type": "notFound"}
        elif set(patch) - {"name", "parentId"}:
            r["notUpdated"][mid] = {"type": "invalidProperties"}
        else:
            mailboxes[mid].update(patch)
            r["updated"][mid] = None
    for mid in a.get("destroy") or []:
        inside = [eid for eid, e in emails.items() if mid in e["mailboxIds"]]
        if mid not in mailboxes:
            r["notDestroyed"][mid] = {"type": "notFound"}
        elif mailboxes[mid]["role"]:
            r["notDestroyed"][mid] = {"type": "forbidden"}
        elif inside and not a.get("onDestroyRemoveEmails"):
            r["notDestroyed"][mid] = {"type": "mailboxHasEmail"}
        else:
            for eid in inside:
                del emails[eid]
            del mailboxes[mid]
            r["destroyed"].append(mid)
    return r


def m_email_query(a):
    need_account(a)
    f = a.get("filter") or {}
    if set(f) - {"inMailbox", "text"}:
        raise MethodError("unsupportedFilter")
    ids = []
    for eid, e in emails.items():
        if "inMailbox" in f and f["inMailbox"] not in e["mailboxIds"]:
            continue
        if "text" in f:
            msg = email.message_from_bytes(e["raw"], policy=email.policy.default)
            body = msg.get_body(preferencelist=("plain", "html"))
            hay = " ".join([str(msg["subject"]), str(msg["from"]), str(msg["to"]), body.get_content() if body else ""])
            if f["text"].lower() not in hay.lower():
                continue
        ids.append(eid)
    sort = a.get("sort") or [{"property": "receivedAt", "isAscending": True}]
    if sort[0]["property"] != "receivedAt":
        raise MethodError("unsupportedSort")
    ids.sort(key=lambda i: (emails[i]["receivedAt"], int(i[1:])), reverse=not sort[0].get("isAscending", True))
    pos, limit = a.get("position", 0), a.get("limit", 100)
    r = {"accountId": ACCOUNT, "queryState": "q", "canCalculateChanges": False, "position": pos,
         "ids": ids[pos:pos + limit]}
    if a.get("calculateTotal"):
        r["total"] = len(ids)
    return r


def m_email_get(a):
    need_account(a)
    ids = a.get("ids")
    if ids is None:
        raise MethodError("requestTooLarge")
    found = [email_props(i, a.get("properties")) for i in ids if i in emails]
    return {"accountId": ACCOUNT, "state": "s", "list": found, "notFound": [i for i in ids if i not in emails]}


def m_email_set(a):
    need_account(a)
    if a.get("create"):
        raise MethodError("invalidArguments", "create is not supported by this mock")
    r = {"accountId": ACCOUNT, "oldState": "s", "newState": "s", "created": None, "updated": {}, "destroyed": [],
         "notUpdated": {}, "notDestroyed": {}}
    for eid, patch in (a.get("update") or {}).items():
        if eid not in emails:
            r["notUpdated"][eid] = {"type": "notFound"}
            continue
        trial = {"keywords": dict(emails[eid]["keywords"]), "mailboxIds": dict(emails[eid]["mailboxIds"])}
        try:
            apply_patch(trial, patch)
        except (KeyError, ValueError) as ex:
            r["notUpdated"][eid] = {"type": "invalidPatch", "description": str(ex)}
            continue
        emails[eid].update(trial)
        r["updated"][eid] = None
    for eid in a.get("destroy") or []:
        if eid in emails:
            del emails[eid]
            r["destroyed"].append(eid)
        else:
            r["notDestroyed"][eid] = {"type": "notFound"}
    return r


def m_email_import(a):
    need_account(a)
    r = {"accountId": ACCOUNT, "oldState": "s", "newState": "s", "created": {}, "notCreated": {}}
    for cid, obj in a["emails"].items():
        if obj.get("blobId") not in blobs:
            r["notCreated"][cid] = {"type": "blobNotFound"}
        elif not obj.get("mailboxIds") or any(m not in mailboxes for m in obj["mailboxIds"]):
            r["notCreated"][cid] = {"type": "invalidProperties", "properties": ["mailboxIds"]}
        else:
            eid = add_email(blobs[obj["blobId"]], obj["mailboxIds"], obj.get("keywords") or {})
            r["created"][cid] = {"id": eid, "blobId": obj["blobId"], "threadId": "T" + eid,
                                 "size": len(blobs[obj["blobId"]])}
    return r


def m_identity_get(a):
    need_account(a)
    return {"accountId": ACCOUNT, "state": "s", "notFound": [],
            "list": [{"id": "ident1", "name": "Demo User", "email": USER, "mayDelete": False}]}


def m_submission_set(a):
    need_account(a)
    r = {"accountId": ACCOUNT, "oldState": "s", "newState": "s", "created": {}, "notCreated": {}}
    made = {}
    for cid, obj in (a.get("create") or {}).items():
        env = obj.get("envelope")
        if obj.get("emailId") not in emails or obj.get("identityId") != "ident1":
            r["notCreated"][cid] = {"type": "invalidProperties"}
        elif not env or not env.get("rcptTo") or env["mailFrom"]["email"].lower() != USER.lower():
            r["notCreated"][cid] = {"type": "forbiddenFrom"}
        else:
            raw = emails[obj["emailId"]]["raw"]
            with open(LOG, "a") as f:
                f.write(json.dumps({"from": env["mailFrom"]["email"], "rcpt": [x["email"] for x in env["rcptTo"]],
                                    "size": len(raw)}) + "\n")
            add_email(raw, {"mb-inbox": True}, {})  # "delivery": everything lands in the one inbox
            sid = new_id("S")
            made[cid] = obj["emailId"]
            r["created"][cid] = {"id": sid}
    for ref in a.get("onSuccessDestroyEmail") or []:
        if ref.startswith("#") and ref[1:] in made:
            emails.pop(made[ref[1:]], None)
    return r


METHODS = {"Mailbox/get": (m_mailbox_get, MAIL), "Mailbox/set": (m_mailbox_set, MAIL),
           "Email/query": (m_email_query, MAIL), "Email/get": (m_email_get, MAIL), "Email/set": (m_email_set, MAIL),
           "Email/import": (m_email_import, MAIL), "Identity/get": (m_identity_get, SUBMISSION),
           "EmailSubmission/set": (m_submission_set, SUBMISSION)}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, status, body=b"", ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def authed(self):
        want = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        if self.headers.get("Authorization") != want:
            self.reply(401, {"type": "about:blank", "status": 401}, extra={"WWW-Authenticate": "Basic realm=jmap"})
            return False
        return True

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/.well-known/jmap":
            # A redirect to the public name, as a proxied server would send.
            return self.reply(307, extra={"Location": PUBLIC + "/jmap/session"})
        if not self.authed():
            return
        if path == "/jmap/session":
            return self.reply(200, {
                "capabilities": {CORE: {"maxSizeUpload": 50000000, "maxSizeRequest": 10000000}, MAIL: {}, SUBMISSION: {}},
                "accounts": {ACCOUNT: {"name": USER, "isPersonal": True, "accountCapabilities": {MAIL: {}, SUBMISSION: {}}}},
                "primaryAccounts": {MAIL: ACCOUNT, SUBMISSION: ACCOUNT}, "username": USER,
                "apiUrl": PUBLIC + "/jmap/api/",
                "downloadUrl": PUBLIC + "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
                "uploadUrl": PUBLIC + "/jmap/upload/{accountId}/",
                "eventSourceUrl": PUBLIC + "/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}",
                "state": "0"})
        parts = path.strip("/").split("/")
        if parts[:2] == ["jmap", "download"] and len(parts) == 5 and parts[2] == ACCOUNT:
            data = blobs.get(parts[3])
            if data is None:
                return self.reply(404, {"type": "notFound"})
            return self.reply(200, data, ctype="application/octet-stream")
        self.reply(404, {"type": "notFound"})

    def do_POST(self):
        if not self.authed():
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        path = urllib.parse.urlparse(self.path).path
        if path == f"/jmap/upload/{ACCOUNT}/":
            bid = store_blob(body)
            return self.reply(201, {"accountId": ACCOUNT, "blobId": bid, "type": self.headers.get("Content-Type"),
                                    "size": len(body)})
        if path != "/jmap/api/":
            return self.reply(404, {"type": "notFound"})
        try:
            req = json.loads(body)
            using, calls = req["using"], req["methodCalls"]
        except Exception:
            return self.reply(400, {"type": "urn:ietf:params:jmap:error:notRequest", "status": 400})
        if CORE not in using:
            return self.reply(400, {"type": "urn:ietf:params:jmap:error:unknownCapability", "status": 400})
        done = []
        for name, args, call_id in calls:
            try:
                if name not in METHODS or METHODS[name][1] not in using:
                    raise MethodError("unknownMethod")
                result = METHODS[name][0](resolve_refs(args, done))
                done.append((name, result, call_id))
            except MethodError as e:
                done.append(("error", {"type": e.kind, "description": e.description}, call_id))
            except Exception as e:  # malformed arguments
                done.append(("error", {"type": "invalidArguments", "description": repr(e)}, call_id))
        self.reply(200, {"methodResponses": [[n, r, c] for n, r, c in done], "sessionState": "0"})


def seed():
    def msg(frm, subject, body, html=None):
        m = email.message.EmailMessage(policy=email.policy.SMTP)
        m["From"], m["To"], m["Subject"] = frm, USER, subject
        m["Message-ID"] = f"<{hashlib.md5(subject.encode()).hexdigest()}@example.com>"
        m.set_content(body)
        if html:
            m.add_alternative(html, subtype="html")
        return m.as_bytes()
    add_email(msg("Friend <friend@example.com>", "Welcome", "First message in the inbox."), {"mb-inbox": True},
              {"$seen": True}, "2026-01-01T10:00:00Z")
    add_email(msg("News <news@example.com>", "Newsletter", "Plain part.",
                  '<p>Hello <b>reader</b><script>window.pwned=1</script><img src="https://tracker.example/p.gif"></p>'),
              {"mb-inbox": True}, {}, "2026-02-01T10:00:00Z")


if __name__ == "__main__":
    seed()
    print("jmap mock on", PORT, flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
