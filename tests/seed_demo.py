"""Fills the IMAP test account with a few realistic messages for manual and browser tests.
usage: seed_demo.py HOST PORT USER PASS"""
import imaplib, sys, time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

host, port, user, pw = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360f8cfc00000030101008a7f6f5d0000000049454e44ae426082")

def msg(frm, subject, text, html=None, attach=None, age_h=0, inline_png=False):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "Demo User <demouser@example.com>", subject
    m["Date"] = formatdate(time.time() - age_h * 3600, localtime=True)
    m["Message-ID"] = make_msgid(domain="example.com")
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
        if inline_png:
            m.get_payload()[1].add_related(PNG, "image", "png", cid="<logo@example.com>")
    for name, data, mt in attach or []:
        m.add_attachment(data, maintype=mt[0], subtype=mt[1], filename=name)
    return m.as_bytes(), time.time() - age_h * 3600

NEWS = """<div style="max-width:600px;margin:0 auto;font-family:Helvetica,Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;border-radius:12px"><tr><td style="padding:28px 32px;color:#fff">
<img src="cid:logo@example.com" width="1" height="1" alt="">
<h1 style="margin:0;font-size:24px">Harbor Weekly</h1><p style="margin:6px 0 0;color:#cbd5e1">Issue 48 &middot; what shipped this week</p></td></tr></table>
<h2 style="font-size:18px;margin:24px 0 8px">Faster search, calmer inbox</h2>
<p style="color:#334155;line-height:1.6">Search now answers in under a second on large mailboxes. We also redesigned the reading pane so long threads are easier to follow.</p>
<p><a href="https://example.com/changelog" style="display:inline-block;background:#4f46e5;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">Read the changelog</a></p>
<img src="https://tracker.example/open.gif?u=42" width="1" height="1" alt="">
<img src="https://images.example/banner.png" width="560" alt="Banner">
<script>document.title='pwned'</script>
<p style="color:#94a3b8;font-size:12px" onclick="alert(1)">You get this because you subscribed. <a href="https://example.com/unsubscribe">Unsubscribe</a></p></div>"""

items = [
    msg("Mara Lindqvist <mara@nordwind.example>", "Angebot für das Hafenprojekt", "Hallo,\n\nanbei wie besprochen das überarbeitete Angebot. Die Positionen 3 und 4 haben wir zusammengefasst.\n\nKannst du bis Donnerstag Rückmeldung geben?\n\nViele Grüße\nMara\n", attach=[("Angebot-2026-114.pdf", b"%PDF-1.4\n" + b"0" * 48213, ("application", "pdf")), ("Kalkulation.xlsx", b"PK" + b"1" * 20311, ("application", "octet-stream"))], age_h=1),
    msg("Harbor Weekly <news@harbor.example>", "Issue 48: faster search, calmer inbox", "Harbor Weekly, issue 48.\nSearch is faster. Read more: https://example.com/changelog\n", html=NEWS, age_h=3, inline_png=True),
    msg("Jonas Becker <jonas.becker@example.org>", "Re: Termin nächste Woche", "Passt für mich.\n\nDienstag 10 Uhr im großen Raum? Ich bringe die Unterlagen mit.\n\n> Am Montag schrieb Demo User:\n> Hast du nächste Woche Zeit für das Review?\n> Vorschlag: Dienstag oder Mittwoch.\n", age_h=7),
    msg("GitLab <gitlab@code.example>", "postern | Pipeline #8812 passed", "Pipeline #8812 for main passed in 4 minutes 12 seconds.\n\nhttps://code.example/postern/-/pipelines/8812\n", age_h=26),
    msg("Aiko Tanaka <aiko@studio.example>", "Photos from Saturday", "Hi!\n\nHere are a few favourites from Saturday. The light at the harbour was unreal.\n\nAiko\n", attach=[("harbour-01.png", PNG, ("image", "png"))], age_h=50),
    msg("Stadtwerke <service@stadtwerke.example>", "Ihre Abrechnung für Oktober", "Guten Tag,\n\nIhre Abrechnung für Oktober steht im Kundenportal bereit.\nBetrag: 84,20 EUR, fällig am 30.11.\n", age_h=120),
]
im = imaplib.IMAP4(host, port)
im.login(user, pw)
for raw, when in reversed(items):
    im.append("INBOX", "", imaplib.Time2Internaldate(when), raw)
im.select("INBOX")
typ, data = im.uid("search", None, "ALL")
uids = data[0].split()
for u in uids[-3:-1]:
    pass
im.uid("store", uids[-4], "+FLAGS", "(\\Seen)")
im.uid("store", uids[-5], "+FLAGS", "(\\Seen \\Flagged)")
im.uid("store", uids[-6], "+FLAGS", "(\\Seen)")
for name in ("Archive", "Projects", "Projects/Harbour", "Receipts"):
    im.create(name)
im.logout()
print("seeded", len(items))
