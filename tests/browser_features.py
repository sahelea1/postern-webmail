"""Drives the features of 0.2 in headless Chrome: column widths, colour
themes, remote-image settings, notifications and sound, S/MIME (importing a
key and a certificate, sending signed and encrypted mail, reading it back,
trusting a certificate) and a quick sign-out that keeps local settings.
Fails on any console error, CSP and Trusted Types included.

usage: browser_features.py BASE PKI_DIR IMAP_PORT SHOT_DIR
The gateway must run with POSTERN_SMIME_CA_FILE=PKI_DIR/ca.crt (see
tests/smime_e2e.py pki) and the demo data from tests/seed_demo.py.
"""
import imaplib, subprocess, sys, time
from playwright.sync_api import sync_playwright, expect

BASE, PKI, IMAP_PORT, OUT = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
problems = []
step = 0


def watch(page):
    def console(m):
        if m.type in ("error", "warning"):
            problems.append(f"console {m.type}: {m.text}")
    page.on("console", console)
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))


def shot(page, name):
    global step
    step += 1
    page.wait_for_timeout(300)
    page.screenshot(path=f"{OUT}/f{step:02d}-{name}.png")


def append(raw):
    im = imaplib.IMAP4("127.0.0.1", IMAP_PORT)
    im.login("demouser", "demopass")
    im.append("INBOX", "", imaplib.Time2Internaldate(time.time()), raw)
    im.logout()


def cms(*args, data):
    return subprocess.run(["openssl", "cms", *args], input=data, capture_output=True, check=True).stdout


def open_settings(page, tab):
    page.locator(".rail-foot .iconbtn").nth(0).click()
    page.wait_for_selector(".settings-tabs")
    page.locator(".settings-tabs button", has_text=tab).click()


def close_dialog(page):
    page.keyboard.press("Escape")
    expect(page.locator(".dialog")).to_have_count(0)


entity = b"Content-Type: text/plain; charset=utf-8\r\n\r\nHello from a self-signed sender\r\n"
append(cms("-sign", "-signer", f"{PKI}/mallory.crt", "-inkey", f"{PKI}/mallory.key", "-from", "alice@example.com",
           "-to", "demouser@example.com", "-subject", "Unverified signature", "-crlfeol", data=entity))
append(cms("-encrypt", "-aes256", "-from", "alice@example.com", "-to", "demouser@example.com", "-subject", "Encrypted for you",
           "-crlfeol", f"{PKI}/demo.crt", data=b"Content-Type: text/plain; charset=utf-8\r\n\r\nThe secret plan\r\n"))

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, locale="en-GB")
    ctx.grant_permissions(["notifications"], origin=BASE)
    # Record notifications and sounds instead of showing or playing them.
    ctx.add_init_script("""
        window.__notes = []; window.__sounds = 0;
        const N = window.Notification;
        window.Notification = class extends N { constructor(t, o) { super(t, o); window.__notes.push([t, o && o.body]); } };
        const A = window.AudioContext;
        window.AudioContext = class extends A { createOscillator() { window.__sounds++; return super.createOscillator(); } };
    """)
    page = ctx.new_page()
    watch(page)
    keyed = []  # (path, carried the sealed key)
    page.on("request", lambda r: keyed.append((r.url.split("8080", 1)[-1], "x-postern-key" in r.headers)) if "/api/" in r.url else None)
    page.goto(BASE)
    page.fill("input[type=email]", "demouser@example.com")
    page.fill("input[type=password]", "demopass")
    page.click("button[type=submit]")
    page.wait_for_selector(".row")

    # ---- column widths ----
    rail = page.locator(".rail").bounding_box()["width"]
    handle = page.locator(".rail .resizer").bounding_box()
    page.mouse.move(handle["x"] + 4, handle["y"] + 300)
    page.mouse.down()
    page.mouse.move(handle["x"] + 84, handle["y"] + 300, steps=6)
    page.mouse.up()
    wider = page.locator(".rail").bounding_box()["width"]
    assert abs(wider - (rail + 80)) <= 4, f"rail did not follow the drag: {rail} -> {wider}"
    lst = page.locator(".list").bounding_box()["width"]
    page.locator(".list .resizer").focus()
    page.keyboard.press("ArrowRight")
    page.keyboard.press("ArrowRight")
    lst2 = page.locator(".list").bounding_box()["width"]
    assert abs(lst2 - (lst + 32)) <= 4, f"arrow keys did not resize the list: {lst} -> {lst2}"
    page.reload()
    page.wait_for_selector(".row")
    assert abs(page.locator(".rail").bounding_box()["width"] - wider) <= 2, "rail width not kept"
    assert abs(page.locator(".list").bounding_box()["width"] - lst2) <= 2, "list width not kept"
    shot(page, "wider-columns")
    page.locator(".rail .resizer").dblclick()
    assert abs(page.locator(".rail").bounding_box()["width"] - rail) <= 2, "double click did not reset"

    # ---- colour themes ----
    open_settings(page, "Appearance")
    shot(page, "appearance")
    for name, palette in [("Nord", "nord"), ("Paper", "paper"), ("Forest", "forest")]:
        page.locator(".swatch", has_text=name).click()
        assert page.evaluate("document.documentElement.dataset.palette") == palette
    page.locator(".segmented button", has_text="Dark").click()
    close_dialog(page)
    accent = page.evaluate("getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()")
    assert accent == "#4ade80", f"dark forest accent: {accent}"
    page.locator(".row", has_text="Issue 48").first.click()
    page.wait_for_selector("iframe.mailframe")
    shot(page, "forest-dark")
    open_settings(page, "Appearance")
    page.locator(".swatch", has_text="Nord").click()
    page.locator(".segmented button", has_text="Light").click()
    close_dialog(page)
    shot(page, "nord-light")
    open_settings(page, "Appearance")
    page.locator(".swatch", has_text="Indigo").click()
    page.locator(".segmented button", has_text="Match system").click()
    close_dialog(page)

    # ---- remote images ----
    def open_newsletter(frame=True):
        page.locator(".row", has_text="Pipeline").first.click()
        page.wait_for_selector(".reader .subject")
        page.locator(".row", has_text="Issue 48").first.click()
        page.wait_for_selector("iframe.mailframe" if frame else ".plain")
        page.wait_for_timeout(300)

    open_settings(page, "Privacy")
    page.locator(".segmented button", has_text="Never load").click()
    close_dialog(page)
    open_newsletter()
    expect(page.locator(".banner", has_text="blocked in your settings")).to_have_count(1)
    expect(page.locator(".banner button")).to_have_count(0)
    open_settings(page, "Privacy")
    page.locator(".segmented button", has_text="Ask every time").click()
    close_dialog(page)
    open_newsletter()
    page.locator(".banner button", has_text="Always from news@harbor.example").click()
    expect(page.locator(".banner")).to_have_count(0)
    open_newsletter()
    expect(page.locator(".banner")).to_have_count(0)
    html = page.frames[-1].content()
    assert "tracker.example" in html or "harbor.example" in html, "remote images were not allowed for the trusted sender"
    page.wait_for_timeout(500)
    # The allowed images point at hosts that do not exist here.
    problems[:] = [x for x in problems if "ERR_TUNNEL_CONNECTION_FAILED" not in x and "ERR_NAME_NOT_RESOLVED" not in x]
    open_settings(page, "Privacy")
    shot(page, "privacy")
    page.locator(".plainlist button", has_text="Remove").click()
    page.locator(".switch", has_text="plain text").click()
    close_dialog(page)
    open_newsletter(frame=False)
    expect(page.locator("iframe.mailframe")).to_have_count(0)
    open_settings(page, "Privacy")
    page.locator(".switch", has_text="plain text").click()
    close_dialog(page)

    # ---- notifications and sound ----
    open_settings(page, "Notifications")
    page.locator(".switch", has_text="Notify me").click()
    page.select_option(".dialog select", "chime")
    page.locator("button", has_text="Send a test").click()
    shot(page, "notifications")
    close_dialog(page)
    assert page.evaluate("window.__notes.length") == 1, "test notification not shown"
    sounds = page.evaluate("window.__sounds")
    assert sounds >= 2, "no sound played on choosing one"
    # New mail while the tab is in the background.
    page.evaluate("Object.defineProperty(document, 'visibilityState', {get: () => 'hidden'}); document.hasFocus = () => false;")
    append(b"From: Lena Vogel <lena@example.org>\r\nTo: demouser@example.com\r\nSubject: Fresh news\r\n\r\nJust arrived.\r\n")
    page.locator(".list-title .iconbtn[title='Refresh']").click()
    for _ in range(40):  # wait_for_function needs eval, which the page's CSP forbids
        if page.evaluate("window.__notes.length") >= 2:
            break
        page.wait_for_timeout(250)
    note = page.evaluate("window.__notes[window.__notes.length - 1]")
    assert note == ["Lena Vogel", "Fresh news"], note
    assert page.evaluate("window.__sounds") > sounds, "no sound for new mail"
    assert page.title().startswith("("), f"unread count not in the title: {page.title()}"

    # ---- S/MIME: import key and certificate ----
    page.locator(".row", has_text="Encrypted for you").first.click()
    page.wait_for_selector(".locked")
    shot(page, "encrypted-no-key")
    page.locator(".locked button").click()
    page.wait_for_selector(".key-import")
    page.set_input_files(".key-import input[type=file]", f"{PKI}/demo.p12")
    page.fill(".key-import input[type=password]", "secret")
    page.locator(".key-import button[type=submit]").click()
    page.wait_for_selector(".certcard")
    expect(page.locator(".certcard")).to_contain_text("demouser@example.com")
    page.set_input_files(".settings input[type=file][accept*='.pem']", f"{PKI}/alice.crt")
    page.wait_for_selector(".certlist li")
    expect(page.locator(".certlist")).to_contain_text("alice@example.com")
    shot(page, "smime-settings")
    close_dialog(page)

    page.locator(".row", has_text="Pipeline").first.click()
    page.wait_for_selector(".reader .subject")
    page.locator(".row", has_text="Encrypted for you").first.click()
    page.wait_for_selector(".sec-chip")
    expect(page.locator(".plain")).to_contain_text("The secret plan")
    expect(page.locator(".sec-chip").first).to_contain_text("Encrypted, AES-256-CBC")

    # ---- an unverified signature, then trusted by hand ----
    page.locator(".row", has_text="Unverified signature").first.click()
    page.wait_for_selector(".sec-chip.warn")
    page.locator(".sec-chip.warn").click()
    shot(page, "unverified-signature")
    page.locator(".sec-details button", has_text="Trust this certificate").click()
    page.wait_for_selector(".sec-chip.ok")
    expect(page.locator(".sec-chip.ok")).to_contain_text("certificate you trust")

    # ---- composing: sign and encrypt ----
    page.locator(".compose-btn").click()
    page.wait_for_selector(".composer")
    expect(page.locator(".composer .toggle", has_text="Sign")).to_have_attribute("aria-pressed", "true")
    page.fill("#c-to", "bob@example.com")
    page.fill("#c-subject", "Should not go")
    page.locator(".composer .toggle", has_text="Encrypt").click()
    expect(page.locator(".composer-note")).to_contain_text("No certificate for bob@example.com")
    shot(page, "composer-missing-cert")
    page.fill("#c-to", "Alice <alice@example.com>")
    expect(page.locator(".composer-note")).to_have_count(0)
    page.fill("#c-subject", "Signed and encrypted from the browser")
    page.fill(".composer-body", "Meet at noon.")
    shot(page, "composer-encrypt")
    page.locator(".composer button[type=submit]").click()
    page.wait_for_selector(".toast:has-text('Message sent')", timeout=15000)
    page.locator(".list-title .iconbtn[title='Refresh']").click()
    page.locator(".row", has_text="Signed and encrypted from the browser").first.click()
    page.wait_for_selector(".sec-chip.ok >> nth=1")
    chips = page.locator(".sec-chip").all_inner_texts()
    assert any("Encrypted" in c for c in chips) and any("Signed by demouser@example.com" in c for c in chips), chips
    expect(page.locator(".plain")).to_contain_text("Meet at noon.")
    expect(page.locator(".row", has_text="Signed and encrypted from the browser").first.locator(".row-marks")).to_have_count(1)
    shot(page, "read-own-encrypted")

    leaked = [p for p, k in keyed if k and not (p.startswith("/api/message?") or p.startswith("/api/message/") or p in ("/api/send", "/api/smime/status"))]
    assert not leaked, f"the key went along with: {leaked[:5]}"
    assert any(k for p, k in keyed if p.startswith("/api/message?")), "the key was never sent where it is needed"

    # ---- sign-out is immediate and keeps local data ----
    t0 = time.monotonic()
    page.locator(".rail-foot .iconbtn").last.click()
    page.wait_for_selector(".login-card")
    took = time.monotonic() - t0
    assert took < 1.5, f"sign-out took {took:.2f}s"
    kept = page.evaluate("[localStorage.getItem('postern.smime.keys') !== null, localStorage.getItem('postern.layout') !== null, (JSON.parse(localStorage.getItem('postern.prefs')||'{}')).sound]")
    assert kept == [True, True, "chime"], f"local data lost on sign-out: {kept}"
    print(f"sign-out took {took:.2f}s, local data kept")
    page.fill("input[type=email]", "demouser@example.com")
    page.fill("input[type=password]", "demopass")
    page.click("button[type=submit]")
    page.wait_for_selector(".row")
    ctx.close()

    # ---- phone: settings tabs scroll sideways ----
    ctx = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2, is_mobile=True, has_touch=True, locale="de-DE")
    page = ctx.new_page()
    watch(page)
    page.goto(BASE)
    page.fill("input[type=email]", "demouser@example.com")
    page.fill("input[type=password]", "demopass")
    page.click("button[type=submit]")
    page.wait_for_selector(".row")
    page.locator(".list-title .iconbtn").first.click()
    page.wait_for_selector(".rail.open")
    page.locator(".rail-foot .iconbtn").nth(0).click()
    page.wait_for_selector(".settings-tabs")
    page.locator(".settings-tabs button", has_text="S/MIME").click()
    shot(page, "mobile-smime")
    ctx.close()
    browser.close()

if problems:
    print("PROBLEMS:")
    for x in problems:
        print("  ", x)
    sys.exit(1)
print("FEATURE BROWSER TEST PASSED")
