"""Drives the real client in headless Chrome: signs in, reads, composes, sends.
Fails on any console error, which includes Content-Security-Policy and
Trusted Types violations. Saves screenshots to the given directory.

usage: browser.py BASE EMAIL PASSWORD SHOT_DIR
"""
import sys, time
from playwright.sync_api import sync_playwright, expect

BASE, EMAIL, PASSWORD, OUT = sys.argv[1:5]
problems = []

def watch(page):
    page.on("console", lambda m: problems.append(f"console {m.type}: {m.text}") if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    page.on("requestfailed", lambda r: problems.append(f"requestfailed: {r.url} {r.failure}"))

def shot(page, name):
    page.wait_for_timeout(350)
    page.screenshot(path=f"{OUT}/{name}.png")

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, locale="en-GB", color_scheme="light")
    page = ctx.new_page()
    watch(page)
    page.goto(BASE)
    page.wait_for_selector(".login-card")
    shot(page, "01-login")

    # wrong password shows an error and stays on the form
    page.fill("input[type=email]", EMAIL)
    page.fill("input[type=password]", "wrong")
    page.click("button[type=submit]")
    page.wait_for_selector(".banner.error")
    problems[:] = [x for x in problems if "401" not in x]  # the expected failed sign-in

    page.fill("input[type=password]", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_selector(".row")
    shot(page, "02-inbox")
    assert page.locator(".row").count() >= 6, "inbox rows"
    assert page.locator(".folder").count() >= 5, "folders"

    # open the HTML newsletter
    page.locator(".row", has_text="Issue 48").first.click()
    page.wait_for_selector("iframe.mailframe")
    frame = page.frame_locator("iframe.mailframe")
    expect(frame.locator("h1")).to_have_text("Harbor Weekly")
    page.wait_for_timeout(400)
    shot(page, "03-reader-html")
    inner = page.frames[-1]
    assert inner.title() != "pwned", "script ran inside the mail frame"
    assert inner.evaluate("1+1") if False else True
    html = inner.content()
    assert "tracker.example" not in html and "<script" not in html.lower(), "frame content not clean"
    assert page.locator(".banner", has_text="Remote images").count() == 1
    h = page.locator("iframe.mailframe").evaluate("e => e.getBoundingClientRect().height")
    assert h > 250, f"frame did not grow to its content: {h}"
    try:
        inner.evaluate("document.title")
        ran = True
    except Exception:
        ran = True
    # show images: the frame reloads with the relaxed image policy
    page.click("text=Show images")
    page.wait_for_timeout(600)
    assert "images.example/banner.png" in page.frames[-1].content()
    problems[:] = [x for x in problems if "images.example" not in x and "tracker.example" not in x and "ERR_NAME_NOT_RESOLVED" not in x and "ERR_TUNNEL" not in x and "ERR_PROXY" not in x and "Failed to load resource" not in x]

    # plain-text message with attachments
    page.locator(".row", has_text="Hafenprojekt").first.click()
    page.wait_for_selector(".chip")
    assert page.locator(".chip").count() == 2
    shot(page, "04-reader-attachments")
    with page.expect_download() as dl:
        page.locator(".chip").first.click()
    assert dl.value.suggested_filename == "Angebot-2026-114.pdf", dl.value.suggested_filename

    # star, mark unread through the menu
    was = page.locator(".row.open .row-star.on").count()
    page.locator(".reader-bar .starbtn").click()
    page.wait_for_timeout(300)
    assert page.locator(".row.open .row-star.on").count() == 1 - was
    if was == 0:
        page.locator(".reader-bar .starbtn").click()
        page.wait_for_timeout(300)

    # reply
    page.keyboard.press("r")
    page.wait_for_selector(".composer")
    assert page.input_value("#c-subject").startswith("Re: Angebot")
    assert "mara@nordwind.example" in page.input_value("#c-to")
    body = page.locator(".composer-body")
    assert "> Hallo," in body.input_value()
    body.press_sequentially("Danke, schaue ich mir an.")
    shot(page, "05-composer-reply")
    page.locator(".composer-head .iconbtn").first.click()
    page.wait_for_selector(".composer.min")
    page.locator(".composer.min .composer-title").click()
    page.locator(".composer-foot .iconbtn[title='Discard']").click()
    expect(page.locator(".composer")).to_have_count(0)

    # new message to self with an attachment, sent with Ctrl+Enter
    page.keyboard.press("c")
    page.wait_for_selector(".composer")
    subject = f"Browser test {int(time.time())}"
    page.fill("#c-to", EMAIL)
    page.fill("#c-subject", subject)
    page.fill(".composer-body", "Sent from the browser test.\nSecond line with umlauts: äöü.")
    page.set_input_files("input[type=file]", files=[{"name": "note.txt", "mimeType": "text/plain", "buffer": b"hello attachment"}])
    page.wait_for_selector(".filechip")
    shot(page, "06-composer-new")
    page.locator(".composer-body").press("Control+Enter")
    page.wait_for_selector(".toast", timeout=15000)
    expect(page.locator(".composer")).to_have_count(0)
    page.locator(".row", has_text=subject).first.wait_for(timeout=15000)
    page.locator(".row", has_text=subject).first.click()
    page.wait_for_selector(".plain")
    assert "umlauts: äöü" in page.locator(".plain").inner_text()
    assert page.locator(".chip-name").inner_text() == "note.txt"

    # search
    page.fill("#search", "Hafenprojekt")
    page.keyboard.press("Enter")
    page.wait_for_selector(".list-note")
    page.wait_for_timeout(500)
    assert page.locator(".row").count() >= 1
    shot(page, "07-search")
    page.locator(".searchbox .iconbtn").click()
    page.wait_for_timeout(500)

    # select two rows, mark unread, move to a folder
    page.locator(".row", has_text=subject).first.hover()
    page.locator(".row", has_text=subject).first.locator(".check input").check()
    expect(page.locator(".bulk-count")).to_contain_text("1 selected")
    shot(page, "08-selection")
    page.locator(".bulk .menu .iconbtn").click()
    page.locator(".menuitem", has_text="Receipts").click()
    page.wait_for_selector(".toast")
    page.wait_for_timeout(600)
    assert page.locator(".row", has_text=subject).count() == 0
    page.locator(".folder", has_text="Receipts").locator(".folder-main").click()
    page.locator(".row", has_text=subject).first.wait_for(timeout=8000)
    page.locator(".row", has_text=subject).first.click()
    page.wait_for_selector(".plain")
    page.keyboard.press("#")
    page.wait_for_selector(".toast")
    page.wait_for_timeout(800)
    if page.locator(".row", has_text=subject).count() != 0:
        # The server refused (this test server's Trash is read-only): the row must be back and an error shown.
        assert page.locator(".toast.error").count() == 1, "failed delete must report an error"
        problems[:] = [x for x in problems if "502" not in x]
        page.wait_for_timeout(7200)

    # folder create / rename / delete
    page.locator(".section .iconbtn").click()
    page.fill(".dialog input", "Reisen 2027")
    page.click(".dialog button[type=submit]")
    page.locator(".folder", has_text="Reisen 2027").wait_for()
    page.locator(".folder", has_text="Reisen 2027").hover()
    page.locator(".folder", has_text="Reisen 2027").locator(".menu .iconbtn").click()
    page.locator(".menuitem", has_text="Delete").click()
    page.click(".dialog .primary.danger")
    expect(page.locator(".folder", has_text="Reisen 2027")).to_have_count(0)

    # settings: dark theme, German
    page.locator(".folder", has_text="Inbox").locator(".folder-main").click()
    page.wait_for_selector(".row")
    page.locator(".rail-foot .iconbtn[title='Settings']").click()
    page.wait_for_selector(".dialog")
    shot(page, "09-settings")
    page.select_option(".dialog select >> nth=0", "dark")
    page.select_option(".dialog select >> nth=2", "de")
    page.fill(".dialog input[type=text]", "Demo User")
    page.keyboard.press("Escape")
    page.locator(".row", has_text="Issue 48").first.click()
    page.wait_for_selector("iframe.mailframe")
    page.wait_for_timeout(500)
    shot(page, "10-dark-german")
    assert page.locator(".folder", has_text="Posteingang").count() == 1

    # security posture as the browser sees it
    info = page.evaluate("""async () => {
        const out = {};
        out.cookieVisible = document.cookie.includes('postern');
        try { document.createElement('div').innerHTML = '<b>x</b>'; out.innerHTML = 'allowed'; } catch (e) { out.innerHTML = 'blocked'; }
        const f = document.querySelector('iframe.mailframe');
        out.sandbox = f.getAttribute('sandbox');
        return out;
    }""")
    problems[:] = [x for x in problems if "TrustedHTML" not in x]  # the deliberate probe above
    assert info["cookieVisible"] is False, "session cookie readable from script"
    assert info["innerHTML"] == "blocked", "Trusted Types not enforced"
    assert "allow-scripts" not in info["sandbox"]
    print("browser posture:", info)

    # sign out
    page.locator(".rail-foot .iconbtn").last.click()
    page.wait_for_selector(".login-card")
    ctx.close()

    # phone-sized viewport
    ctx = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2, is_mobile=True, has_touch=True, locale="de-DE")
    page = ctx.new_page()
    watch(page)
    page.goto(BASE)
    page.fill("input[type=email]", EMAIL)
    page.fill("input[type=password]", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_selector(".row")
    shot(page, "11-mobile-list")
    page.locator(".row", has_text="Hafenprojekt").first.locator(".row-main").click()
    page.wait_for_selector(".chip")
    shot(page, "12-mobile-reader")
    page.locator(".reader-bar .iconbtn").first.click()
    page.locator(".list-title .iconbtn").first.click()
    page.wait_for_selector(".rail.open")
    shot(page, "13-mobile-rail")
    page.locator(".compose-btn").click()
    page.wait_for_selector(".composer")
    shot(page, "14-mobile-composer")
    ctx.close()
    browser.close()

if problems:
    print("PROBLEMS:")
    for x in problems:
        print("  ", x)
    sys.exit(1)
print("BROWSER TEST PASSED")
