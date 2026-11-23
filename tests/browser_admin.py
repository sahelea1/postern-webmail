"""Drives the admin console in headless Chrome. usage: browser_admin.py ADMIN_URL BINARY DATA_DIR SHOT_DIR"""
import os, subprocess, sys
from playwright.sync_api import sync_playwright, expect

ADMIN, BINARY, DATA, OUT = sys.argv[1:5]
problems = []
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    page = browser.new_page(viewport={"width": 1100, "height": 900})
    page.on("console", lambda m: problems.append(f"console {m.type}: {m.text}") if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    page.goto(ADMIN)
    page.wait_for_selector(".gate")
    page.screenshot(path=f"{OUT}/20-admin-gate.png")
    problems[:] = [x for x in problems if "401" not in x]  # the signed-out probe
    env = dict(os.environ, POSTERN_DATA_DIR=DATA, POSTERN_ADMIN_URL=ADMIN)
    link = subprocess.run([BINARY, "admin-link"], env=env, capture_output=True, text=True).stdout.splitlines()[0]
    page.goto(link)
    page.wait_for_selector(".card h2")
    before = page.locator("section.card").count()
    page.screenshot(path=f"{OUT}/21-admin.png")
    page.locator("section.card").first.locator("button", has_text="Test connection").click()
    page.wait_for_selector(".note.ok", timeout=20000)
    page.click("text=Add mail server")
    card = page.locator("section.card").last
    card.locator("input[type=text]").nth(0).fill("second")
    card.locator("input[type=text]").nth(1).fill("Second Server")
    card.locator("select").first.select_option("jmap")
    card = page.locator("section.card").last
    card.locator("input[type=text]").nth(2).fill("second.example, *.second.example")
    card.locator("input[type=text]").nth(3).fill("https://mail.second.example")
    page.screenshot(path=f"{OUT}/22-admin-edit.png", full_page=True)
    page.click("text=Save changes")
    page.wait_for_selector(".bar .note.ok")
    assert 'id = "second"' in open(os.path.join(DATA, "servers.toml")).read()
    # invalid input is refused by the server and reported
    card.locator("input[type=text]").nth(0).fill("bad id")
    page.click("text=Save changes")
    page.wait_for_selector(".bar .note.bad")
    problems[:] = [x for x in problems if "400" not in x]
    card.locator("button", has_text="Remove").click()
    page.click("text=Save changes")
    page.wait_for_selector(".bar .note.ok")
    assert page.locator("section.card").count() == before
    assert 'id = "second"' not in open(os.path.join(DATA, "servers.toml")).read()
    page.click("text=Sign out")
    page.wait_for_selector(".gate")
    browser.close()
if problems:
    print("PROBLEMS:", *problems, sep="\n  ")
    sys.exit(1)
print("ADMIN BROWSER TEST PASSED")
