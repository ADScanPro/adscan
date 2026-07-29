"""Render report-hero.html to a high-DPI PNG via Chromium (Playwright).

Re-buildable: renders the #stage element at 2x, transparent background.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
html = (HERE / "report-hero.html").as_uri()
out = HERE / "report-hero@2x.png"

with sync_playwright() as p:
    b = p.chromium.launch()
    page = b.new_page(viewport={"width": 1600, "height": 1000}, device_scale_factor=2)
    page.goto(html)
    page.wait_for_timeout(400)
    el = page.query_selector("#stage")
    el.screenshot(path=str(out), omit_background=True)
    b.close()
print("wrote", out)
