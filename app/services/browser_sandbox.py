"""Browser Sandbox - Playwright headless Chromium + DOM mutation tracker."""
import asyncio
import base64
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.utils.ssrf_guard import is_safe_url
from app.services.sandbox_scripts import INIT_JS, COLLECT_JS
from app.services.sandbox_risk import assess_risk


# ── Playwright runner ──────────────────────────────────────────────────────────

async def _run(url: str) -> dict:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed. Run: pip install playwright && playwright install chromium"}

    origin = urlparse(url).netloc
    network_requests: list[dict] = []
    console_logs:     list[dict] = []
    dialog_events:    list[dict] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox", "--disable-setuid-sandbox",
                "--disable-dev-shm-usage", "--disable-gpu",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        ctx = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            java_script_enabled=True,
            accept_downloads=False,
        )
        await ctx.add_init_script(script=INIT_JS)
        page = await ctx.new_page()

        def _on_request(req):
            rhost = urlparse(req.url).netloc
            network_requests.append({
                "url": req.url[:300], "method": req.method,
                "resource_type": req.resource_type,
                "cross_origin": rhost != origin,
            })

        def _on_console(msg):
            if msg.type in ("error", "warning"):
                console_logs.append({"type": msg.type, "text": msg.text[:200]})

        def _on_dialog(dlg):
            dialog_events.append({"type": dlg.type, "message": dlg.message[:200]})
            asyncio.create_task(dlg.dismiss())

        page.on("request", _on_request)
        page.on("console", _on_console)
        page.on("dialog",  _on_dialog)

        nav_error = None
        try:
            await page.goto(url, timeout=20000, wait_until="domcontentloaded")
        except Exception as e:
            nav_error = str(e)

        try:
            await page.wait_for_load_state("networkidle", timeout=6000)
        except Exception:
            pass

        dom_data: dict = {}
        try:
            dom_data = await page.evaluate(COLLECT_JS)
        except Exception as e:
            dom_data = {"error": str(e)}

        screenshot_b64 = None
        try:
            ss_bytes = await page.screenshot(type="jpeg", quality=78, full_page=False)
            screenshot_b64 = base64.b64encode(ss_bytes).decode()
        except Exception:
            pass

        final_url = page.url
        await browser.close()

    cross_origin = [r for r in network_requests if r["cross_origin"]]
    exfil        = [r for r in cross_origin if r["method"] in ("POST", "PUT", "PATCH")]

    return {
        "url": url, "final_url": final_url,
        "redirected": final_url.rstrip("/") != url.rstrip("/"),
        "nav_error": nav_error,
        "dom": dom_data,
        "network": {
            "total_requests":      len(network_requests),
            "cross_origin_count":  len(cross_origin),
            "cross_origin_requests": cross_origin[:100],
            "data_exfil_candidates": exfil[:20],
        },
        "console_errors": console_logs[:30],
        "dialogs": dialog_events,
        "screenshot_b64": screenshot_b64,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Result normaliser ──────────────────────────────────────────────────────────

def _normalize(raw: dict) -> dict:
    dom  = raw.get("dom") or {}
    net  = raw.get("network") or {}
    risk = raw.get("risk") or {}

    pw_fields    = sum(1 for f in dom.get("forms", []) if f.get("has_password"))
    email_fields = sum(1 for f in dom.get("forms", []) if f.get("has_email"))
    storage      = dom.get("storage_access", [])
    mutations    = dom.get("mutations", [])
    timers       = dom.get("timers", [])
    risk_score10 = min(10, round(risk.get("score", 0) / 10))

    return {
        "url":        raw.get("url"),
        "final_url":  raw.get("final_url"),
        "page_title": dom.get("title", ""),
        "risk_score": risk_score10,
        "risk_level": risk.get("level", "Unknown"),
        "findings":   risk.get("findings", []),
        "dom": {
            "form_count":           len(dom.get("forms", [])),
            "password_field_count": pw_fields,
            "email_field_count":    email_fields,
            "script_count":         len(dom.get("external_scripts", [])),
            "iframe_count":         len(dom.get("iframes", [])),
            "mutation_count":       len(mutations),
            "meta_refresh":         len(dom.get("meta_refresh", [])),
            "storage_keys":         [a.get("key") for a in storage[:20]],
            "timer_count":          len(timers),
        },
        "network": {
            "total_requests":        net.get("total_requests", 0),
            "cross_origin_requests": net.get("cross_origin_count", 0),
            "data_exfiltration":     len(net.get("data_exfil_candidates", [])),
            "cross_origin_urls":     [r["url"] for r in net.get("cross_origin_requests", [])[:15]],
        },
        "javascript": {
            "eval_count":        1 if dom.get("has_eval")      else 0,
            "document_write":    1 if dom.get("has_doc_write") else 0,
            "atob_btoa":         1 if dom.get("has_base64")    else 0,
            "obfuscated_scripts": [],
        },
        "screenshot":  raw.get("screenshot_b64"),
        "nav_error":   raw.get("nav_error"),
        "scanned_at":  raw.get("scanned_at"),
    }


# ── Public entry point ─────────────────────────────────────────────────────────

def sandbox_scan_sync(url: str) -> dict:
    """
    Sync wrapper for Starlette thread-pool background tasks.
    Creates a ProactorEventLoop on Windows so Playwright can spawn Chromium.
    """
    safe, reason = is_safe_url(url)
    if not safe:
        return {"url": url, "error": f"Blocked: {reason}",
                "risk_score": 0, "risk_level": "Blocked", "findings": []}

    loop = asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        raw = loop.run_until_complete(_run(url))
    finally:
        loop.close()
        asyncio.set_event_loop(None)

    if "error" not in raw:
        raw["risk"] = assess_risk(raw)
    return _normalize(raw)
