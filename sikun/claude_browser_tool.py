"""Headless-browser tool for the Claude engine (Playwright Chromium).

Many web targets — OWASP Juice Shop among them — are client-side / DOM-driven
(Angular, DOM-based XSS, flows that only exist after JS runs). The HTTP-level
tools (``http_probe`` / ``dir_enum`` / curl via Bash) can't see any of that.
``browser_fetch`` renders a page in headless Chromium and returns the resulting
DOM text, title, final URL, and console errors, and can optionally evaluate a
snippet of page JS — so a worker can observe JS-rendered content.

Playwright is OPTIONAL. If it isn't installed the tool returns an install hint
rather than crashing, so importing this module and building options never fails
for users who don't need it. On the target machine:

    pip install playwright && playwright install chromium

Scope is enforced: ``BROWSER_SCOPE`` declares the URL's host, so the permission
gate (``sikun.permission``) hard-blocks an out-of-scope URL before the page
loads — same guarantee as the other scope-gated tools.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from claude_agent_sdk import SdkMcpTool, tool

_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "開くURL(認可範囲内)。例 http://localhost:3000/#/login"},
        "js": {"type": "string",
               "description": "任意: ページロード後に evaluate する JS 式。結果を文字列化して返す"},
        "wait_selector": {"type": "string",
                          "description": "任意: この CSS セレクタが現れるまで待つ"},
    },
    "required": ["url"],
}


def _content(obj: Any) -> dict[str, Any]:
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}]}


def browser_tools() -> list[SdkMcpTool]:
    """Return the headless-browser SDK tool(s)."""

    @tool("browser_fetch",
          "headless Chromium でURLを開き、レンダ後のDOMテキスト/タイトル/最終URL/コンソールエラーを"
          "構造化して返す。任意で js(ページ内 evaluate)と wait_selector を指定可。DOM/JS 依存の"
          "Web課題(DOM XSS、SPA画面遷移など)の観測に使う。HTTPレベルの http_probe では見えない挙動向け。",
          _SCHEMA)
    async def _browser_fetch(args: dict[str, Any]) -> dict[str, Any]:
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return _content({"error": "playwright 未インストール。対象マシンで "
                                      "`pip install playwright && playwright install chromium` を実行してください。"})
        url = args["url"]
        js = args.get("js")
        wait_selector = args.get("wait_selector")
        console_errors: list[str] = []
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
                await page.goto(url, wait_until="networkidle", timeout=30000)
                if wait_selector:
                    try:
                        await page.wait_for_selector(wait_selector, timeout=10000)
                    except Exception as exc:  # noqa: BLE001
                        console_errors.append(f"wait_selector: {exc}")
                title = await page.title()
                body_text = (await page.inner_text("body"))[:6000]
                js_result = None
                if js:
                    try:
                        js_result = str(await page.evaluate(js))[:2000]
                    except Exception as exc:  # noqa: BLE001
                        js_result = f"<eval error: {exc}>"
                final_url = page.url
                await browser.close()
            return _content({
                "title": title, "final_url": final_url, "text": body_text,
                "js_result": js_result, "console_errors": console_errors[:20],
            })
        except Exception as exc:  # noqa: BLE001
            return _content({"error": f"browser error: {exc}", "console_errors": console_errors[:20]})

    return [_browser_fetch]


# Reliable scope extraction — handed to the permission gate so an out-of-scope
# URL is hard-blocked before the browser navigates to it.
BROWSER_SCOPE: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "browser_fetch": lambda a: [a["url"]] if a.get("url") else [],
}
