"""Evidence-based, passive checks of a single HTTP response.

These are configuration observations, not proof of an exploitable vulnerability.
No request is issued here. Cookie values are deliberately excluded from evidence.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


class _Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.resources = []
        self.password_forms = []
        self.form_action = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.form_action = attrs.get("action", "")
        if tag == "input" and attrs.get("type", "").lower() == "password":
            if self.form_action is not None:
                self.password_forms.append(self.form_action)
        if tag in {"script", "iframe", "img", "audio", "video", "source"}:
            self.resources.append((tag, attrs.get("src", "")))
        if tag == "link" and "stylesheet" in attrs.get("rel", "").lower().split():
            self.resources.append((tag, attrs.get("href", "")))

    def handle_endtag(self, tag):
        if tag == "form":
            self.form_action = None


def inspect_http(url: str, status: str, header_items: list[tuple[str, str]],
                 body: str, *, complete: bool = True) -> list[dict]:
    """Return checks with explicit applicability and bounded, reproducible evidence."""
    headers: dict[str, list[str]] = {}
    for name, value in header_items:
        headers.setdefault(name.lower(), []).append(value)
    checks = []

    def add(check, state, evidence, remediation="", severity="info"):
        checks.append({"check": check, "status": state, "severity": severity,
                       "evidence": evidence, "remediation": remediation,
                       "url": url, "kind": "configuration_observation"})

    if not status.isdigit() or not 200 <= int(status) < 300:
        add("response", "not_applicable", "A successful response is required for page checks.")
        return checks
    secure = urlsplit(url).scheme == "https"
    ctype = ";".join(headers.get("content-type", [])).lower()
    is_html = "text/html" in ctype or "application/xhtml+xml" in ctype
    if secure:
        hsts = headers.get("strict-transport-security", [])
        age = re.search(r"(?:^|;)\s*max-age\s*=\s*\"?(\d+)\"?\s*(?:;|$)",
                        hsts[0] if hsts else "", re.I)
        valid = len(hsts) == 1 and age and int(age[1]) > 0
        add("hsts", "pass" if valid else "review", "Strict-Transport-Security: " +
            (hsts[0][:200] if hsts else "absent"),
            "HTTPS の運用条件を確認し、有効な max-age を設定する。")
    else:
        add("hsts", "not_applicable", "HSTS is only honored over HTTPS.")
    nosniff = headers.get("x-content-type-options", [])
    add("content_type_options", "pass" if [v.lower() for v in nosniff] == ["nosniff"] else "review",
        "X-Content-Type-Options: " + ", ".join(nosniff or ["absent"]),
        "正しい Content-Type と X-Content-Type-Options: nosniff を設定する。")
    if is_html:
        policies = headers.get("content-security-policy", [])
        directives = [set(part.strip().split()[0].lower() for part in policy.split(";")
                          if part.strip()) for policy in policies]
        # Presence of report-only policy, or just a reporting directive, offers no enforcement.
        enforcing = any(d & {"default-src", "script-src", "script-src-elem"} for d in directives)
        add("csp", "review", "Enforcing script policy present; effectiveness needs review."
            if enforcing else "No enforcing script/default-src policy observed.",
            "CSP のソース許可範囲を確認する。ヘッダーの有無だけで XSS を断定しない。")
        frame_policies = [part.strip() for policy in policies for part in policy.split(";")
                          if part.strip().lower().startswith("frame-ancestors ")]
        xfo = headers.get("x-frame-options", [])
        frame_block = any(p.lower().split()[1:] == ["'none'"] or
                          p.lower().split()[1:] == ["'self'"] for p in frame_policies)
        if not frame_policies:
            frame_block = len(xfo) == 1 and xfo[0].upper() in {"DENY", "SAMEORIGIN"}
        add("frame_protection", "pass" if frame_block else "review",
            "Frame policy: " + "; ".join(frame_policies + xfo or ["absent"]),
            "埋め込み要件を確認し、frame-ancestors または X-Frame-Options を設定する。")
        document = _Document()
        document.feed(body)
        insecure_resources = [tag for tag, src in document.resources
                              if src and urlsplit(urljoin(url, src)).scheme == "http"] if secure else []
        upgrades = any("upgrade-insecure-requests" in d for d in directives)
        add("mixed_content", "review" if insecure_resources else ("pass" if complete else "incomplete"),
            "HTTP resource references: " + ", ".join(sorted(set(insecure_resources))) +
            ("; CSP upgrade-insecure-requests present" if upgrades else ""),
            "リソース URL を HTTPS に統一し、ブラウザーで実際の読込結果を確認する。")
        insecure_forms = [action for action in document.password_forms
                          if not secure or urlsplit(urljoin(url, action)).scheme == "http"]
        add("password_transport", "review" if insecure_forms else ("pass" if complete else "incomplete"),
            f"Password forms using an HTTP page or action: {len(insecure_forms)}",
            "ログインページと送信先の双方で HTTPS を使う。", "medium" if insecure_forms else "info")
    else:
        for name in ("csp", "frame_protection", "mixed_content", "password_transport"):
            add(name, "not_applicable", "Response is not declared as HTML.")
    cookies = headers.get("set-cookie", [])
    for index, cookie in enumerate(cookies):
        parts = cookie.split(";")
        name, sep, _ = parts[0].partition("=")
        if not sep:
            add("cookie", "review", f"Malformed Set-Cookie header #{index + 1}")
            continue
        attrs = {}
        for part in parts[1:]:
            key, _, value = part.strip().partition("=")
            attrs[key.lower()] = value.strip().lower()
        problems = []
        if "secure" not in attrs:
            problems.append("Secure absent")
        if "httponly" not in attrs:
            problems.append("HttpOnly absent (may be intentional for JS-readable cookies)")
        if attrs.get("samesite") not in {"strict", "lax", "none"}:
            problems.append("SameSite missing/invalid; browser default applies")
        if attrs.get("samesite") == "none" and "secure" not in attrs:
            problems.append("SameSite=None without Secure is rejected by modern browsers")
        add("cookie", "review" if problems else "pass", f"Cookie {name.strip()[:80]}: " +
            ("; ".join(problems) or "Secure, HttpOnly and SameSite present"),
            "認証用か用途を確認し、必要な属性を設定する。Cookie 値は報告しない。")
    if not cookies:
        add("cookie", "not_applicable", "No Set-Cookie headers observed.")
    return checks
