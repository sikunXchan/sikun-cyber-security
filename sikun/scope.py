"""Scope enforcement — the distribution-safety guardrail.

Threat model (read this before touching it):
- It PREVENTS ACCIDENTS: a typo, a model misunderstanding, or a stray command
  hitting a host outside the authorized exercise range.
- It PROVIDES ACCOUNTABILITY: an append-only audit log of every target touched
  and whether it was allowed/blocked.
- It does NOT try to stop a determined skilled operator — anyone can bypass an
  in-tool check by running raw tools outside SCS. That is procedure's job
  (rules of engagement + who the private build is distributed to), not code.

Two enforcement strengths, by how reliably the target is known:
- RELIABLE (hard block): tools that declare their target — nmap_scan `target`,
  http_probe/dir_enum `url`, or a plugin's `scope_targets(args)`. Out-of-scope
  is refused before execution, no false positives.
- BEST-EFFORT (confirm): raw bash, where the target is only knowable by
  scraping the command string. Host-like tokens are extracted and, if any look
  out of scope, the operator is asked to confirm rather than silently allowing
  or falsely blocking a legitimate command.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_HOST_RE = re.compile(r"https?://([^\s/:'\"]+)")


def host_of(target: str) -> str:
    """Reduce a target string (IP, host, host:port, or URL) to its bare host."""
    t = (target or "").strip().strip("'\"")
    if not t:
        return ""
    if "://" in t:
        return (urlparse(t).hostname or "").strip()
    t = t.split("/", 1)[0]
    try:  # already a bare IP (covers IPv4 and IPv6)?
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    if t.count(":") == 1:  # strip :port from IPv4/hostname (not IPv6)
        t = t.rsplit(":", 1)[0]
    return t


class Scope:
    """An authorized target set: IPs, CIDRs, and hostnames. Empty == disabled
    (no enforcement), so scope is strictly opt-in and never breaks a run that
    hasn't configured it."""

    def __init__(self, entries: list[str]) -> None:
        self.raw = [e.strip() for e in entries if e and e.strip()]
        self.enabled = bool(self.raw)
        self.networks: list = []
        self.hostnames: set[str] = set()
        for entry in self.raw:
            host = host_of(entry) if "://" in entry else entry
            try:
                self.networks.append(ipaddress.ip_network(host, strict=False))
            except ValueError:
                self.hostnames.add(host.lower())

    def contains(self, target: str) -> bool:
        if "://" not in target and "/" in target and target.rsplit("/", 1)[1].isdigit():
            try:
                requested = ipaddress.ip_network(target, strict=False)
            except ValueError:
                pass  # A schemeless URL may have a numeric path component.
            else:
                return any(requested.version == net.version and requested.subnet_of(net)
                           for net in self.networks)
        host = host_of(target)
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
            return any(ip in net for net in self.networks)
        except ValueError:
            pass
        h = host.lower()
        return any(h == hn or h.endswith("." + hn) for hn in self.hostnames)

    def out_of_scope(self, targets: list[str]) -> list[str]:
        """Subset of `targets` not covered. Empty when scope is disabled."""
        if not self.enabled:
            return []
        return [t for t in targets if t and not self.contains(t)]


def extract_hosts(command: str) -> list[str]:
    """Best-effort: pull IPs and URL hosts out of a raw shell command.
    Deliberately conservative (valid IPs + http(s) URLs only) — misses are
    expected, which is why raw-bash checks confirm rather than hard block."""
    hosts: list[str] = list(_URL_HOST_RE.findall(command))
    for candidate in _IP_RE.findall(command):
        try:
            ipaddress.ip_address(candidate)
            hosts.append(candidate)
        except ValueError:
            continue
    seen: set[str] = set()
    unique: list[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


class ScopeGuard:
    """Parsed scope + an append-only JSONL audit log. One per run_agent()."""

    def __init__(self, scope: Scope, audit_path: Path, session_target: str) -> None:
        self.scope = scope
        self.audit_path = audit_path
        self.session_target = session_target

    @property
    def enabled(self) -> bool:
        return self.scope.enabled

    def check(self, targets: list[str]) -> list[str]:
        return self.scope.out_of_scope(targets)

    def audit(self, tool: str, targets: list[str], decision: str) -> None:
        record = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "session_target": self.session_target,
            "tool": tool,
            "targets": targets,
            "decision": decision,
        }
        try:
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass


def guard_reliable(guard: ScopeGuard, tool: str, targets: list[str]) -> str | None:
    """RELIABLE check for tools with a declared target. Audits, and returns an
    error string to hand back to the model when out of scope, else None."""
    bad = guard.check(targets)
    guard.audit(tool, targets, "blocked" if bad else "allow")
    if bad:
        allowed = ", ".join(guard.scope.raw) or "未設定"
        return f"対象が認可スコープ外のため実行を拒否しました: {', '.join(bad)}(認可範囲: {allowed})"
    return None


async def guard_besteffort(app, guard: ScopeGuard, tool: str, targets: list[str]) -> bool:
    """BEST-EFFORT check for raw bash / undeclared plugins. Audits, and on an
    out-of-scope-looking target asks the operator to confirm (safe default =
    block). Returns True if execution should proceed."""
    bad = guard.check(targets)
    if not bad:
        guard.audit(tool, targets, "allow")
        return True
    await app.post_event(
        "system",
        f"[bold yellow]⚠ {tool}: 認可スコープ外の可能性がある対象を検出: {', '.join(bad)}"
        f"(認可範囲: {', '.join(guard.scope.raw)})[/bold yellow]",
    )
    choice = await app.wait_for_choice(
        [("⛔ 中止(推奨・Enter)", "block"), ("⚠ scope外でも実行", "allow")]
    )
    guard.audit(tool, targets, f"operator-{choice}")
    return choice == "allow"
