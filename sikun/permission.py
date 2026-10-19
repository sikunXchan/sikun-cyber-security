"""Authorization enforcement for orchestrator-worker runs.

This is the port of SCS's ``ScopeGuard`` (``sikun/scope.py``) into two shapes:

1. ``screen_targets`` — a provider-neutral check used by any worker (mock or
   real) before it touches a target. It reuses the existing ``Scope`` /
   ``ScopeGuard`` logic and audit log, so the "authorized targets only +
   append-only audit" guarantee is identical to the Gemini engine's.

2. ``make_scope_permission`` — adapts (1) to the Claude Agent SDK's
   ``can_use_tool`` callback signature, so the *same* scope decision gates the
   SDK's built-in tools (Bash, etc.) and any MCP tool. Verified against
   claude_agent_sdk 0.2.159: ``can_use_tool`` is
   ``Callable[[str, dict, ToolPermissionContext], Awaitable[PermissionResultAllow | PermissionResultDeny]]``.

Threat model is unchanged from ``scope.py``: this prevents *accidents* (a tool
firing at a host outside the authorized exercise range) and provides
*accountability* (the audit log). It is a safety rail for authorized CTF/lab
use, not a barrier against a determined operator running tools outside SCS.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Awaitable, Callable

from sikun.scope import ScopeGuard, extract_hosts

# Imported from the installed SDK (dataclasses only — importing these does not
# launch the Claude Code binary; that happens on query()).
from claude_agent_sdk import (
    PermissionResultAllow,
    PermissionResultDeny,
    ToolPermissionContext,
)


def screen_targets(guard: ScopeGuard, tool: str, targets: list[str]) -> str | None:
    """RELIABLE scope check for a tool that declares its targets. Audits the
    decision and returns an error string when out of scope (to hand back to
    the model/worker), or ``None`` when allowed. Mirrors
    ``scope.guard_reliable`` but without needing a TUI app handle, so workers
    can call it directly."""
    bad = guard.check(targets)
    guard.audit(tool, targets, "blocked" if bad else "allow")
    if bad:
        allowed = ", ".join(guard.scope.raw) or "未設定"
        return (f"対象が認可スコープ外のため拒否: {', '.join(bad)}"
                f"(認可範囲: {allowed})")
    return None


# How to pull the target list out of a tool call's input, per tool. A tool not
# listed here is treated as "target undeclared" and falls back to best-effort
# extraction from any string argument (confirm-style: we DENY on a hit, since
# an unattended agent has no operator to confirm with).
def _declared_targets(tool_name: str, tool_input: dict[str, Any]) -> list[str] | None:
    key_by_tool = {
        "nmap_scan": "target",
        "http_probe": "url",
        "dir_enum": "url",
    }
    key = key_by_tool.get(tool_name)
    if key is not None:
        val = tool_input.get(key)
        return [val] if isinstance(val, str) and val else []
    return None  # undeclared


def make_scope_permission(
    guard: ScopeGuard,
    *,
    extra_declared: Callable[[str, dict[str, Any]], list[str] | None] | None = None,
) -> Callable[[str, dict[str, Any], ToolPermissionContext],
              Awaitable[PermissionResultAllow | PermissionResultDeny]]:
    """Build a Claude Agent SDK ``can_use_tool`` callback that enforces scope.

    - A tool with declared targets (nmap/http/dir, or a plugin that supplies
      them via ``extra_declared``) is checked RELIABLY and hard-denied when out
      of scope — no false positives.
    - A tool with no declared target (e.g. raw Bash) is checked BEST-EFFORT by
      scraping host-like tokens from its arguments. On a hit we DENY, because
      an autonomous worker has no human to confirm with (safe default = block).
      When scope is disabled (empty), nothing is blocked.

    Every decision is written to the audit log via ``guard``.
    """

    async def can_use_tool(
        tool_name: str,
        tool_input: dict[str, Any],
        context: ToolPermissionContext,
    ) -> PermissionResultAllow | PermissionResultDeny:
        declared = _declared_targets(tool_name, tool_input)
        if declared is None and extra_declared is not None:
            declared = extra_declared(tool_name, tool_input)

        if declared is not None:
            err = screen_targets(guard, tool_name, declared)
            if err:
                return PermissionResultDeny(behavior="deny", message=err)
            return PermissionResultAllow(behavior="allow")

        # Undeclared: best-effort scrape of all string args.
        if guard.enabled:
            blob = " ".join(str(v) for v in tool_input.values() if isinstance(v, (str, int)))
            host_like = extract_hosts(blob)
            bad = guard.check(host_like)
            if bad:
                guard.audit(tool_name, host_like, "blocked-besteffort")
                return PermissionResultDeny(
                    behavior="deny",
                    message=(f"認可スコープ外の可能性がある対象を検出のため拒否: "
                             f"{', '.join(bad)}(認可範囲: {', '.join(guard.scope.raw)})"),
                )
            guard.audit(tool_name, host_like, "allow-besteffort")
        return PermissionResultAllow(behavior="allow")

    return can_use_tool


def new_guard(scope_entries: list[str], audit_path: Path, session_target: str) -> ScopeGuard:
    """Convenience: build a ScopeGuard from profile scope entries (+ the
    session target, auto-allowed like the Gemini engine does)."""
    from sikun.scope import Scope

    entries = list(scope_entries)
    if entries and session_target:
        entries.append(session_target)
    return ScopeGuard(Scope(entries), audit_path, session_target)
