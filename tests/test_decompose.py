"""Tests for decompose() and the core-tool MCP wiring + scope enforcement.

Offline: no network, no API key, no SDK subprocess (building SDK tool objects
and ClaudeAgentOptions does not launch the Claude binary — only query() does).

Runs two ways:
  * `python tests/test_decompose.py`
  * `pytest`
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from claude_agent_sdk import ToolPermissionContext

from sikun.agent_claude import build_agent_options, make_ctx_factory
from sikun.claude_core_tools import CORE_SCOPE, core_tools
from sikun.decompose import decompose, detect_categories
from sikun.orchestrator import build_layers
from sikun.permission import new_guard


# ── decompose ─────────────────────────────────────────────────────────────

def test_detect_categories_keyword_hits():
    assert "web" in detect_categories("管理画面のSQLiを調べて")
    assert "crypto" in detect_categories("RSAの弱い鍵を解析")
    assert detect_categories("特に何もない指示") == []


def test_detect_categories_allowed_filter():
    hits = detect_categories("web と crypto の話", allowed={"web"})
    assert hits == ["web"]


def test_decompose_always_has_recon_anchor():
    tasks = decompose("なんらかの指示", target="10.0.0.1")
    assert tasks[0].id == "recon-1" and tasks[0].category == "recon"
    assert tasks[0].scope == ["10.0.0.1"]


def test_decompose_web_depends_on_recon_others_parallel():
    tasks = decompose("管理画面(web)とファームウェア(reversing)を調べる",
                      scope=["10.13.37.0/24"])
    by_id = {t.id: t for t in tasks}
    assert "web-1" in by_id and by_id["web-1"].depends_on == ["recon-1"]
    assert "reversing-1" in by_id and by_id["reversing-1"].depends_on == []
    # layers: recon + reversing in layer 0 (parallel), web in layer 1
    layers = build_layers(tasks)
    assert {t.id for t in layers[0]} == {"recon-1", "reversing-1"}
    assert [t.id for t in layers[1]] == ["web-1"]


def test_decompose_scope_inherited_by_children():
    tasks = decompose("webを調べる", scope=["10.0.0.0/24"])
    assert all(t.scope == ["10.0.0.0/24"] for t in tasks)


def test_decompose_respects_allowed_categories():
    # crypto detected but not allowed → only recon remains
    tasks = decompose("RSA暗号を解析", scope=[], target="t", categories=["recon", "web"])
    assert [t.id for t in tasks] == ["recon-1"]


# ── core tools + scope enforcement ─────────────────────────────────────────

def test_core_tools_names():
    tools = core_tools(ssh_host=None)
    assert [t.name for t in tools] == ["nmap_scan", "http_probe", "dir_enum"]


def test_core_scope_extraction():
    assert CORE_SCOPE["nmap_scan"]({"target": "10.0.0.1"}) == ["10.0.0.1"]
    assert CORE_SCOPE["http_probe"]({"url": "http://10.0.0.1/"}) == ["http://10.0.0.1/"]
    assert CORE_SCOPE["nmap_scan"]({}) == []


def test_build_agent_options_registers_core_tool_names():
    with tempfile.TemporaryDirectory() as d:
        guard = new_guard(["10.13.37.0/24"], Path(d) / "a.log", "10.13.37.10")
        opts = build_agent_options(
            system_prompt="p", guard=guard, allowed_tools=["Bash"], plugins=[],
            ctx_factory=make_ctx_factory("10.13.37.10", None, Path(d)),
            core_tools=core_tools(None), core_scope=CORE_SCOPE)
    for name in ("mcp__scs__nmap_scan", "mcp__scs__http_probe", "mcp__scs__dir_enum"):
        assert name in opts.allowed_tools
    assert "Bash" in opts.allowed_tools


def test_permission_gate_blocks_out_of_scope_core_tool():
    with tempfile.TemporaryDirectory() as d:
        guard = new_guard(["10.13.37.0/24"], Path(d) / "a.log", "10.13.37.10")
        opts = build_agent_options(
            system_prompt="p", guard=guard, allowed_tools=["Bash"], plugins=[],
            ctx_factory=make_ctx_factory("10.13.37.10", None, Path(d)),
            core_tools=core_tools(None), core_scope=CORE_SCOPE)
        ctx = ToolPermissionContext()

        async def run():
            ok = await opts.can_use_tool("mcp__scs__nmap_scan", {"target": "10.13.37.42"}, ctx)
            bad = await opts.can_use_tool("mcp__scs__nmap_scan", {"target": "8.8.8.8"}, ctx)
            return ok, bad

        ok, bad = asyncio.run(run())
    assert ok.behavior == "allow"
    assert bad.behavior == "deny" and "8.8.8.8" in bad.message


def _main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
