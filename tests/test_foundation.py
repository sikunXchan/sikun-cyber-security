"""v1.0 foundation tests — profiles, plugins, scaffold, RAG chunking, parsers, TUI board.

Runs two ways:
  * `python tests/test_foundation.py`  (no extra deps — uses the built-in runner below)
  * `pytest`                           (each test_* is a plain sync function)

Every test is offline: the one plugin that shells out is driven with a fake
`ctx.run`, so nothing here touches the network or an API key.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from sikun import scaffold
from sikun.plugins import PluginContext, load_plugins
from sikun.profile import PROJECT_ROOT, load_profile
from sikun.rag import _split_into_chunks
from sikun.tools import _guess_tech, _parse_http_headers
from sikun.tui import SikunApp


def test_default_profile_loads():
    p = load_profile(None)
    assert p.name == "default"
    assert p.provider == "gemini"
    assert p.plugin_dirs and p.plugin_dirs[0].name == "plugins"


def test_example_plugin_loads_and_runs():
    p = load_profile(None)
    result = load_plugins(p.plugin_dirs)
    assert not result.errors, result.errors
    by_name = {pl.name: pl for pl in result.plugins}
    assert "reverse_dns" in by_name

    async def fake_run(cmd: str) -> str:
        assert "9.9.9.9" in cmd
        return "9.9.9.9 dns9.example."

    ctx = PluginContext(target="9.9.9.9", ssh_host=None, workdir=Path.home(), run=fake_run)
    out = asyncio.run(by_name["reverse_dns"].run({"ip": "9.9.9.9"}, ctx))
    assert out["ip"] == "9.9.9.9" and "dns9.example" in out["result"]


def test_plugin_loader_rejects_reserved_and_broken():
    with tempfile.TemporaryDirectory() as d:
        dir_ = Path(d)
        # reserved name -> rejected
        (dir_ / "bad_reserved.py").write_text(
            "from sikun.plugins import ToolPlugin\n"
            "async def _r(a, c): return {}\n"
            "PLUGIN = ToolPlugin(name='bash', description='x', parameters={'type':'object','properties':{}}, run=_r)\n"
        )
        # syntax error -> reported, not fatal
        (dir_ / "broken.py").write_text("def oops(:\n")
        # underscore-prefixed -> ignored entirely
        (dir_ / "_helper.py").write_text("x = 1\n")
        # one good plugin still loads alongside the bad ones
        (dir_ / "good.py").write_text(
            "from sikun.plugins import ToolPlugin\n"
            "async def _r(a, c): return {'ok': True}\n"
            "PLUGIN = ToolPlugin(name='good_tool', description='x', parameters={'type':'object','properties':{}}, run=_r)\n"
        )
        result = load_plugins([dir_])
        names = {pl.name for pl in result.plugins}
        assert names == {"good_tool"}, names
        assert any("予約名" in e for e in result.errors)
        assert any("broken.py" in e for e in result.errors)


def test_scaffold_creates_and_skips():
    name = "unittest_scaffold_tmp"
    prof = PROJECT_ROOT / "profiles" / f"{name}.toml"
    plug = PROJECT_ROOT / "plugins" / f"{name}_ping.py"
    try:
        created, skipped = scaffold.init_agent(name)
        assert prof.exists() and plug.exists()
        assert not skipped
        # second run skips existing files rather than clobbering
        created2, skipped2 = scaffold.init_agent(name)
        assert not created2 and len(skipped2) == 2
        # generated artifacts are valid
        assert load_profile(name).name == name
        assert f"{name}_ping" in {pl.name for pl in load_plugins([PROJECT_ROOT / "plugins"]).plugins}
    finally:
        prof.unlink(missing_ok=True)
        plug.unlink(missing_ok=True)


def test_rag_chunking_splits_on_headings():
    with tempfile.TemporaryDirectory() as d:
        kb = Path(d)
        (kb / "sample.md").write_text("intro text\n\n## 見出しA\n本文A\n\n## 見出しB\n本文B\n")
        chunks = _split_into_chunks(kb)
        headings = [c.heading for c in chunks]
        assert "見出しA" in headings and "見出しB" in headings
        assert any("本文A" in c.text for c in chunks)


def test_http_header_parser_keeps_last_hop():
    raw = (
        "HTTP/1.1 301 Moved Permanently\r\nLocation: http://x/\r\n\r\n"
        "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: PHP/8.1\r\n\r\n"
    )
    status, headers = _parse_http_headers(raw)
    assert status == "200", status
    assert headers.get("Server") == "nginx", headers


def test_guess_tech_from_fingerprints():
    tech = _guess_tech({"Server": "nginx", "X-Powered-By": "PHP/8.1"}, "")
    assert "nginx" in tech and "PHP" in tech


def test_tui_board_tracks_state():
    async def run():
        app = SikunApp(target="192.168.56.10", profile_name="default")
        async with app.run_test() as pilot:
            app.update_board(
                model="gemini-3.5-flash",
                cost=0.1234,
                ports=[
                    {"port": "22", "protocol": "tcp", "service": "ssh"},
                    {"port": "80", "protocol": "tcp", "service": "http"},
                ],
            )
            app.update_board(ports=[{"port": "22", "protocol": "tcp", "service": "ssh"}])
            await app.post_event("finding", "SQLi 認証バイパス", "high")
            await app.post_event("recon", "port 22 open")
            await pilot.pause()
            assert len(app.board["ports"]) == 2
            assert app.board["findings"]["high"] == 1
            assert app.board["phase"] == "recon"
            app._board_renderable()  # must not raise
            assert "gemini-3.5-flash" in app._status_text()

    asyncio.run(run())


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
