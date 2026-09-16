"""Tests for sikun/webapp.py (the pywebview native UI backend).

Runs two ways, same as test_foundation.py:
  * `python tests/test_webapp.py`  (no extra deps beyond requirements.txt)
  * `pytest`

None of this opens a real window — WebApp._push() is a no-op when
self._window is None, and the asyncio wiring that _agent_thread_main()
normally sets up (loop / queue / interrupt event) is built by hand here so
the same JSBridge <-> WebApp handshake pywebview drives in production can be
exercised on a single thread, without a display.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import sikun.webapp as webapp_mod
from sikun.tui import Interrupted
from sikun.webapp import JSBridge, WebApp, markup_to_html


def _wire_loop_state(app: WebApp) -> None:
    """Stand in for WebApp._agent_thread_main()'s setup, using the
    already-running test loop instead of spinning up a background thread."""
    app._loop = asyncio.get_running_loop()
    app._interrupt_event = asyncio.Event()
    app._instruction_queue = asyncio.Queue()


def test_markup_to_html_escapes_and_styles():
    html = markup_to_html("[bold #00f0ff]hello[/bold #00f0ff] <script>alert(1)</script>")
    assert "#00f0ff" in html
    assert "&lt;script&gt;" in html
    assert "<script>" not in html


def test_webapp_board_tracks_state():
    async def run():
        app = WebApp(target="192.168.56.10", profile_name="default")
        try:
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
            assert len(app.board["ports"]) == 2
            assert app.board["findings"]["high"] == 1
            assert app.board["phase"] == "recon"
        finally:
            app._log_file.close()

    asyncio.run(run())


def test_webapp_instruction_roundtrip_via_jsbridge():
    async def run():
        app = WebApp(target="10.0.0.5")
        try:
            _wire_loop_state(app)
            bridge = JSBridge(app)

            wait_task = asyncio.ensure_future(app.wait_for_instruction())
            await asyncio.sleep(0)  # let wait_for_instruction start awaiting the queue
            bridge.submit_instruction("recon開始して")
            result = await asyncio.wait_for(wait_task, timeout=1)
            assert result == "recon開始して"
        finally:
            app._log_file.close()

    asyncio.run(run())


def test_webapp_run_interruptible_raises_on_jsbridge_interrupt():
    async def run():
        app = WebApp(target="10.0.0.5")
        try:
            _wire_loop_state(app)
            bridge = JSBridge(app)

            async def never_ending():
                await asyncio.sleep(10)
                return "done"

            task = asyncio.ensure_future(app.run_interruptible(never_ending()))
            await asyncio.sleep(0)
            bridge.interrupt()
            try:
                await asyncio.wait_for(task, timeout=1)
            except Interrupted:
                pass
            else:
                raise AssertionError("expected Interrupted")
        finally:
            app._log_file.close()

    asyncio.run(run())


def test_webapp_wait_for_choice_returns_clicked_value():
    async def run():
        app = WebApp(target="10.0.0.5")
        try:
            _wire_loop_state(app)
            bridge = JSBridge(app)

            task = asyncio.ensure_future(
                app.wait_for_choice([("続行", "continue"), ("中止", "stop")])
            )
            await asyncio.sleep(0)
            bridge.choose("stop")
            result = await asyncio.wait_for(task, timeout=1)
            assert result == "stop"
        finally:
            app._log_file.close()

    asyncio.run(run())


def test_reports_list_and_read_blocks_path_traversal():
    with tempfile.TemporaryDirectory() as d:
        orig_rem, orig_det = webapp_mod.REMEDIATIONS_DIR, webapp_mod.DETECTIONS_DIR
        webapp_mod.REMEDIATIONS_DIR = Path(d) / "remediations"
        webapp_mod.DETECTIONS_DIR = Path(d) / "detections"
        try:
            webapp_mod.REMEDIATIONS_DIR.mkdir()
            webapp_mod.DETECTIONS_DIR.mkdir()
            (webapp_mod.REMEDIATIONS_DIR / "fix1.md").write_text("# fix", encoding="utf-8")
            (webapp_mod.DETECTIONS_DIR / "rule1.yml").write_text("title: x", encoding="utf-8")

            items = webapp_mod.list_reports()
            assert {i["name"] for i in items} == {"fix1.md", "rule1.yml"}
            assert webapp_mod.read_report("remediation", "fix1.md") == "# fix"

            for bad_name in ("../fix1.md", "/etc/passwd"):
                try:
                    webapp_mod.read_report("remediation", bad_name)
                except ValueError:
                    pass
                else:
                    raise AssertionError(f"expected ValueError for {bad_name!r}")
        finally:
            webapp_mod.REMEDIATIONS_DIR, webapp_mod.DETECTIONS_DIR = orig_rem, orig_det


def test_profiles_list_read_save_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        orig = webapp_mod.PROFILES_DIR
        webapp_mod.PROFILES_DIR = Path(d)
        try:
            assert webapp_mod.list_profiles() == []

            ok = webapp_mod.save_profile("mine", 'name = "mine"\npersona = "careful"\n')
            assert ok == {"ok": True}
            assert webapp_mod.list_profiles() == ["mine"]
            assert 'persona = "careful"' in webapp_mod.read_profile("mine")

            bad = webapp_mod.save_profile("mine", "not [valid toml")
            assert bad["ok"] is False and "error" in bad
            # a rejected save must not clobber the last-good content on disk
            assert 'persona = "careful"' in webapp_mod.read_profile("mine")

            try:
                webapp_mod.save_profile("../evil", "x = 1")
            except ValueError:
                pass
            else:
                raise AssertionError("expected ValueError for path traversal")
        finally:
            webapp_mod.PROFILES_DIR = orig


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
