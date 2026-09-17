"""Sikun Cyber Security — native desktop UI (pywebview).

Mirrors SikunApp's (sikun/tui.py) public async interface — post_event /
run_interruptible / wait_for_instruction / wait_for_choice / session_state /
update_board / set_activity / clear_activity — so sikun.agent_gemini.run_agent
drives this exactly like the Textual TUI, unmodified.

pywebview requires the GUI loop on the main thread, so the window is created
there and the agent's asyncio loop runs on a background thread started by
webview.start(func=...). JS-originated calls (JSBridge methods below) arrive
on pywebview's own thread and hop onto that loop via call_soon_threadsafe;
Python-to-JS pushes go through Window.evaluate_js(), which pywebview allows
from any thread.
"""

from __future__ import annotations

import asyncio
import datetime
import io
import json
import shutil
import tomllib
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Coroutine, TypeVar

import webview
from rich.console import Console
from rich.text import Text as RichText

from sikun.events import AgentEvent
from sikun.tui import LOG_DIR, Interrupted

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = Path(__file__).resolve().parent / "web"
REMEDIATIONS_DIR = PROJECT_ROOT / "remediations"
DETECTIONS_DIR = PROJECT_ROOT / "detections"
PROFILES_DIR = PROJECT_ROOT / "profiles"
MASCOT_SRC = Path(__file__).resolve().parent / "assets" / "mascot.png"
MASCOT_WEB_COPY = WEB_DIR / "assets" / "mascot.png"


def _sync_web_assets() -> None:
    """WebKitGTK's file:// loader blocks '../' out of the page's own
    directory, so the mascot can't be referenced straight from
    sikun/assets/ the way the TUI banner does. Mirror it into
    sikun/web/assets/ (re-copied whenever the source changes) instead of
    hand-maintaining a second binary."""
    if not MASCOT_SRC.exists():
        return
    if MASCOT_WEB_COPY.exists() and MASCOT_WEB_COPY.stat().st_mtime >= MASCOT_SRC.stat().st_mtime:
        return
    MASCOT_WEB_COPY.parent.mkdir(exist_ok=True)
    shutil.copyfile(MASCOT_SRC, MASCOT_WEB_COPY)

T = TypeVar("T")

AgentFactory = Callable[["WebApp"], Awaitable[None]]


def markup_to_html(markup: str) -> str:
    """Render Rich markup to an inline-styled HTML fragment (spans only, no
    document wrapper) — reuses the exact same color language as the TUI
    (sikun/events.py) so the transcript looks consistent between surfaces."""
    buf = io.StringIO()
    console = Console(
        file=buf, record=True, width=200, force_terminal=True,
        color_system="truecolor", highlight=False,
    )
    console.print(RichText.from_markup(markup), end="")
    return console.export_html(inline_styles=True, code_format="{code}")


# --- Reports (remediations/ + detections/) — pure file I/O, no agent-loop coupling ---

def list_reports() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for kind, directory, suffix in (
        ("remediation", REMEDIATIONS_DIR, ".md"),
        ("detection", DETECTIONS_DIR, ".yml"),
    ):
        if not directory.exists():
            continue
        for path in directory.glob(f"*{suffix}"):
            stat = path.stat()
            items.append({
                "kind": kind,
                "name": path.name,
                "mtime": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "mtime_epoch": stat.st_mtime,
                "size": stat.st_size,
            })
    items.sort(key=lambda x: x["mtime_epoch"], reverse=True)
    return items


def _report_dir(kind: str) -> Path:
    if kind == "remediation":
        return REMEDIATIONS_DIR
    if kind == "detection":
        return DETECTIONS_DIR
    raise ValueError(f"unknown report kind: {kind}")


def read_report(kind: str, name: str) -> str:
    """Read one report file by kind + bare filename. Rejects anything that
    isn't a plain filename inside the expected directory (no path traversal)."""
    directory = _report_dir(kind)
    if not name or Path(name).name != name:
        raise ValueError("invalid report name")
    path = directory / name
    if not path.is_file():
        raise FileNotFoundError(name)
    return path.read_text(encoding="utf-8")


# --- Profiles (profiles/*.toml) — Settings page ---

def list_profiles() -> list[str]:
    if not PROFILES_DIR.exists():
        return []
    return sorted(p.stem for p in PROFILES_DIR.glob("*.toml"))


def _profile_path(name: str) -> Path:
    if not name or Path(name).name != name:
        raise ValueError("invalid profile name")
    return PROFILES_DIR / f"{name}.toml"


def read_profile(name: str) -> str:
    path = _profile_path(name)
    return path.read_text(encoding="utf-8") if path.exists() else ""


def save_profile(name: str, content: str) -> dict[str, Any]:
    path = _profile_path(name)
    try:
        tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        return {"ok": False, "error": str(exc)}
    PROFILES_DIR.mkdir(exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return {"ok": True}


class WebApp:
    def __init__(
        self,
        target: str = "(未設定)",
        profile_name: str = "default",
        start_mode: str = "security",
    ) -> None:
        self.target = target
        self.profile_name = profile_name
        self._window: webview.Window | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._start_time = datetime.datetime.now()

        self.session_state: dict[str, str] = {"mode": start_mode, "effort": "default"}
        self.board: dict[str, Any] = {
            "model": "",
            "cost": 0.0,
            "phase": "-",
            "cwd": "",
            "last_cmd": "",
            "turns": 0,
            "tools": 0,
            "cost_history": [],
            "ports": [],
            "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        self._activity = ""

        # Created once the agent thread's event loop is running (see
        # _agent_thread_main) — JSBridge methods only touch these after
        # self._loop is set, so there's no race with the window opening.
        self._interrupt_event: asyncio.Event | None = None
        self._instruction_queue: asyncio.Queue[str] | None = None
        self._choice_future: asyncio.Future[str] | None = None

        LOG_DIR.mkdir(exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[:40]
        self._log_path = LOG_DIR / f"{ts}_{safe_target}.log"
        self._log_file = self._log_path.open("a", encoding="utf-8")

    # --- window lifecycle -------------------------------------------------

    def run(self, agent_factory: AgentFactory | None = None) -> None:
        _sync_web_assets()
        bridge = JSBridge(self)
        self._window = webview.create_window(
            "Sikun Cyber Security",
            url=str((WEB_DIR / "index.html").resolve()),
            js_api=bridge,
            width=1280,
            height=860,
            min_size=(960, 640),
            background_color="#05060a",
        )
        self._window.events.closed += self._on_closed
        if agent_factory is not None:
            webview.start(self._agent_thread_main, (agent_factory,), debug=False)
        else:
            webview.start(debug=False)

    def _on_closed(self) -> None:
        if not self._log_file.closed:
            self._log_file.close()

    def _agent_thread_main(self, agent_factory: AgentFactory) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._interrupt_event = asyncio.Event()
        self._instruction_queue = asyncio.Queue()
        try:
            loop.run_until_complete(self._boot_and_run(agent_factory))
        finally:
            loop.close()

    async def _boot_and_run(self, agent_factory: AgentFactory) -> None:
        self._push_board()
        self._push_meta()
        await self.post_event(
            "system",
            f"[bold #00f0ff]◈ SIKUN CYBER SECURITY[/bold #00f0ff] "
            f"[dim #6a7a99]起動しました — 対象: {self.target} "
            f"ログ: {self._log_path}[/dim #6a7a99]",
        )
        try:
            await agent_factory(self)
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator, never swallowed silently
            await self.post_event("system", f"[bold red]致命的エラー: {exc}[/bold red]")

    # --- SikunApp-compatible interface used by sikun.agent_gemini.run_agent ---

    async def post_event(self, channel: str, text: str, severity: str | None = None) -> None:
        event = AgentEvent(channel=channel, text=text, severity=severity)  # type: ignore[arg-type]
        self._write_log_line(event)

        if channel in ("recon", "exploit", "finding"):
            self.board["phase"] = channel
        if channel == "finding" and severity in self.board["findings"]:
            self.board["findings"][severity] += 1

        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._push("pushEvent", {
            "channel": channel,
            "severity": severity,
            "ts": ts,
            "html": markup_to_html(event.render()),
        })
        self._push_board()

    async def run_interruptible(self, coro: Coroutine[Any, Any, T]) -> T:
        assert self._interrupt_event is not None, "run_interruptible() called before the agent loop started"
        self._interrupt_event.clear()
        task: asyncio.Task[T] = asyncio.ensure_future(coro)
        interrupt_wait = asyncio.ensure_future(self._interrupt_event.wait())
        done, _pending = await asyncio.wait(
            {task, interrupt_wait}, return_when=asyncio.FIRST_COMPLETED
        )
        if task in done:
            interrupt_wait.cancel()
            return task.result()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        raise Interrupted()

    async def wait_for_instruction(self) -> str:
        assert self._instruction_queue is not None, "wait_for_instruction() called before the agent loop started"
        self._push("setBusy", {"busy": False})
        instruction = await self._instruction_queue.get()
        self._push("setBusy", {"busy": True})
        return instruction

    async def wait_for_choice(self, options: list[tuple[str, str]]) -> str:
        assert self._loop is not None
        future: asyncio.Future[str] = self._loop.create_future()
        self._choice_future = future
        self._push("showChoice", {"options": [{"label": label, "value": value} for label, value in options]})
        try:
            return await future
        finally:
            self._choice_future = None
            self._push("hideChoice", {})

    def update_board(self, **kwargs: Any) -> None:
        ports = kwargs.pop("ports", None)
        if ports:
            self._merge_ports(ports)
        turn_cost = kwargs.pop("turn_cost", None)
        if turn_cost is not None:
            hist = self.board["cost_history"]
            hist.append(float(turn_cost))
            del hist[:-40]
        self.board.update(kwargs)
        self._push_board()

    def _merge_ports(self, ports: list[dict]) -> None:
        seen = {(p.get("host") or self.target, p.get("port"), p.get("protocol")): p for p in self.board["ports"]}
        for p in ports:
            key = (p.get("host") or self.target, p.get("port"), p.get("protocol"))
            if key not in seen:
                seen[key] = dict(p)
                self.board["ports"].append(seen[key])
            else:
                seen[key].update({k: v for k, v in p.items() if v not in (None, "", "unknown")})

    def set_activity(self, label: str) -> None:
        self._activity = label
        self._push("setActivity", {"activity": label})

    def clear_activity(self) -> None:
        self._activity = ""
        self._push("setActivity", {"activity": ""})

    # --- slash commands (mirrors sikun/tui.py's _handle_command) ---

    async def handle_command(self, raw: str) -> None:
        parts = raw.split(maxsplit=1)
        if not parts:
            return
        cmd, arg = parts[0].lower(), (parts[1].strip() if len(parts) > 1 else "")

        if cmd == "mode":
            if arg not in ("security", "study", "general"):
                await self.post_event("system", "[bold red]使い方: /mode security|study|general[/bold red]")
                return
            self.session_state["mode"] = arg
            self._push_meta()
            await self.post_event("system", f"[bold green]モード切替: {arg}(次のターンから反映)[/bold green]")
        elif cmd == "effort":
            if not arg:
                await self.post_event("system", "[bold red]使い方: /effort low|medium|high|xhigh|max[/bold red]")
                return
            self.session_state["effort"] = arg
            await self.post_event(
                "system",
                f"[bold green]effort設定: {arg}(次のターンから反映。Geminiバックエンドでは"
                "現状効果なし)[/bold green]",
            )
        elif cmd == "plan":
            self.session_state["force_plan"] = "1"
            await self.post_event("system", "[bold green]次のタスクは計画提示を強制します[/bold green]")
        elif cmd == "model":
            if arg not in ("lite", "full"):
                await self.post_event("system", "[bold red]使い方: /model lite|full[/bold red]")
                return
            self.session_state["model"] = arg
            note = "簡単な作業向けの軽量モデル" if arg == "lite" else "通常モデル"
            await self.post_event("system", f"[bold green]モデル切替: {arg}({note}、次のターンから反映)[/bold green]")
        else:
            await self.post_event("system", f"[bold red]不明なコマンド: /{cmd}[/bold red]")

    # --- internals ---

    def _push_board(self) -> None:
        self._push("pushBoard", self.board)

    def _push_meta(self) -> None:
        self._push("setMeta", {"target": self.target, "mode": self.session_state.get("mode", "-")})

    def _push(self, fn_name: str, payload: dict) -> None:
        """Fire-and-forget push into the page. Safe to call before the window
        exists (tests construct a WebApp without ever opening one) and safe
        to call from the agent's background thread — pywebview serializes
        evaluate_js() calls onto the GUI thread internally."""
        if self._window is None:
            return
        try:
            self._window.evaluate_js(f"window.sikun && window.sikun.{fn_name}({json.dumps(payload)})")
        except Exception:
            pass

    def _write_log_line(self, event: AgentEvent) -> None:
        if self._log_file.closed:
            return
        plain = RichText.from_markup(event.render()).plain.strip("\n")
        if not plain:
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._log_file.write(f"[{ts}][{event.channel}] {plain}\n")
        self._log_file.flush()


class JSBridge:
    """Exposed to the page as window.pywebview.api.* Every method below
    arrives on pywebview's own thread, never the agent's event-loop thread,
    so anything touching asyncio state hops back via call_soon_threadsafe."""

    def __init__(self, app: WebApp) -> None:
        self._app = app

    def submit_instruction(self, text: str) -> None:
        app = self._app
        text = (text or "").strip()
        if not text or app._loop is None or app._instruction_queue is None:
            return
        if text.startswith("/"):
            app._loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(app.handle_command(text[1:].strip()), loop=app._loop)
            )
            return
        app._loop.call_soon_threadsafe(
            lambda: asyncio.ensure_future(
                app.post_event("system", f"[bold cyan]> {text}[/bold cyan]"), loop=app._loop
            )
        )
        app._loop.call_soon_threadsafe(app._instruction_queue.put_nowait, text)

    def choose(self, value: str) -> None:
        app = self._app
        if app._loop is None:
            return

        def _resolve() -> None:
            future = app._choice_future
            if future is not None and not future.done():
                future.set_result(value)

        app._loop.call_soon_threadsafe(_resolve)

    def interrupt(self) -> None:
        app = self._app
        if app._loop is None or app._interrupt_event is None:
            return
        app._loop.call_soon_threadsafe(app._interrupt_event.set)

    # --- Reports / Settings: plain file I/O, safe on pywebview's own thread ---

    def list_reports(self) -> list[dict[str, Any]]:
        return list_reports()

    def read_report(self, kind: str, name: str) -> dict[str, Any]:
        try:
            return {"ok": True, "content": read_report(kind, name)}
        except (ValueError, FileNotFoundError) as exc:
            return {"ok": False, "error": str(exc)}

    def list_profiles(self) -> list[str]:
        return list_profiles()

    def read_profile(self, name: str) -> dict[str, Any]:
        try:
            return {"ok": True, "content": read_profile(name)}
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}

    def save_profile(self, name: str, content: str) -> dict[str, Any]:
        try:
            return save_profile(name, content)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
