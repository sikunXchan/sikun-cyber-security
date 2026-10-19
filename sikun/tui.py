"""Sikun Cyber Security — minimal terminal UI.

Claude-Code-like: one linear scrolling transcript, a slim status line, and a
bottom input box. No sidebar, no cost readout, no modes, no startup theatre —
just the banner once, then the conversation.
"""

from __future__ import annotations

import asyncio
import datetime
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Coroutine, TypeVar

from rich.text import Text as RichText
from textual.app import App, ComposeResult
from textual.widgets import Input, RichLog, Static

from sikun.banner import banner_renderable
from sikun.events import AgentEvent

AgentFactory = Callable[["SikunApp"], Awaitable[None]]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"

T = TypeVar("T")


class Interrupted(Exception):
    """Raised by SikunApp.run_interruptible() when the operator presses Esc
    mid-call — Esc-to-stop for a runaway/long-running turn."""


class SikunApp(App):
    # Disable Textual's built-in command palette: it is an unexpected overlay
    # (and a source of the "screen goes blank" surprise on stray key combos).
    ENABLE_COMMAND_PALETTE = False

    CSS = """
    Screen { layout: vertical; background: #05060a; }

    #status-bar {
        height: 1;
        padding: 0 1;
        background: #0a0e1a;
        color: #00f0ff;
        text-style: bold;
    }

    #transcript {
        width: 1fr;
        height: 1fr;
        padding: 0 1;
        border: none;
        background: #05060a;
        color: #c7f5ff;
        scrollbar-size: 1 1;
        scrollbar-color: #ff2bd6;
        scrollbar-background: #0a0e1a;
    }

    #cmdline {
        dock: bottom;
        border: round #00f0ff;
        background: #0a0e1a;
        color: #d7fbff;
        margin: 0 1 1 1;
    }
    #cmdline:focus { border: round #ff2bd6; }
    """

    BINDINGS = [
        ("ctrl+c", "quit", "終了"),
        ("escape", "interrupt", "中断"),
    ]

    def __init__(
        self,
        target: str = "(未設定)",
        agent_factory: AgentFactory | None = None,
        profile_name: str = "default",
    ) -> None:
        super().__init__()
        self.target = target
        self.agent_factory = agent_factory
        self.profile_name = profile_name
        self.events: asyncio.Queue[AgentEvent] = asyncio.Queue()
        self.user_input: asyncio.Queue[str] = asyncio.Queue()
        self._start_time = time.monotonic()
        self._interrupt_event = asyncio.Event()
        self._blink = False
        self._frame = 0
        self._activity = ""      # non-empty while the agent is working -> spinner
        self._last_sec = -1

        LOG_DIR.mkdir(exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[:40]
        self._log_path = LOG_DIR / f"{ts}_{safe_target}.log"
        self._log_file = self._log_path.open("a", encoding="utf-8")

    def compose(self) -> ComposeResult:
        yield Static(self._status_text(), id="status-bar")
        yield RichLog(id="transcript", markup=True, wrap=True, highlight=False, auto_scroll=True)
        yield Input(placeholder="指示を入力して Enter", id="cmdline")

    def on_mount(self) -> None:
        self.set_interval(0.12, self._tick)
        self.run_worker(self._startup(), exclusive=False)
        self.query_one("#cmdline", Input).focus()

    async def _startup(self) -> None:
        log = self.query_one("#transcript", RichLog)
        log.write(banner_renderable())
        log.write(RichText.from_markup(f"[dim #6a7a99]session log: {self._log_path}[/dim #6a7a99]\n"))
        self.run_worker(self._drain_events(), exclusive=False)
        if self.agent_factory is not None:
            self.run_worker(self.agent_factory(self), exclusive=False)

    def on_unmount(self) -> None:
        if not self._log_file.closed:
            self._log_file.close()

    def action_interrupt(self) -> None:
        self._interrupt_event.set()

    async def run_interruptible(self, coro: Coroutine[Any, Any, T]) -> T:
        """Run `coro`; if the operator presses Esc before it finishes, cancel
        it and raise Interrupted."""
        self._interrupt_event.clear()
        task: asyncio.Task[T] = asyncio.ensure_future(coro)
        interrupt_wait = asyncio.ensure_future(self._interrupt_event.wait())
        done, _pending = await asyncio.wait(
            {task, interrupt_wait}, return_when=asyncio.FIRST_COMPLETED)
        if task in done:
            interrupt_wait.cancel()
            return task.result()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        raise Interrupted()

    _SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def _status_text(self) -> str:
        elapsed = int(time.monotonic() - self._start_time)
        mm, ss = divmod(elapsed, 60)
        sep = "[#2b3a5a]│[/#2b3a5a]"
        if self._activity:
            spin = self._SPINNER[self._frame % len(self._SPINNER)]
            lead = f"[bold #ff2bd6]{spin}[/bold #ff2bd6]"
            tail = f" {sep} [#ffb000]▸ {self._activity}[/#ffb000]"
        else:
            lead = "[#39ff14]◉[/#39ff14]" if self._blink else "[#124a12]◉[/#124a12]"
            tail = ""
        return (
            f"{lead} [bold #00f0ff]SikunCybersecurity[/bold #00f0ff] {sep} "
            f"[dim #6a7a99]tgt[/dim #6a7a99] [#ff3bd6]{self.target}[/#ff3bd6] {sep} "
            f"[#00f0ff]{mm:02d}:{ss:02d}[/#00f0ff]{tail}"
        )

    def _tick(self) -> None:
        self._frame += 1
        sec = int(time.monotonic() - self._start_time)
        if self._activity or sec != self._last_sec:
            self._last_sec = sec
            self._blink = (self._frame // 4) % 2 == 0
            self._refresh_status()

    def _refresh_status(self) -> None:
        try:
            self.query_one("#status-bar", Static).update(self._status_text())
        except Exception:
            pass

    def set_activity(self, label: str) -> None:
        self._activity = label
        self._refresh_status()

    def clear_activity(self) -> None:
        self._activity = ""
        self._refresh_status()

    async def _drain_events(self) -> None:
        transcript = self.query_one("#transcript", RichLog)
        while True:
            event = await self.events.get()
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            transcript.write(f"[#33425c]{ts}[/#33425c] {event.render()}")

    async def post_event(self, channel: str, text: str, severity: str | None = None) -> None:
        """Push a line into the transcript and mirror it (markup stripped) to
        the session log file."""
        event = AgentEvent(channel=channel, text=text, severity=severity)  # type: ignore[arg-type]
        await self.events.put(event)
        self._write_log_line(event)

    def _write_log_line(self, event: AgentEvent) -> None:
        if self._log_file.closed:
            return
        plain = RichText.from_markup(event.render()).plain.strip("\n")
        if not plain:
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._log_file.write(f"[{ts}][{event.channel}] {plain}\n")
        self._log_file.flush()

    async def on_input_submitted(self, message: Input.Submitted) -> None:
        text = message.value.strip()
        if not text:
            return
        message.input.value = ""

        if text.startswith("/"):
            await self._handle_command(text[1:].strip())
            return

        await self.post_event("system", f"\n[bold cyan]> {text}[/bold cyan]")
        await self.user_input.put(text)

    async def _handle_command(self, raw: str) -> None:
        cmd = raw.split(maxsplit=1)[0].lower() if raw else ""
        if cmd in ("quit", "exit", "q"):
            self.exit()
        elif cmd == "clear":
            self.query_one("#transcript", RichLog).clear()
        elif cmd == "help":
            await self.post_event(
                "system",
                "[dim]コマンド: /clear(画面消去) /quit(終了)。Esc=中断、Ctrl+C=終了。"
                "それ以外の入力はそのまま指示になります。[/dim]")
        else:
            await self.post_event("system", f"[dim]不明なコマンド: /{cmd}(/help)[/dim]")

    async def wait_for_instruction(self) -> str:
        """Block until the operator types something into the bottom input box."""
        return await self.user_input.get()


async def _demo_agent(app: SikunApp) -> None:
    """Fake producer so the layout can be sanity-checked without an API key."""
    await asyncio.sleep(0.5)
    await app.post_event("recon", "nmap 実行中...")
    await asyncio.sleep(0.5)
    await app.post_event("recon", "[+] port 80 open (Apache 2.4.41)")
    await app.post_event("finding", "/login の SQLi — 認証バイパス可能", severity="high")


def run_demo() -> None:
    app = SikunApp(target="192.168.56.10 (demo)", agent_factory=_demo_agent)
    app.run()


if __name__ == "__main__":
    run_demo()
