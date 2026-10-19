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
        height: 1;
        padding: 0 1;
        border: none;
        background: #0a0e1a;
        color: #d7fbff;
    }
    #cmdline:focus { background: #122238; }
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
        self._frame = 0
        self._activity = ""      # non-empty while the agent is working -> spinner
        self._last_sec = -1
        # Cached widget handles + last-rendered status string. Re-querying the
        # DOM and repainting the status bar on every timer tick is what made
        # the hardware cursor (and the IME conversion popup anchored to it)
        # jump around while typing. We now repaint only when the text actually
        # changes, and never while the operator is mid-input (see _tick).
        self._status_widget: Static | None = None
        self._input_widget: Input | None = None
        self._last_status = ""

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
        # Cache the widgets the status timer touches so _tick never re-queries
        # the DOM (a per-tick query_one is both wasteful and a refresh trigger).
        self._status_widget = self.query_one("#status-bar", Static)
        self._input_widget = self.query_one("#cmdline", Input)
        self.set_interval(0.15, self._tick)
        self.run_worker(self._startup(), exclusive=False)
        self._input_widget.focus()
        # The real terminal cursor starts at the top-left (0,0). Until the first
        # keystroke moves it into the input box, a Japanese IME composition
        # anchors at that corner instead of in the box. Re-assert focus and
        # repaint *after* the first paint so the hardware cursor lands in the
        # box up front and IME works from the very first character.
        self.call_after_refresh(self._prime_input)

    def _prime_input(self) -> None:
        inp = self._input_widget
        if inp is None:
            return
        inp.focus()
        # Textual computes the caret position correctly from the start, but the
        # real terminal cursor is only shown/moved once the caret actually
        # *changes* — the first typed character is normally what does it, which
        # is why a Japanese IME composition before that lands at the top-left
        # corner. Briefly move the caret (insert then clear) so that sync fires
        # up front and IME anchors in the box from the very first character.
        try:
            inp.insert_text_at_cursor(" ")
            inp.value = ""
            inp.cursor_position = 0
        except Exception:
            pass
        self.refresh()

    def on_resize(self, event) -> None:
        # Entering/leaving fullscreen resizes the terminal, which can reset the
        # hardware cursor to the top-left and re-break IME placement. Re-prime
        # after the resize settles — but only while the box is empty, so we
        # never disturb text (or an IME composition) already in progress.
        if self._input_widget is not None and not self._input_widget.value:
            self.call_after_refresh(self._prime_input)

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
            # Steady (non-blinking) ready indicator. Blinking forced a repaint
            # twice a second even while idle, which disturbed IME composition.
            lead = "[#39ff14]◉[/#39ff14]"
            tail = ""
        return (
            f"{lead} [bold #00f0ff]SikunCybersecurity[/bold #00f0ff] {sep} "
            f"[dim #6a7a99]tgt[/dim #6a7a99] [#ff3bd6]{self.target}[/#ff3bd6] {sep} "
            f"[#00f0ff]{mm:02d}:{ss:02d}[/#00f0ff]{tail}"
        )

    def _tick(self) -> None:
        self._frame += 1
        if self._activity:
            # Agent is working (operator is not typing): animate the spinner.
            self._refresh_status()
            return
        # Idle: advance the clock at most once per second...
        sec = int(time.monotonic() - self._start_time)
        if sec == self._last_sec:
            return
        self._last_sec = sec
        # ...but hold the repaint entirely while the operator is composing in
        # the input box. Repainting moves the terminal cursor, which drags the
        # IME conversion window with it and makes it flicker/jump. A frozen
        # clock for a few seconds of typing is a fair trade for a steady caret.
        if self._input_widget is not None and self._input_widget.value:
            return
        self._refresh_status()

    def _refresh_status(self) -> None:
        if self._status_widget is None:
            return
        text = self._status_text()
        if text == self._last_status:
            return  # nothing visible changed -> skip the repaint
        self._last_status = text
        try:
            self._status_widget.update(text)
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
            # Never let a single malformed event (e.g. an unexpected channel)
            # raise out of this loop: that would kill the worker and silently
            # freeze the entire transcript. Fall back to the raw text instead.
            try:
                body = event.render()
            except Exception as exc:  # pragma: no cover - defensive
                body = f"[dim #6a7a99]({type(exc).__name__}) {event.text}[/dim #6a7a99]"
            try:
                transcript.write(f"[#33425c]{ts}[/#33425c] {body}")
            except Exception:
                transcript.write(f"[#33425c]{ts}[/#33425c] {event.text}")

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
