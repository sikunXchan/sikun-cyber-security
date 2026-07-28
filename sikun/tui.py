"""Sikun Cyber Security — rich terminal UI.

Layout mirrors Claude Code's CLI: one linear scrolling transcript (recon,
exploit, findings, tool calls/results, and operator input all interleaved
in real chronological order — not split into separate panes) plus a slim
status line and a bottom input box.
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
from textual.containers import Horizontal
from textual.widgets import Button, Input, RichLog, Static

from sikun.banner import banner_renderable
from sikun.events import AgentEvent

AgentFactory = Callable[["SikunApp"], Awaitable[None]]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"

T = TypeVar("T")

_BOARD_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_BOARD_SEV_COLOR = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "green",
    "info": "dim",
}


class Interrupted(Exception):
    """Raised by SikunApp.run_interruptible() when the operator presses Esc
    mid-call — mirrors Claude Code's Esc-to-stop behavior for a runaway/
    long-running turn, or one queued by an accidental Enter."""


class SikunApp(App):
    CSS = """
    Screen {
        layout: vertical;
        background: $surface;
    }

    #status-bar {
        height: 1;
        padding: 0 1;
        background: $panel;
        color: $text-muted;
    }

    #main-row {
        height: 1fr;
    }

    #transcript {
        width: 1fr;
        height: 1fr;
        padding: 0 1;
        border: none;
        scrollbar-size: 1 1;
    }

    #sidebar {
        width: 34;
        height: 1fr;
        padding: 0 1;
        border-left: solid $primary;
        color: $text;
    }

    #cmdline {
        dock: bottom;
        border: round $primary;
        margin: 0 1 1 1;
    }

    #choice-bar {
        height: 3;
        margin: 0 1;
        align: center middle;
        display: none;
    }

    #choice-bar Button {
        margin: 0 1;
    }
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
        # Live "situation board" shown in the right sidebar. Backends push into
        # it via update_board(); finding counts/phase are derived in post_event.
        self.board: dict[str, Any] = {
            "model": "",
            "cost": 0.0,
            "phase": "-",
            "ports": [],
            "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        # Mutable session controls, changed live via slash commands (/mode, /effort).
        # The agent loop polls this dict each turn rather than being handed a
        # one-shot config, so a switch takes effect on the *next* turn without
        # restarting the session.
        self.session_state: dict[str, str] = {"mode": "security", "effort": "default"}
        self._choice_future: asyncio.Future[str] | None = None
        self._interrupt_event = asyncio.Event()

        LOG_DIR.mkdir(exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[:40]
        self._log_path = LOG_DIR / f"{ts}_{safe_target}.log"
        self._log_file = self._log_path.open("a", encoding="utf-8")

    def compose(self) -> ComposeResult:
        yield Static(self._status_text(), id="status-bar")
        with Horizontal(id="main-row"):
            yield RichLog(id="transcript", markup=True, wrap=True, highlight=False, auto_scroll=True)
            yield Static(id="sidebar")
        yield Horizontal(id="choice-bar")
        yield Input(
            placeholder="指示を入力して Enter (/mode, /effort, /plan, /model)", id="cmdline"
        )

    def on_mount(self) -> None:
        transcript = self.query_one("#transcript", RichLog)
        transcript.write(banner_renderable())
        transcript.write(f"[dim]セッションログ: {self._log_path}[/dim]\n")
        self._refresh_sidebar()

        self.set_interval(1.0, self._tick_clock)
        self.run_worker(self._drain_events(), exclusive=False)
        if self.agent_factory is not None:
            self.run_worker(self.agent_factory(self), exclusive=False)
        self.query_one("#cmdline", Input).focus()

    def on_unmount(self) -> None:
        if not self._log_file.closed:
            self._log_file.close()

    def action_interrupt(self) -> None:
        """Esc — cancel whatever the agent is currently awaiting via
        run_interruptible() (a model call, a long shell command, ...)."""
        self._interrupt_event.set()

    async def run_interruptible(self, coro: Coroutine[Any, Any, T]) -> T:
        """Run `coro`; if the operator presses Esc before it finishes, cancel
        it and raise Interrupted instead of returning a result."""
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

    def _status_text(self) -> str:
        elapsed = int(time.monotonic() - self._start_time)
        mm, ss = divmod(elapsed, 60)
        mode = self.session_state.get("mode", "security")
        model = self.board.get("model") or "-"
        cost = self.board.get("cost", 0.0)
        return (
            f"✻ Sikun Cyber Security   target: {self.target}   profile: {self.profile_name}   "
            f"mode: {mode}   model: {model}   ${cost:.4f}   {mm:02d}:{ss:02d}"
        )

    def _tick_clock(self) -> None:
        self.query_one("#status-bar", Static).update(self._status_text())

    def update_board(self, **kwargs: Any) -> None:
        """Called by the agent backends (same asyncio loop) to push structured
        state — model, cumulative cost, discovered ports — into the sidebar.
        Findings/phase are derived separately in post_event."""
        ports = kwargs.pop("ports", None)
        if ports:
            self._merge_ports(ports)
        self.board.update(kwargs)
        self._refresh_sidebar()

    def _merge_ports(self, ports: list[dict]) -> None:
        seen = {(p.get("port"), p.get("protocol")) for p in self.board["ports"]}
        for p in ports:
            key = (p.get("port"), p.get("protocol"))
            if key not in seen:
                self.board["ports"].append(p)
                seen.add(key)

    def _board_renderable(self) -> RichText:
        lines: list[str] = ["[bold]戦況ボード[/bold]", "[dim]────────────────[/dim]"]
        lines.append(f"phase : [cyan]{self.board.get('phase', '-')}[/cyan]")
        lines.append("")

        ports = self.board.get("ports", [])
        lines.append(f"[bold]開放ポート[/bold] ({len(ports)})")
        if ports:
            for p in ports[:8]:
                lines.append(f" [green]{p.get('port')}/{p.get('protocol', '')}[/green] {p.get('service', '?')}")
            if len(ports) > 8:
                lines.append(f" [dim]...(+{len(ports) - 8})[/dim]")
        else:
            lines.append(" [dim](なし)[/dim]")
        lines.append("")

        findings = self.board.get("findings", {})
        total_f = sum(findings.values())
        lines.append(f"[bold]発見 findings[/bold] ({total_f})")
        if total_f:
            for sev in _BOARD_SEV_ORDER:
                n = findings.get(sev, 0)
                if n:
                    lines.append(f" [{_BOARD_SEV_COLOR[sev]}]{sev}[/{_BOARD_SEV_COLOR[sev]}] {n}")
        else:
            lines.append(" [dim](まだなし)[/dim]")
        return RichText.from_markup("\n".join(lines))

    def _refresh_sidebar(self) -> None:
        try:
            sidebar = self.query_one("#sidebar", Static)
        except Exception:
            return
        sidebar.update(self._board_renderable())

    async def _drain_events(self) -> None:
        transcript = self.query_one("#transcript", RichLog)
        while True:
            event = await self.events.get()
            transcript.write(event.render())

    async def post_event(self, channel: str, text: str, severity: str | None = None) -> None:
        """Call from the agent loop (same asyncio loop) to push a line into the
        transcript, and mirror it (markup stripped) to the session log file on
        disk — so cost/finding data survives even if the terminal scrollback
        doesn't."""
        event = AgentEvent(channel=channel, text=text, severity=severity)  # type: ignore[arg-type]
        await self.events.put(event)
        self._write_log_line(event)

        # Derive board state from the event stream: the current phase follows
        # the latest non-system channel, and finding counts tick up per report.
        if channel in ("recon", "exploit", "finding"):
            self.board["phase"] = channel
        if channel == "finding" and severity in self.board["findings"]:
            self.board["findings"][severity] += 1
        self._refresh_sidebar()

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
        """Slash commands mutate session_state directly and never reach the
        model as a conversation turn — /mode, /effort etc. are harness-level
        controls, not instructions to the agent."""
        parts = raw.split(maxsplit=1)
        if not parts:
            return
        cmd, arg = parts[0].lower(), (parts[1].strip() if len(parts) > 1 else "")

        if cmd == "mode":
            if arg not in ("security", "general"):
                await self.post_event("system", "[bold red]使い方: /mode security|general[/bold red]")
                return
            self.session_state["mode"] = arg
            await self.post_event(
                "system", f"[bold green]モード切替: {arg}(次のターンから反映)[/bold green]"
            )
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
            await self.post_event(
                "system", f"[bold green]モデル切替: {arg}({note}、次のターンから反映)[/bold green]"
            )
        else:
            await self.post_event("system", f"[bold red]不明なコマンド: /{cmd}[/bold red]")

    async def wait_for_instruction(self) -> str:
        """Block until the operator types something into the bottom input box."""
        return await self.user_input.get()

    async def wait_for_choice(self, options: list[tuple[str, str]]) -> str:
        """Show `options` (label, value) as a row of buttons instead of making
        the operator type free text — used for plan approval / cost-cap
        confirmation, where the answer is always one of a small fixed set.
        The first option is focused by default so Enter picks it immediately.
        Returns the `value` of whichever button was clicked or Enter'd."""
        bar = self.query_one("#choice-bar", Horizontal)
        await bar.remove_children()
        loop = asyncio.get_running_loop()
        future: asyncio.Future[str] = loop.create_future()
        self._choice_future = future
        buttons = []
        for i, (label, value) in enumerate(options):
            if i == 0:
                variant = "success"
            elif value in ("reject", "stop"):
                variant = "error"
            else:
                variant = "default"
            btn = Button(label, id=f"choice-{i}", variant=variant)
            btn.choice_value = value  # type: ignore[attr-defined]
            buttons.append(btn)
        await bar.mount_all(buttons)
        bar.display = True
        buttons[0].focus()
        try:
            return await future
        finally:
            bar.display = False
            self.query_one("#cmdline", Input).focus()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        future = self._choice_future
        if future is None or future.done():
            return
        value = getattr(event.button, "choice_value", None)
        if value is not None:
            future.set_result(value)


async def _demo_agent(app: SikunApp) -> None:
    """Fake producer so the layout can be sanity-checked without an API key."""
    await asyncio.sleep(0.5)
    await app.post_event("recon", "nmap 実行中...")
    await asyncio.sleep(0.5)
    await app.post_event("recon", "[+] port 22 open (ssh)")
    await app.post_event("recon", "[+] port 80 open (Apache 2.4.41)")
    await asyncio.sleep(0.5)
    await app.post_event("exploit", "/login に対して SQLi を試行中...")
    await asyncio.sleep(0.8)
    await app.post_event("exploit", "[+] SQLi confirmed — 認証バイパス成功")
    await app.post_event(
        "finding",
        "Apache mod_xxx 既知の脆弱性 (CVE-2023-xxxx)",
        severity="critical",
    )
    await app.post_event(
        "finding",
        "/login の SQLi — 認証バイパス可能",
        severity="high",
    )


def run_demo() -> None:
    app = SikunApp(target="192.168.56.10 (demo)", agent_factory=_demo_agent)
    app.run()


if __name__ == "__main__":
    run_demo()
