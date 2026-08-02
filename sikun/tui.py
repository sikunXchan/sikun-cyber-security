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
    "critical": "bold #ffffff on #ff0059",
    "high": "bold #ff3bd6",
    "medium": "bold #ffb000",
    "low": "#00f0ff",
    "info": "dim #6a7a99",
}


class Interrupted(Exception):
    """Raised by SikunApp.run_interruptible() when the operator presses Esc
    mid-call — mirrors Claude Code's Esc-to-stop behavior for a runaway/
    long-running turn, or one queued by an accidental Enter."""


class SikunApp(App):
    CSS = """
    /* --- neon cyberpunk skin: cyan base signal, magenta impact, near-black bg --- */
    Screen {
        layout: vertical;
        background: #05060a;
    }

    #status-bar {
        height: 1;
        padding: 0 1;
        background: #0a0e1a;
        color: #00f0ff;
        text-style: bold;
    }

    #main-row {
        height: 1fr;
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

    #sidebar {
        width: 34;
        height: 1fr;
        padding: 0 1;
        border-left: solid #ff2bd6;
        background: #05060a;
        color: #c7f5ff;
    }

    #bootline {
        dock: bottom;
        height: auto;
        padding: 0 2;
        color: #00f0ff;
        background: #05060a;
        display: none;
    }

    #cmdline {
        dock: bottom;
        border: round #00f0ff;
        background: #0a0e1a;
        color: #d7fbff;
        margin: 0 1 1 1;
    }

    #cmdline:focus {
        border: round #ff2bd6;
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
        start_mode: str = "security",
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
        self.session_state: dict[str, str] = {"mode": start_mode, "effort": "default"}
        self._choice_future: asyncio.Future[str] | None = None
        self._interrupt_event = asyncio.Event()
        self._blink = False  # drives the blinking "live" glyph in the status bar
        self._boot_done = False
        self._frame = 0          # animation frame counter (spinner / blink)
        self._activity = ""      # non-empty while the agent is working -> status spinner
        self._last_sec = -1      # throttle idle status repaints to ~1/s (IME-friendly)

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
        yield Static(id="bootline")  # typewriter scratch line, shown only during boot
        yield Input(
            placeholder="指示を入力して Enter (/mode, /effort, /plan, /model)", id="cmdline"
        )

    def on_mount(self) -> None:
        self._refresh_sidebar()
        self.set_interval(0.12, self._tick)  # spins the activity indicator; throttled at idle
        # Boot animation first, then wire up the live event drain + agent. Keeping
        # them behind the boot worker means the cinematic sequence isn't racing
        # the agent's first "指示待ち" line into the transcript.
        self.run_worker(self._startup(), exclusive=False)
        self.query_one("#cmdline", Input).focus()

    async def _startup(self) -> None:
        await self._boot_sequence()
        self.run_worker(self._drain_events(), exclusive=False)
        if self.agent_factory is not None:
            self.run_worker(self.agent_factory(self), exclusive=False)

    async def _type(self, text: str, style: str, commit: str | None = None, cps: float = 0.022) -> None:
        """Typewriter: reveal `text` char-by-char in the bottom boot line, then
        commit a (possibly richer-markup) finished line into the transcript.
        RichLog can't edit a line in place, so the live typing happens in a
        dedicated Static (#bootline) and only the finished line is logged."""
        boot = self.query_one("#bootline", Static)
        boot.display = True
        shown = ""
        for ch in text:
            shown += ch
            boot.update(f"[{style}]{shown}[/{style}]▮")
            await asyncio.sleep(cps)
        boot.update(f"[{style}]{shown}[/{style}]")
        await asyncio.sleep(0.04)
        self.query_one("#transcript", RichLog).write(
            RichText.from_markup(commit if commit is not None else f"[{style}]{text}[/{style}]")
        )
        boot.update("")
        boot.display = False

    async def _boot_sequence(self) -> None:
        """Cinematic startup: scanline rule, typed boot banner, per-module [OK]
        rolls, target lock — then the mascot. Pure eye-candy; writes directly to
        the transcript (not via the event queue)."""
        log = self.query_one("#transcript", RichLog)
        rule = "[#123]" + "▚" * 60 + "[/#123]"

        log.write(RichText.from_markup(rule))
        await asyncio.sleep(0.35)
        await self._type(
            "◈ SIKUN CYBER SECURITY // offensive core",
            "bold #00f0ff",
            commit="[bold #00f0ff]◈ SIKUN CYBER SECURITY[/bold #00f0ff] [dim #6a7a99]// offensive core[/dim #6a7a99]",
        )
        await asyncio.sleep(0.25)
        await self._type("initializing neural-offensive subsystem", "dim #7fa8bf",
                         commit="[#7fa8bf]  initializing neural-offensive subsystem ...[/#7fa8bf] [bold #39ff14][OK][/bold #39ff14]")
        await asyncio.sleep(0.3)

        # module roll — real plugin/subsystem names so it reads as genuine
        for name in ("scope-guard", "persistent-shell", "target-memory", "plugin-loader", "gemini-link"):
            await asyncio.sleep(0.22)
            log.write(RichText.from_markup(
                f"[#b26bff]  ▸[/#b26bff] mount [#00f0ff]{name}[/#00f0ff] "
                f"[dim #6a7a99]{'.' * (18 - len(name))}[/dim #6a7a99] [bold #39ff14][OK][/bold #39ff14]"
            ))
        await asyncio.sleep(0.4)

        await self._type(
            f"target locked: {self.target}",
            "bold #ff3bd6",
            commit=f"[bold #ff3bd6]⌖ target locked:[/bold #ff3bd6] [#ff9be8]{self.target}[/#ff9be8]",
            cps=0.04,
        )
        await asyncio.sleep(0.45)
        log.write(RichText.from_markup(rule))
        log.write(banner_renderable())
        log.write(RichText.from_markup(f"[dim #6a7a99]session log: {self._log_path}[/dim #6a7a99]\n"))
        self._boot_done = True

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

    _SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def _status_text(self) -> str:
        elapsed = int(time.monotonic() - self._start_time)
        mm, ss = divmod(elapsed, 60)
        mode = self.session_state.get("mode", "security")
        model = self.board.get("model") or "-"
        cost = self.board.get("cost", 0.0)
        sep = "[#2b3a5a]│[/#2b3a5a]"
        if self._activity:
            spin = self._SPINNER[self._frame % len(self._SPINNER)]
            lead = f"[bold #ff2bd6]{spin}[/bold #ff2bd6]"
            tail = f" {sep} [#ffb000]▸ {self._activity}[/#ffb000]"
        else:
            lead = "[#39ff14]◉[/#39ff14]" if self._blink else "[#124a12]◉[/#124a12]"
            tail = ""
        return (
            f"{lead} [bold #00f0ff]SIKUN//CSEC[/bold #00f0ff] {sep} "
            f"[dim #6a7a99]tgt[/dim #6a7a99] [#ff3bd6]{self.target}[/#ff3bd6] {sep} "
            f"[dim #6a7a99]mode[/dim #6a7a99] [#b26bff]{mode}[/#b26bff] {sep} "
            f"[dim #6a7a99]model[/dim #6a7a99] [#c7f5ff]{model}[/#c7f5ff] {sep} "
            f"[#39ff14]${cost:.4f}[/#39ff14] {sep} [#00f0ff]{mm:02d}:{ss:02d}[/#00f0ff]{tail}"
        )

    def _tick(self) -> None:
        """Fast animation tick. While the agent is working, repaint every frame
        so the spinner spins; at idle, only repaint when the shown second flips
        (keeps idle repaints ~1/s, which a CJK IME composition tolerates)."""
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
        """Called by the agent loop to show a live spinner + label in the status
        bar while a model call or tool is running."""
        self._activity = label
        self._refresh_status()

    def clear_activity(self) -> None:
        self._activity = ""
        self._refresh_status()

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
        rule = "[#1a2a44]" + "▚" * 16 + "[/#1a2a44]"
        lines: list[str] = ["[bold #ff2bd6]▓ SITREP[/bold #ff2bd6]", rule]
        lines.append(f"[dim #6a7a99]phase[/dim #6a7a99] [#b26bff]{self.board.get('phase', '-')}[/#b26bff]")
        lines.append("")

        ports = self.board.get("ports", [])
        lines.append(f"[bold #00f0ff]▸ PORTS[/bold #00f0ff] [dim #6a7a99]({len(ports)})[/dim #6a7a99]")
        if ports:
            for p in ports[:8]:
                lines.append(f" [#39ff14]{p.get('port')}/{p.get('protocol', '')}[/#39ff14] [#c7f5ff]{p.get('service', '?')}[/#c7f5ff]")
            if len(ports) > 8:
                lines.append(f" [dim #6a7a99]...(+{len(ports) - 8})[/dim #6a7a99]")
        else:
            lines.append(" [dim #6a7a99](none)[/dim #6a7a99]")
        lines.append("")

        findings = self.board.get("findings", {})
        total_f = sum(findings.values())
        lines.append(f"[bold #ff3bd6]✖ FINDINGS[/bold #ff3bd6] [dim #6a7a99]({total_f})[/dim #6a7a99]")
        if total_f:
            for sev in _BOARD_SEV_ORDER:
                n = findings.get(sev, 0)
                if n:
                    lines.append(f" [{_BOARD_SEV_COLOR[sev]}]{sev}[/{_BOARD_SEV_COLOR[sev]}] {n}")
        else:
            lines.append(" [dim #6a7a99](none yet)[/dim #6a7a99]")
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
            # dim timestamp gutter on every line -> operator-log feel
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            transcript.write(f"[#33425c]{ts}[/#33425c] {event.render()}")

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
            if arg not in ("security", "study", "general"):
                await self.post_event(
                    "system", "[bold red]使い方: /mode security|study|general[/bold red]"
                )
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
