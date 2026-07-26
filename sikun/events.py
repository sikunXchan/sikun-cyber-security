"""Shared event model between the agent loop and the TUI.

The agent (task-4) and any demo/mock producer both push AgentEvent objects
into an asyncio.Queue that the TUI drains and routes to the right panel.
Keeping this in its own module means tui.py and agent.py never import each
other directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from rich.markup import escape

Channel = Literal["recon", "exploit", "finding", "system"]
Severity = Literal["critical", "high", "medium", "low", "info"]

_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "yellow",
    "info": "dim",
}

_CHANNEL_LABEL = {
    "recon": "[cyan]Recon[/cyan]",
    "exploit": "[yellow]Exploit[/yellow]",
    "finding": "[bold red]Finding[/bold red]",
}


def render_tool_call(label: str) -> str:
    """Format a tool invocation as a single collapsed header line, e.g.
    '⏺ Bash(nmap -Pn 192.168.1.1)' — mirrors Claude Code's tool-call style
    so the transcript reads as one linear stream of actions, not a wall of
    raw command echoes."""
    return f"[bold]⏺[/bold] {escape(label)}"


def render_tool_result(output: str) -> str:
    """Format tool output indented under its call line ('  ⎿  ...'), dimmed,
    matching the collapsed-result look of Claude Code's transcript."""
    lines = (output or "(no output)").splitlines() or ["(no output)"]
    rendered = [f"  [dim]⎿[/dim]  [dim]{escape(lines[0])}[/dim]"]
    for line in lines[1:]:
        rendered.append(f"     [dim]{escape(line)}[/dim]")
    return "\n".join(rendered)


@dataclass(frozen=True, slots=True)
class AgentEvent:
    channel: Channel
    text: str
    severity: Severity | None = None

    def render(self) -> str:
        """Rich-markup-formatted line for the transcript. `system`-channel
        text is expected to already be fully formatted markup (tool calls/
        results, dim notices, plan proposals) and is passed through as-is;
        recon/exploit/finding get a '⏺ <Channel>: ' tag so they read as
        distinct events in the single linear stream."""
        if self.channel == "system":
            if self.severity is None:
                return self.text
            style = _SEVERITY_STYLE[self.severity]
            return f"[{style}]{self.text}[/{style}]"
        prefix = f"[bold]⏺[/bold] {_CHANNEL_LABEL[self.channel]}: "
        if self.severity is not None:
            style = _SEVERITY_STYLE[self.severity]
            return f"{prefix}[{style}]{escape(self.text)}[/{style}]"
        return f"{prefix}{escape(self.text)}"
