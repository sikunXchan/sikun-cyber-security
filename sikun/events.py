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

# Neon-cyberpunk palette: cyan is the base signal, magenta/pink is impact,
# amber is caution. Hex so the look is consistent across terminal themes.
_SEVERITY_STYLE = {
    "critical": "bold #ffffff on #ff0059",
    "high": "bold #ff3bd6",
    "medium": "bold #ffb000",
    "low": "#00f0ff",
    "info": "dim #6a7a99",
}

# Channel = a colored, glyph-tagged log tag, hacker-console style ([▸]/[⚡]/[✖]).
_CHANNEL_LABEL = {
    "recon": "[bold #00f0ff]▸ RECON[/bold #00f0ff]",
    "exploit": "[bold #b26bff]⚡ EXPLOIT[/bold #b26bff]",
    "finding": "[bold #ff3bd6]✖ FINDING[/bold #ff3bd6]",
}


def render_tool_call(label: str) -> str:
    """Format a tool invocation as a single collapsed header line, e.g.
    '⏺ Bash(nmap -Pn 192.168.1.1)' — mirrors Claude Code's tool-call style
    so the transcript reads as one linear stream of actions, not a wall of
    raw command echoes."""
    return f"[bold #00f0ff]⏺[/bold #00f0ff] [#c0f7ff]{escape(label)}[/#c0f7ff]"


def render_tool_result(output: str) -> str:
    """Format tool output indented under its call line ('  ⎿  ...'), dimmed,
    matching the collapsed-result look of Claude Code's transcript."""
    lines = (output or "(no output)").splitlines() or ["(no output)"]
    rendered = [f"  [#2b6f8f]⎿[/#2b6f8f]  [dim #7fa8bf]{escape(lines[0])}[/dim #7fa8bf]"]
    for line in lines[1:]:
        rendered.append(f"     [dim #7fa8bf]{escape(line)}[/dim #7fa8bf]")
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
        prefix = f"[bold #00f0ff]⏺[/bold #00f0ff] {_CHANNEL_LABEL[self.channel]}[dim #6a7a99] ›[/dim #6a7a99] "
        if self.severity is not None:
            style = _SEVERITY_STYLE[self.severity]
            return f"{prefix}[{style}]{escape(self.text)}[/{style}]"
        return f"{prefix}{escape(self.text)}"
