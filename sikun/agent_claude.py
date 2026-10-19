"""Claude Agent SDK worker — the real engine behind an orchestrator category.

This is the ``agent_gemini.py`` replacement for one worker: it drives the
Claude Agent SDK (``claude_agent_sdk``) instead of hand-rolling the tool loop.
The SDK supplies the agent loop, context management, built-in tools, MCP, and
the permission gate; this module only wires SCS's existing pieces into it:

- SCS ``profiles`` persona           → ``ClaudeAgentOptions.system_prompt``
- SCS ``plugins`` (``ToolPlugin``)   → in-process MCP tools (``tool`` +
                                        ``create_sdk_mcp_server``)
- SCS ``ScopeGuard`` authorization   → ``ClaudeAgentOptions.can_use_tool``
                                        (see ``sikun.permission``)
- per-category workers               → ``ClaudeAgentOptions.agents``
                                        (``AgentDefinition``), optional

All names/signatures were verified against the installed claude_agent_sdk
0.2.159 (``query``, ``ClaudeAgentOptions``, ``tool``,
``create_sdk_mcp_server``, ``AgentDefinition``, ``PermissionResult*``).

IMPORTANT — authorization & cost: calling ``ClaudeWorker.run`` makes real
Claude API calls and, through the SDK's tools, can execute commands against
the configured target. Use it ONLY against an authorized CTF/lab target, with
``scope`` set so the permission gate hard-blocks anything else. It requires an
``ANTHROPIC_API_KEY`` (per Anthropic's SDK terms, API-key auth — not claude.ai
login). The mock experiment in ``experiments/`` does NOT run this worker.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable

from claude_agent_sdk import (
    AgentDefinition,
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    SdkMcpTool,
    TextBlock,
    create_sdk_mcp_server,
    query,
    tool,
)

from sikun.orchestrator import SubTask, Worker, WorkerResult
from sikun.permission import make_scope_permission
from sikun.plugins import PluginContext, ToolPlugin
from sikun.scope import ScopeGuard

# The worker is asked to end its turn with this JSON object so the orchestrator
# gets a structured WorkerResult instead of prose. Kept small on purpose.
_RESULT_INSTRUCTION = """\
作業の最後に、次の形の JSON を1つだけ ```json コードブロックで出力して終了すること:
{"status":"done|blocked|error",
 "findings":[{"type":"...","detail":"...","evidence":"..."}],
 "next_hints":["次の層の担当へのヒント"],
 "scope_touched":["実際に触れた対象"]}
findings は根本原因(CWE等)とセットで。推測は evidence を空にする。"""

_JSON_BLOCK = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


def plugin_to_sdk_tool(plugin: ToolPlugin, ctx_factory: Callable[[], PluginContext]) -> SdkMcpTool:
    """Wrap one SCS ``ToolPlugin`` as an in-process SDK MCP tool.

    ``plugin.parameters`` is already a JSON-Schema object, which ``tool()``
    accepts directly. The handler builds a fresh ``PluginContext`` (shell
    bound to the authorized target) and returns the plugin's result in MCP
    content form. ``plugin.scope_targets`` is surfaced to the permission gate
    separately (see ``build_options``), so enforcement stays reliable.
    """

    @tool(plugin.name, plugin.description, plugin.parameters)
    async def _handler(args: dict[str, Any]) -> dict[str, Any]:
        result = await plugin.run(args, ctx_factory())
        text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
        return {"content": [{"type": "text", "text": text}]}

    return _handler


def _extract_result(text: str, category: str) -> WorkerResult:
    """Parse the trailing JSON block the worker was asked to emit; fall back to
    a prose-only result when the model didn't comply."""
    matches = _JSON_BLOCK.findall(text)
    if matches:
        try:
            data = json.loads(matches[-1])
            return WorkerResult(
                category=category,
                status=str(data.get("status", "done")),
                findings=list(data.get("findings", [])),
                next_hints=list(data.get("next_hints", [])),
                scope_touched=list(data.get("scope_touched", [])),
                raw=text,
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return WorkerResult(category=category, status="done",
                        findings=[{"type": "note", "detail": text[:2000]}], raw=text)


@dataclass
class ClaudeWorker:
    """A category worker backed by the Claude Agent SDK.

    ``allowed_tools`` are the built-in tool names this worker may use (e.g.
    ``["Bash"]``); ``plugins`` become MCP tools it can also call. ``scope`` is
    the authorized target set for THIS worker (a subset of the run's scope),
    enforced through ``can_use_tool``.
    """

    category: str
    persona: str
    guard: ScopeGuard
    model: str = "claude-opus-5-5"
    allowed_tools: list[str] = field(default_factory=list)
    plugins: list[ToolPlugin] = field(default_factory=list)
    target: str = ""
    ssh_host: str | None = None
    workdir: Path = field(default_factory=Path.cwd)
    max_turns: int = 24
    max_budget_usd: float | None = 2.0
    sandbox: Any = None            # pass a SandboxSettings to restrict network/fs

    def _ctx_factory(self) -> Callable[[], PluginContext]:
        async def run_shell(command: str) -> str:
            # Local-or-SSH shell for plugins, mirroring the Gemini engine's
            # PersistentShell wiring. Kept minimal here; real deployments
            # should reuse sikun.tools.PersistentShell for cd/env persistence.
            import asyncio
            argv = (["ssh", self.ssh_host, command] if self.ssh_host
                    else ["bash", "-lc", command])
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                cwd=str(self.workdir))
            out, _ = await proc.communicate()
            return out.decode("utf-8", "replace")

        def make() -> PluginContext:
            return PluginContext(target=self.target, ssh_host=self.ssh_host,
                                 workdir=self.workdir, run=run_shell)
        return make

    def _build_options(self) -> ClaudeAgentOptions:
        ctx_factory = self._ctx_factory()
        sdk_tools = [plugin_to_sdk_tool(p, ctx_factory) for p in self.plugins]
        mcp_servers: dict[str, Any] = {}
        allowed = list(self.allowed_tools)
        if sdk_tools:
            mcp_servers["scs"] = create_sdk_mcp_server("scs", tools=sdk_tools)
            # SDK MCP tool call names are namespaced "mcp__<server>__<tool>".
            allowed += [f"mcp__scs__{p.name}" for p in self.plugins]

        # Plugins that declare scope_targets get reliable enforcement.
        plugin_scope = {p.name: p.scope_targets for p in self.plugins if p.scope_targets}

        def extra_declared(tool_name: str, tool_input: dict[str, Any]) -> list[str] | None:
            base = tool_name.split("__")[-1]  # strip mcp__scs__ prefix
            fn = plugin_scope.get(base)
            return fn(tool_input) if fn else None

        return ClaudeAgentOptions(
            system_prompt=f"{self.persona}\n\n{_RESULT_INSTRUCTION}",
            allowed_tools=allowed,
            mcp_servers=mcp_servers,
            can_use_tool=make_scope_permission(self.guard, extra_declared=extra_declared),
            model=self.model,
            max_turns=self.max_turns,
            max_budget_usd=self.max_budget_usd,
            cwd=str(self.workdir),
            sandbox=self.sandbox,
        )

    async def run(self, task: SubTask, upstream: dict[str, WorkerResult]) -> WorkerResult:
        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            raise RuntimeError(
                "ClaudeWorker は ANTHROPIC_API_KEY（またはトークン）が必要です。"
                "認可されたCTF/ラボ標的に対してのみ実行してください。")

        hints = [h for r in upstream.values() for h in r.next_hints]
        prompt = (
            f"# 担当カテゴリ: {task.category}\n"
            f"# ゴール: {task.goal}\n"
            f"# 認可対象(これ以外は触れない): {', '.join(task.scope) or '(scope未設定)'}\n"
        )
        if hints:
            prompt += "# 前層からの引き継ぎ:\n" + "\n".join(f"- {h}" for h in hints) + "\n"

        collected: list[str] = []
        async for message in query(prompt=prompt, options=self._build_options()):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        collected.append(block.text)
            elif isinstance(message, ResultMessage):
                break

        return _extract_result("\n".join(collected), task.category)


def build_workers(category_personas: dict[str, str], guard: ScopeGuard, **kw: Any) -> dict[str, ClaudeWorker]:
    """Build one ClaudeWorker per category from a {category: persona} map.
    Convenience for the orchestrator's router."""
    return {cat: ClaudeWorker(category=cat, persona=persona, guard=guard, **kw)
            for cat, persona in category_personas.items()}


# For orchestrator subagent-style delegation inside a single ClaudeWorker, a
# category can instead be expressed as an AgentDefinition passed via
# ClaudeAgentOptions.agents. Exposed here so a future single-process variant
# can register workers as SDK subagents rather than separate query() runs.
def category_agent(description: str, prompt: str, *, tools: list[str] | None = None,
                   model: str | None = None) -> AgentDefinition:
    return AgentDefinition(description=description, prompt=prompt,
                           tools=tools, model=model)
