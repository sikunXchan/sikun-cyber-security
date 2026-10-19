"""Claude Agent SDK worker — the real engine behind an orchestrator category.

This worker drives the
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

from sikun.claude_core_tools import CORE_SCOPE
from sikun.claude_core_tools import core_tools as build_core_tools
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


def make_ctx_factory(target: str, ssh_host: str | None, workdir: Path) -> Callable[[], PluginContext]:
    """Build a PluginContext factory whose shell runs commands locally or over
    SSH against the authorized target — the same wiring the Gemini engine's
    PersistentShell provides, in minimal form (no cd/env persistence across
    calls; reuse sikun.tools.PersistentShell when that is needed)."""
    import asyncio

    async def run_shell(command: str) -> str:
        argv = ["ssh", ssh_host, command] if ssh_host else ["bash", "-lc", command]
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            cwd=str(workdir))
        out, _ = await proc.communicate()
        return out.decode("utf-8", "replace")

    def make() -> PluginContext:
        return PluginContext(target=target, ssh_host=ssh_host, workdir=workdir, run=run_shell)

    return make


def build_agent_options(
    *,
    system_prompt: str,
    guard: ScopeGuard,
    allowed_tools: list[str],
    plugins: list[ToolPlugin],
    ctx_factory: Callable[[], PluginContext],
    model: str = "claude-opus-4-8",
    max_turns: int = 24,
    max_budget_usd: float | None = 2.0,
    workdir: Path | None = None,
    sandbox: Any = None,
    resume: str | None = None,
    effort: str = "high",
    core_tools: list[SdkMcpTool] | None = None,
    core_scope: dict[str, Callable[[dict[str, Any]], list[str]]] | None = None,
) -> ClaudeAgentOptions:
    """Assemble ClaudeAgentOptions from SCS pieces: a persona/mode system
    prompt, the built-in allowed tools, SCS plugins and core recon tools
    exposed as in-process MCP tools, and the scope-enforcing permission gate.
    Shared by the per-category ``ClaudeWorker`` and the TUI engine
    (``sikun.engine_claude``) so the wiring lives in exactly one place.

    ``core_tools`` are SDK tools (from ``sikun.claude_core_tools``) and
    ``core_scope`` maps each of their names to a reliable target extractor —
    merged with plugins' ``scope_targets`` so the permission gate hard-blocks
    out-of-scope calls for both.

    SCOPE ENFORCEMENT — do NOT list a scope-gated tool in ``allowed_tools``.
    The Agent SDK auto-approves anything in ``allowed_tools`` and then SKIPS
    ``can_use_tool`` for it (it emits ``CanUseToolShadowedWarning`` and the
    gate never runs — confirmed in ``claude_agent_sdk/types.py``). So the
    plugins/core MCP tools and Bash are deliberately left OUT of
    ``allowed_tools``: they stay available (via ``mcp_servers`` / built-ins)
    and every call is routed through ``can_use_tool``, which allows in-scope
    and denies out-of-scope. ``allowed_tools`` is reserved for tools the caller
    wants auto-approved WITHOUT a scope check — keep it empty unless you mean
    exactly that."""
    sdk_tools = [plugin_to_sdk_tool(p, ctx_factory) for p in plugins]
    # name -> reliable target extractor, for the permission gate.
    scope_map: dict[str, Callable[[dict[str, Any]], list[str]]] = {
        p.name: p.scope_targets for p in plugins if p.scope_targets}
    if core_tools:
        sdk_tools += core_tools
        if core_scope:
            scope_map.update(core_scope)

    mcp_servers: dict[str, Any] = {}
    if sdk_tools:
        mcp_servers["scs"] = create_sdk_mcp_server("scs", tools=sdk_tools)
    # NOTE: the MCP tool names are intentionally NOT appended to `allowed`,
    # so can_use_tool governs (and scope-gates) every one of them.
    allowed = list(allowed_tools)

    def extra_declared(tool_name: str, tool_input: dict[str, Any]) -> list[str] | None:
        base = tool_name.split("__")[-1]  # strip mcp__scs__ prefix
        fn = scope_map.get(base)
        return fn(tool_input) if fn else None

    return ClaudeAgentOptions(
        system_prompt=system_prompt,
        allowed_tools=allowed,
        mcp_servers=mcp_servers,
        can_use_tool=make_scope_permission(guard, extra_declared=extra_declared),
        model=model,
        effort=effort,
        max_turns=max_turns,
        max_budget_usd=max_budget_usd,
        cwd=str(workdir) if workdir else None,
        resume=resume,
        sandbox=sandbox,
    )


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
    model: str = "claude-opus-4-8"
    allowed_tools: list[str] = field(default_factory=list)
    plugins: list[ToolPlugin] = field(default_factory=list)
    target: str = ""
    ssh_host: str | None = None
    workdir: Path = field(default_factory=Path.cwd)
    max_turns: int = 24
    max_budget_usd: float | None = 2.0
    sandbox: Any = None            # pass a SandboxSettings to restrict network/fs
    effort: str = "high"           # low|medium|high|xhigh|max — agentic tasks like high+
    enable_core_tools: bool = True  # expose nmap_scan/http_probe/dir_enum as MCP tools
    enable_browser: bool = True     # expose browser_fetch (headless Chromium) for DOM/JS targets

    def _ctx_factory(self) -> Callable[[], PluginContext]:
        return make_ctx_factory(self.target, self.ssh_host, self.workdir)

    def _build_options(self) -> ClaudeAgentOptions:
        core: list[SdkMcpTool] = []
        cscope: dict[str, Callable[[dict[str, Any]], list[str]]] = {}
        if self.enable_core_tools:
            core += build_core_tools(self.ssh_host)
            cscope.update(CORE_SCOPE)
        if self.enable_browser:
            from sikun.claude_browser_tool import BROWSER_SCOPE, browser_tools
            core += browser_tools()
            cscope.update(BROWSER_SCOPE)
        return build_agent_options(
            system_prompt=f"{self.persona}\n\n{_RESULT_INSTRUCTION}",
            guard=self.guard,
            allowed_tools=self.allowed_tools,
            plugins=self.plugins,
            ctx_factory=self._ctx_factory(),
            model=self.model,
            effort=self.effort,
            max_turns=self.max_turns,
            max_budget_usd=self.max_budget_usd,
            workdir=self.workdir,
            sandbox=self.sandbox,
            core_tools=core or None,
            core_scope=cscope or None,
        )

    async def run(self, task: SubTask, upstream: dict[str, WorkerResult]) -> WorkerResult:
        # No API key required: the Agent SDK's query() authenticates via the
        # environment key OR the `claude` CLI's own login. We don't preflight —
        # if the CLI isn't authenticated, query() raises and orchestrate()
        # turns it into an error WorkerResult. Use only against authorized
        # CTF/lab targets (scope enforcement gates every tool call).
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


# Role line appended to the profile persona for each category worker, so a
# child stays focused on its slice of the DAG. Kept here (rich-free) so both
# the TUI engine and the headless benchmark can build the same router.
CATEGORY_ROLES: dict[str, str] = {
    "recon": "ネットワーク偵察担当。nmap_scan / http_probe で開放ポート・サービス・Web入口を特定し、根拠付きで報告する。攻撃はしない。",
    "web": "Web脆弱性調査担当。http_probe / dir_enum と Bash で管理画面・API・認証周りを認可範囲内で調べる。",
    "crypto": "暗号解析担当。鍵・証明書・暗号設定の弱点を調べる。",
    "reversing": "リバースエンジニアリング担当。バイナリ/ファームウェアを静的解析する。",
    "forensics": "フォレンジック担当。ログ・パケット・ダンプ・成果物を解析する。",
    "pwn": "バイナリエクスプロイト観点の担当。メモリ破壊・権限昇格の観点で認可範囲内に調べる。",
    "mobile": "モバイルアプリ解析担当。APK/アプリの静的解析を行う。",
    "misc": "汎用担当。他カテゴリに属さない課題を扱う。",
}


def build_category_router(
    base_persona: str,
    guard: ScopeGuard,
    model: str,
    plugins: list[ToolPlugin],
    target: str,
    ssh_host: str | None,
    workdir: Path,
) -> dict[str, "ClaudeWorker"]:
    """One ClaudeWorker per category (see CATEGORY_ROLES), sharing
    scope/plugins/core tools. Used by the TUI engine and the benchmark."""
    from sikun.decompose import WORKER_CATEGORIES

    router: dict[str, ClaudeWorker] = {}
    for cat in WORKER_CATEGORIES:
        role = CATEGORY_ROLES.get(cat, "")
        persona = f"{base_persona.strip()}\n\n# 役割\n{role}" if base_persona.strip() else role
        router[cat] = ClaudeWorker(
            category=cat, persona=persona, guard=guard, model=model,
            # allowed_tools empty on purpose: Bash and the MCP tools are left
            # to can_use_tool so scope is actually enforced (see
            # build_agent_options). Bash stays available as a built-in.
            allowed_tools=[], plugins=plugins, target=target,
            ssh_host=ssh_host, workdir=workdir,
        )
    return router
