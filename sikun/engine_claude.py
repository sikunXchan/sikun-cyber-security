"""Claude Agent SDK engine for the TUI — a drop-in ``run_agent`` alternative.

Same call contract as ``sikun.agent_gemini.run_agent`` so ``main.py`` can pick
it with ``--engine claude`` and the Textual TUI (``sikun.tui.SikunApp``) drives
it unchanged: ``agent_factory(app)`` returns this coroutine, and it talks back
through ``app.post_event`` / ``app.wait_for_instruction`` /
``app.run_interruptible``.

This is migration Step 1: a SINGLE Claude agent per user turn (not the
multiagent orchestrator in ``sikun.orchestrator``). It gives the TUI equivalent
behavior to the Gemini engine on the new backend:

- the same mode system prompts (``sikun.prompts``) and profile persona,
- the same SCS plugins, now exposed as in-process MCP tools,
- the same scope enforcement + audit log (``sikun.permission`` → the SDK's
  ``can_use_tool`` gate), and
- conversation continuity across turns via the SDK session (``resume``).

Requires an ``ANTHROPIC_API_KEY`` (or ``ANTHROPIC_AUTH_TOKEN``) and the
``claude`` CLI the SDK drives; use only against authorized targets. The
built-in ``Bash`` tool is enabled, so scope enforcement is what keeps work
inside the authorized range — set ``scope`` in the profile.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
    query,
)

from sikun.agent_claude import ClaudeWorker, build_agent_options, make_ctx_factory
from sikun.decompose import WORKER_CATEGORIES, decompose
from sikun.events import render_tool_call, render_tool_result
from sikun.orchestrator import orchestrate, synthesize
from sikun.permission import new_guard
from sikun.plugins import ToolPlugin, load_plugins
from sikun.profile import Profile
from sikun.prompts import (
    GENERAL_SYSTEM_PROMPT_TEMPLATE,
    STUDY_SYSTEM_PROMPT_TEMPLATE,
    SYSTEM_PROMPT_TEMPLATE,
)
from sikun.tools import preview_for_ui
from sikun.tui import LOG_DIR

DEFAULT_MODEL = "claude-opus-5-5"

# Role line appended to the profile persona for each category worker, so a
# child stays focused on its slice of the DAG.
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


def _build_router(
    base_persona: str,
    guard,
    model: str,
    plugins: list[ToolPlugin],
    target: str,
    ssh_host: str | None,
    workdir: Path,
) -> dict[str, ClaudeWorker]:
    """One ClaudeWorker per category, sharing scope/plugins/core tools. Each
    gets the profile persona plus its category role line."""
    router: dict[str, ClaudeWorker] = {}
    for cat in WORKER_CATEGORIES:
        persona = base_persona.strip()
        role = CATEGORY_ROLES.get(cat, "")
        persona = f"{persona}\n\n# 役割\n{role}" if persona else role
        router[cat] = ClaudeWorker(
            category=cat, persona=persona, guard=guard, model=model,
            allowed_tools=["Bash"], plugins=plugins, target=target,
            ssh_host=ssh_host, workdir=workdir,
        )
    return router


def _build_system_prompt(target: str, mode: str, persona: str) -> str:
    """Same mode selection as the Gemini engine's ``_build_config`` so the TUI
    behaves identically across backends."""
    template = {
        "security": SYSTEM_PROMPT_TEMPLATE,
        "study": STUDY_SYSTEM_PROMPT_TEMPLATE,
    }.get(mode, GENERAL_SYSTEM_PROMPT_TEMPLATE)
    system_text = template.format(target=target)
    if persona and persona.strip():
        system_text += f"\n\n# このエージェント固有の指示(プロファイル)\n{persona.strip()}\n"
    return system_text


def _preview_input(tool_input: dict[str, Any]) -> str:
    """One-line preview of a tool call's arguments for the transcript."""
    if "command" in tool_input:            # Bash
        return str(tool_input["command"])
    try:
        return json.dumps(tool_input, ensure_ascii=False)[:200]
    except (TypeError, ValueError):
        return str(tool_input)[:200]


def _result_text(content: Any) -> str:
    """ToolResultBlock.content is either a string or a list of content blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(block.get("text", "") or "")
            else:
                parts.append(getattr(block, "text", "") or str(block))
        return "\n".join(p for p in parts if p)
    return str(content)


async def _consume_turn(app, instruction: str, options) -> str | None:
    """Run one agent turn, streaming its messages into the TUI transcript.
    Returns the SDK session id so the next turn can resume the conversation."""
    session_id: str | None = None
    async for message in query(prompt=instruction, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock) and block.text.strip():
                    await app.post_event("system", block.text.strip())
                elif isinstance(block, ToolUseBlock):
                    await app.post_event(
                        "system", render_tool_call(f"{block.name}({_preview_input(block.input)})"))
        elif isinstance(message, UserMessage):
            for block in getattr(message, "content", None) or []:
                if isinstance(block, ToolResultBlock):
                    text = _result_text(block.content)
                    if text:
                        await app.post_event("system", render_tool_result(preview_for_ui(text)))
        elif isinstance(message, ResultMessage):
            session_id = message.session_id
            if message.total_cost_usd:
                await app.post_event(
                    "system",
                    f"[dim]コスト: ${message.total_cost_usd:.4f} / turns={message.num_turns}[/dim]")
            if message.stop_reason == "refusal":
                await app.post_event(
                    "system",
                    "[bold yellow]安全分類器により応答が停止しました(refusal)。"
                    "認可された演習であることを明示し、作業を具体的な手順に分けて再依頼してください。[/bold yellow]")
            break
    return session_id


async def run_agent(
    app,
    target: str,
    workdir: Path | None = None,
    initial_instruction: str | None = None,
    ssh_host: str | None = None,
    profile: Profile | None = None,
    startup_status: bool = False,
) -> None:
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        await app.post_event(
            "system",
            "[bold red]ANTHROPIC_API_KEY が未設定です。.env に設定してから "
            "--engine claude で起動し直してください。[/bold red]")
        return

    profile = profile or Profile()
    workdir = workdir or Path.home()

    load_result = load_plugins(profile.plugin_dirs)
    plugins = load_result.plugins
    for err in load_result.errors:
        await app.post_event("system", f"[yellow]プラグイン警告: {err}[/yellow]")
    if plugins:
        await app.post_event(
            "system", f"[dim]プラグイン読み込み: {', '.join(sorted(p.name for p in plugins))}[/dim]")

    # Same scope guard + audit log as the Gemini engine (session target auto-allowed).
    guard = new_guard(list(profile.scope), LOG_DIR / "audit.log", target)
    if guard.enabled:
        await app.post_event(
            "system", f"[dim]スコープ強制: 有効(認可範囲 {', '.join(guard.scope.raw)})[/dim]")
    else:
        await app.post_event(
            "system",
            "[bold yellow]⚠ スコープ未設定 — 範囲チェック無効。配布時は profile に scope を設定してください[/bold yellow]")

    model = profile.model or DEFAULT_MODEL
    persona = profile.persona
    ctx_factory = make_ctx_factory(target, ssh_host, workdir)
    scope_list = list(profile.scope) or ([target] if target else [])
    router = _build_router(persona, guard, model, plugins, target, ssh_host, workdir)
    await app.post_event(
        "system",
        f"[dim]Claude エンジン起動(model={model}, target={target}, ssh={ssh_host or 'ローカル'})[/dim]")

    session_id: str | None = None
    first = True
    while True:
        if first and initial_instruction:
            instruction = initial_instruction
        else:
            await app.post_event("system", "[dim]指示待ち — 下の入力欄から指示を入力してください[/dim]")
            instruction = await app.wait_for_instruction()
        first = False

        mode = app.session_state.get("mode", "security")
        try:
            if mode == "security":
                # Multi-agent: decompose → orchestrate category workers.
                await app.run_interruptible(
                    _run_orchestrated(app, instruction, router, scope_list, target))
            else:
                # study / general: a single direct agent (no decomposition).
                options = build_agent_options(
                    system_prompt=_build_system_prompt(target, mode, persona),
                    guard=guard, allowed_tools=["Bash"], plugins=plugins,
                    ctx_factory=ctx_factory, model=model, workdir=workdir,
                    resume=session_id,
                )
                new_sid = await app.run_interruptible(_consume_turn(app, instruction, options))
                if new_sid:
                    session_id = new_sid
        except asyncio.CancelledError:
            await app.post_event("system", "[bold yellow]⏹ 中断しました(Esc)[/bold yellow]")
        except Exception as exc:  # noqa: BLE001 — surface any SDK/API error in the TUI
            await app.post_event("system", f"[bold red]APIエラー: {exc}[/bold red]")


async def _run_orchestrated(app, instruction, router, scope_list, target) -> None:
    """Security-mode turn: decompose the instruction into a DAG, run the
    category workers layer by layer, and post the merged report to the TUI."""
    tasks = decompose(instruction, scope=scope_list, target=target,
                      categories=list(router.keys()))
    plan = " → ".join(
        "[" + "+".join(t.id for t in layer) + "]"
        for layer in _preview_layers(tasks))
    await app.post_event("system", f"[dim]分解: {len(tasks)} タスク / 実行計画 {plan}[/dim]")

    results = await orchestrate(tasks, router, on_event=app.post_event)
    report = synthesize(results)

    s = report["summary"]
    await app.post_event(
        "finding" if report["findings"] else "system",
        f"統合: タスク{s['tasks']} / findings {s['findings']} / blocked {s['blocked']} / errors {s['errors']}")
    for f in report["findings"]:
        detail = f.get("detail", "")
        await app.post_event("finding",
                             f"[{f.get('source', '?')}/{f.get('category', '?')}] "
                             f"{f.get('type', '?')}: {detail}")
    for hint in report["next_hints"]:
        await app.post_event("system", f"[dim]→ {hint}[/dim]")


def _preview_layers(tasks):
    """Compute the layers for the plan preview; tolerate a bad DAG by showing
    tasks flat rather than raising in the UI path."""
    from sikun.orchestrator import build_layers
    try:
        return build_layers(tasks)
    except ValueError:
        return [tasks]
