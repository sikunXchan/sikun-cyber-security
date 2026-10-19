"""Claude Agent SDK engine for the TUI.

One behavior: each user instruction is decomposed into a DAG and run by the
orchestrator across category workers; the merged report is posted back to the
TUI. No modes, no cost display. Talks to the TUI through ``app.post_event`` /
``app.wait_for_instruction`` / ``app.run_interruptible``.

Auth: no API key required — the Agent SDK drives the ``claude`` CLI, which uses
the environment key OR the CLI's own login. Use only against authorized targets
(scope enforcement gates every tool call).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from sikun.agent_claude import build_category_router
from sikun.decompose import decompose
from sikun.orchestrator import build_layers, orchestrate, synthesize
from sikun.permission import new_guard
from sikun.plugins import load_plugins
from sikun.profile import Profile
from sikun.prompts import build_system_prompt
from sikun.tui import LOG_DIR

DEFAULT_MODEL = "claude-opus-4-8"


async def run_agent(
    app,
    target: str,
    workdir: Path | None = None,
    initial_instruction: str | None = None,
    ssh_host: str | None = None,
    profile: Profile | None = None,
) -> None:
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        await app.post_event(
            "system",
            "[dim]APIキー未設定 — `claude` CLI のログイン認証で動作します"
            "(CLI未ログインなら SDK がエラーを返します)。[/dim]")

    profile = profile or Profile()
    workdir = workdir or Path.home()

    load_result = load_plugins(profile.plugin_dirs)
    plugins = load_result.plugins
    for err in load_result.errors:
        await app.post_event("system", f"[yellow]プラグイン警告: {err}[/yellow]")
    if plugins:
        await app.post_event(
            "system", f"[dim]プラグイン: {', '.join(sorted(p.name for p in plugins))}[/dim]")

    guard = new_guard(list(profile.scope), LOG_DIR / "audit.log", target)
    if guard.enabled:
        await app.post_event(
            "system", f"[dim]スコープ: {', '.join(guard.scope.raw)}[/dim]")
    else:
        await app.post_event(
            "system",
            "[bold yellow]⚠ スコープ未設定 — 範囲チェック無効。profile に scope を設定してください[/bold yellow]")

    model = profile.model or DEFAULT_MODEL
    scope_list = list(profile.scope) or ([target] if target else [])
    base_persona = build_system_prompt(target, profile.persona)
    router = build_category_router(base_persona, guard, model, plugins, target, ssh_host, workdir)

    first = True
    while True:
        if first and initial_instruction:
            instruction = initial_instruction
        else:
            instruction = await app.wait_for_instruction()
        first = False
        try:
            await app.run_interruptible(_run_orchestrated(app, instruction, router, scope_list, target))
        except asyncio.CancelledError:
            await app.post_event("system", "[bold yellow]⏹ 中断しました(Esc)[/bold yellow]")
        except Exception as exc:  # noqa: BLE001 — surface any SDK/API error in the TUI
            await app.post_event("system", f"[bold red]エラー: {exc}[/bold red]")


async def _run_orchestrated(app, instruction, router, scope_list, target) -> None:
    """Decompose the instruction into a DAG, run the category workers layer by
    layer, and post the merged report to the TUI."""
    tasks = decompose(instruction, scope=scope_list, target=target, categories=list(router))
    plan = " → ".join(
        "[" + "+".join(t.id for t in layer) + "]" for layer in _preview_layers(tasks))
    await app.post_event("system", f"[dim]分解: {len(tasks)} タスク / 計画 {plan}[/dim]")

    results = await orchestrate(tasks, router, on_event=app.post_event)
    report = synthesize(results)

    s = report["summary"]
    await app.post_event(
        "finding" if report["findings"] else "system",
        f"統合: タスク{s['tasks']} / findings {s['findings']} / blocked {s['blocked']} / errors {s['errors']}")
    for f in report["findings"]:
        await app.post_event(
            "finding",
            f"[{f.get('source', '?')}/{f.get('category', '?')}] {f.get('type', '?')}: {f.get('detail', '')}")
    for hint in report["next_hints"]:
        await app.post_event("system", f"[dim]→ {hint}[/dim]")


def _preview_layers(tasks):
    """Layers for the plan preview; tolerate a bad DAG by showing tasks flat."""
    try:
        return build_layers(tasks)
    except ValueError:
        return [tasks]
