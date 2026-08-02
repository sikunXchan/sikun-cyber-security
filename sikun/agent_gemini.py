"""The agent loop — a Gemini tool-use orchestrator.

Exposes ``run_agent`` and drives the event-channel contract (report tool ->
app.post_event). bash calls run against one long-lived
sikun.tools.PersistentShell for the whole run (cd/env vars/background PIDs
persist across calls), instead of a fresh subprocess per call. System-prompt
templates come from sikun.prompts.

Verified empirically against the live API (not just docs) on 2026-07-25:
- Async surface: client.aio.models.generate_content(...)
- Tool schema: types.FunctionDeclaration + types.Tool(function_declarations=[...])
- Round-trip: append response.candidates[0].content to history, then a
  Content(role="user", parts=[Part.from_function_response(name=..., response={...})])
- Part.from_function_response has no call-id param in this SDK version — it
  pairs by function name only, so two parallel calls to the *same* tool in
  one turn can't be told apart. Not an issue for our one-tool-call-per-part
  usage; would need a workaround if that changes.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from google import genai
from google.genai import types

from sikun.prompts import (
    GENERAL_SYSTEM_PROMPT_TEMPLATE,
    STUDY_SYSTEM_PROMPT_TEMPLATE,
    SYSTEM_PROMPT_TEMPLATE,
)
from sikun.events import render_tool_call, render_tool_result
from sikun.memory import TargetMemory
from sikun.plugins import PluginContext, ToolPlugin, load_plugins
from sikun.profile import Profile
from sikun.scope import Scope, ScopeGuard, extract_hosts, guard_besteffort, guard_reliable
from sikun.tools import PersistentShell, preview_for_ui, run_dir_enum, run_http_probe, run_nmap_scan
from sikun.tui import LOG_DIR, Interrupted

FULL_MODEL = os.environ.get("SIKUN_GEMINI_MODEL", "gemini-3.5-flash")
# lite (released 2026-07-21 — ~5x cheaper input / ~3.6x cheaper output than
# full Flash) is the default tier: most turns are routine (port checks,
# straightforward recon narration) and don't need full Flash's judgment.
# /model full opts back into full Flash for turns that need careful
# multi-step judgment (plan proposals, exploit chaining, finding verification).
LITE_MODEL = os.environ.get("SIKUN_GEMINI_LITE_MODEL", "gemini-3.5-flash-lite")
MAX_OUTPUT_TOKENS = 16000
MAX_COST = float(os.environ.get("SIKUN_MAX_COST", "0"))  # 0 = no cap, just a heads-up warning

_TIER_MODEL = {"lite": LITE_MODEL, "full": FULL_MODEL}
# lite is for routine, low-judgment turns (port checks, straightforward
# recon narration) the operator already flagged as simple by picking /model
# lite; full is what the operator reaches for once things get hard (exploit
# chaining, finding verification), so it gets the deep end of the thinking
# budget rather than one flat level for every turn regardless of difficulty.
_TIER_THINKING_LEVEL = {"lite": types.ThinkingLevel.LOW, "full": types.ThinkingLevel.HIGH}

# How much of the tail of `contents` stays verbatim; anything older gets its
# bulky tool-output fields (bash stdout, raw nmap/gobuster/curl dumps)
# collapsed down to just the structured findings, once a run runs long
# enough that old raw logs would otherwise sit in every subsequent request
# competing for the model's attention against whatever it's doing now.
CONTEXT_KEEP_RECENT = int(os.environ.get("SIKUN_CONTEXT_KEEP_RECENT", "12"))
CONTEXT_TRUNCATE_CHARS = 300

# Standard paid-tier per-million-token USD rates. Thinking tokens are billed
# as output tokens (confirmed on the pricing page, not just inferred).
_PRICING = {
    "gemini-3.5-flash": {"input": 1.50, "output": 9.00},
    "gemini-3.5-flash-lite": {"input": 0.30, "output": 2.50},
}

_STOP_FINISH_REASONS = {"STOP", "MAX_TOKENS"}

# On a provider safety block, one automatic retry re-asserts the authorized
# context and asks for a precise, professional restatement before the operator
# is ever bothered. This is a re-assertion of the (true) authorization, not
# keyword-dodging: we do NOT tell the model to euphemize technique names to
# slip past the classifier — if it still blocks, we stop and defer.
AUTH_CONTEXT_NUDGE = (
    "直前のリクエストがプロバイダの安全判定でブロックされました。"
    "この作業は明示的に認可された対象に対するセキュリティ診断です。"
    "認可の前提(認可元・対象範囲)を改めて明示し、観測している事実と操作の目的を"
    "正確な技術用語で記述したうえで、同じ操作を続けてください。"
)

# Self-correction: after this many consecutive tool-active turns that produced
# no new progress (no finding / port / path / live endpoint / substantive
# output), inject one high-effort "step back and re-plan" turn instead of
# letting the agent flail or quietly give up. The cooldown stops it re-firing
# every turn once triggered. The discipline in the nudge — prioritize by
# impact, do one bounded adjacency pass, then record a deferred candidate
# rather than fabricate — is distilled from openai/codex-security's
# validation/attack-path guidance.
REPLAN_AFTER_UNPRODUCTIVE = 4
REPLAN_COOLDOWN_TURNS = 8
REPLAN_NUDGE = (
    "【戦略の見直し】ここまで進展の乏しい試行が続いた。一度手を止めて棚卸しすること:\n"
    "1. これまで判明した事実(開いているポート/サービス/バージョン/応答)を簡潔に要約する\n"
    "2. 直近で試したアプローチと、なぜ効かなかったか(返ってきた具体的な応答)を明示する\n"
    "3. 未検証のより有望なベクトルを、影響度の高い順(RCE > 危険なデシリアライズ > SSTI > "
    "SQLi > SSRF > パストラバーサル > 認可バイパス)に洗い出す\n"
    "4. 今詰まっている点が『ある1つの事実の欠如』だけなら、その1点を狙って限定的に1回だけ調べる。"
    "それでも埋まらなければ、その候補は recon チャンネルに『保留(要検証: 何が足りていないか)』として"
    "正直に記録し、次に有望なベクトルへ移る\n"
    "闇雲な再試行や、未達成なのに finding を出すこと(嘘の成功)は禁止。"
)

# Coverage gate: the observed failure mode was the OPPOSITE of flailing — the
# agent did real work, then declared the engagement complete while high-value
# attack surfaces it had literally already enumerated (an unsolved-challenge
# list, a package.json.bak sitting in a listing) stayed untried. REPLAN can't
# catch this: it fires on 4 consecutive *unproductive* tool-turns, but here the
# agent voluntarily stops calling tools at all. So when the agent tries to
# conclude after having done attack work this segment, force ONE breadth audit
# first. This is the codex-security "coverage ledger" idea applied at the
# completion boundary — breadth (don't leave surfaces untried), not depth
# (don't stubbornly hammer one vector). It explicitly permits 保留 and fires at
# most once per work segment, so it adds thoroughness without runaway.
COVERAGE_NUDGE = (
    "【網羅チェック】結論・最終報告に入る前に、攻撃面の棚卸しを必ず行うこと:\n"
    "1. これまでの偵察で判明した攻撃面(エンドポイント/パラメータ/フォーム/公開ファイル/"
    "確認したチャレンジ一覧など)を列挙する\n"
    "2. そのうち実際に試したものと、まだ手を付けていないものを分ける\n"
    "3. 未着手の中に影響度の高いベクタ(RCE > 危険なデシリアライズ > SSTI > SQLi > "
    "認可バイパス/IDOR > SSRF > 機密ファイル露出 > XSS > パストラバーサル)が残っているなら、"
    "結論に入らずそれを実際に試すこと\n"
    "4. 各未着手ベクタは「試して成立/不成立」まで進めるか、十分試したうえで"
    "「保留(要検証: 何が足りないか)」として recon に正直に記録するまでは、診断完了を名乗らないこと\n"
    "注意: 1つのベクタに闇雲に固執する必要はない(数回で見切って保留に落としてよい)。"
    "求めているのは深追いではなく取りこぼしのない網羅。未達成なのに finding を出すこと(嘘の成功)は禁止。"
)


def _should_audit_coverage(mode: str, did_work: bool, already_audited: bool) -> bool:
    """Whether to force one coverage audit before letting the agent conclude.

    Only in security mode, only after real attack work happened this segment,
    and only once per segment — so an agent that quits early gets exactly one
    "did you leave anything untried?" push, never an audit on a pure Q&A turn
    and never a loop."""
    return mode == "security" and did_work and not already_audited

BASH_DECLARATION = types.FunctionDeclaration(
    name="bash",
    description="Execute a shell command and return its output.",
    parameters={
        "type": "object",
        "properties": {"command": {"type": "string", "description": "shell command to run"}},
        "required": ["command"],
    },
)

REPORT_DECLARATION = types.FunctionDeclaration(
    name="report",
    description=(
        "UIの該当パネルに進捗・発見事項を表示する。実際の操作はbashツールで行い、"
        "このツールは状況説明や成果物の報告専用。攻撃ステップを踏むたびに、"
        "recon(偵察結果)/exploit(攻撃の試行・結果)/finding(確定した脆弱性・成果)"
        "のいずれかで呼び出すこと。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "channel": {
                "type": "string",
                "enum": ["recon", "exploit", "finding", "system"],
                "description": "表示先パネル",
            },
            "text": {"type": "string", "description": "表示するメッセージ"},
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
                "description": "finding の場合の重要度(任意)",
            },
            "evidence": {
                "type": "string",
                "description": (
                    "finding の場合は必須。脆弱性を裏付ける再現コマンドとその出力の要点。"
                    "これを示せない=未確認なら、finding ではなく recon で『要確認』として報告する"
                ),
            },
        },
        "required": ["channel", "text"],
    },
)

NMAP_SCAN_DECLARATION = types.FunctionDeclaration(
    name="nmap_scan",
    description=(
        "対象ホストのポートスキャン・サービス検出を行い、構造化された結果(開いているポート・"
        "サービス名・バージョン)を返す。bashでnmapコマンドを自分で組み立てて生の出力をパースする"
        "より信頼性が高いので、ポートスキャンをしたい場合はこちらを優先して使うこと。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "スキャン対象のIP/ホスト名"},
            "ports": {
                "type": "string",
                "description": "ポート範囲(例: '1-1000', '22,80,443')。省略時は上位1000番",
            },
            "service_detection": {
                "type": "boolean",
                "description": "サービスバージョン検出(-sV)を行うか。デフォルトtrue",
            },
        },
        "required": ["target"],
    },
)

HTTP_PROBE_DECLARATION = types.FunctionDeclaration(
    name="http_probe",
    description=(
        "対象URL/ホストにHTTPリクエストを送り、ステータスコード・レスポンスヘッダ・"
        "ページタイトル・技術スタックの推測を構造化して返す。bashでcurlを叩いて生の"
        "ヘッダやHTMLを自分で読むより信頼性が高いので、Webサービスの初期調査(何が"
        "動いているかの把握)にはこちらを優先して使うこと。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "対象URL(例: 'http://192.168.1.1:8080/')。スキームを省略した場合はhttp://を補う",
            },
        },
        "required": ["url"],
    },
)

DIR_ENUM_DECLARATION = types.FunctionDeclaration(
    name="dir_enum",
    description=(
        "対象URL配下のディレクトリ・ファイルを探索し、見つかったパスとステータスコードを"
        "構造化して返す(gobusterが対象にあれば使用、無ければ組み込みの簡易ワードリストで"
        "curlスイープにフォールバック)。隠しパネル・バックアップファイル・.git/.env等の"
        "露出確認に使う。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "探索対象のベースURL"},
            "wordlist": {
                "type": "string",
                "description": "カンマ区切りの探索パス一覧(省略時は組み込みの一般的なパス群を使用)",
            },
        },
        "required": ["url"],
    },
)

PLAN_DECLARATION = types.FunctionDeclaration(
    name="propose_plan",
    description=(
        "実行系のアクション(攻撃・攻撃的な検証など、対象の状態を変えたり攻撃を成立させたり"
        "する操作)を取る前に、具体的な計画を提示してユーザーの承認を待つ。単なる説明・"
        "脆弱性の報告・診断(読み取り専用で実害のない調査)だけならこのツールは不要で、"
        "直接 bash/nmap_scan/report で調査・報告に進んでよい。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "対象"},
            "steps": {"type": "string", "description": "実施予定の手順(箇条書き推奨)"},
            "risk": {"type": "string", "description": "想定されるリスク・影響範囲"},
        },
        "required": ["steps"],
    },
)

TOOLS = types.Tool(
    function_declarations=[
        BASH_DECLARATION,
        REPORT_DECLARATION,
        NMAP_SCAN_DECLARATION,
        HTTP_PROBE_DECLARATION,
        DIR_ENUM_DECLARATION,
        PLAN_DECLARATION,
    ]
)


def _build_config(
    target: str,
    mode: str,
    tool_obj: types.Tool | None = None,
    persona: str = "",
    memory_summary: str = "",
) -> types.GenerateContentConfig:
    """Build a fresh GenerateContentConfig for the given mode ('security',
    'study', or 'general'). Called at startup, whenever /mode changes, and
    whenever the per-target memory summary drifts (a new port/finding landed) —
    cheap enough to just rebuild rather than diff.

    `tool_obj` is the (possibly plugin-augmented) tool set and `persona` is
    the active profile's extra system-prompt text — both default to the
    built-ins so a profile-less call still works."""
    template = {
        "security": SYSTEM_PROMPT_TEMPLATE,
        "study": STUDY_SYSTEM_PROMPT_TEMPLATE,
    }.get(mode, GENERAL_SYSTEM_PROMPT_TEMPLATE)
    system_text = template.format(target=target)
    if persona and persona.strip():
        system_text += f"\n\n# このエージェント固有の指示(プロファイル)\n{persona.strip()}\n"
    if memory_summary:
        system_text += f"\n\n{memory_summary}\n"
    return types.GenerateContentConfig(
        tools=[tool_obj if tool_obj is not None else TOOLS],
        system_instruction=system_text,
        max_output_tokens=MAX_OUTPUT_TOKENS,
    )


def _resolve_tier(app) -> str:
    """/model lite|full picks the model tier per-turn via session_state, same
    polling pattern as /mode — takes effect on the next turn, no restart.
    Default is lite; /model full opts back into the pricier tier for turns
    that need deeper judgment."""
    return "full" if app.session_state.get("model") == "full" else "lite"


def _fmt_plugin_args(args: dict) -> str:
    """Compact one-line arg preview for a plugin tool call in the transcript."""
    return ", ".join(f"{k}={str(v)[:40]}" for k, v in args.items())


def _notify_board(app, **kwargs) -> None:
    """Push structured state (model/cost/ports) to the TUI's side board if the
    app exposes one. Guarded so a headless/test app without a board still runs."""
    updater = getattr(app, "update_board", None)
    if callable(updater):
        updater(**kwargs)


def _activity(app, label: str) -> None:
    """Drive the TUI's status-bar activity spinner (set with a label, or clear
    with ''). Guarded so a headless/test app without one still runs."""
    fn = getattr(app, "set_activity" if label else "clear_activity", None)
    if callable(fn):
        fn(label) if label else fn()


def _compact_old_context(contents: list[types.Content], keep_recent: int = CONTEXT_KEEP_RECENT) -> None:
    """Once a run runs long, old raw tool output is dead weight: it costs
    tokens every subsequent turn and competes for the model's attention
    against whatever phase it's actually in now. Recent turns stay verbatim;
    anything older than `keep_recent` Content entries keeps only the state
    later phases still need (structured findings, narration) and drops the
    raw bash/nmap/curl dumps that produced it. Mutates in place — idempotent,
    since already-collapsed entries are already short and the length check
    is a no-op on a second pass, so it's safe to call every turn."""
    boundary = len(contents) - keep_recent
    if boundary <= 0:
        return
    for content in contents[:boundary]:
        for part in content.parts or []:
            fr = part.function_response
            if fr is None or not isinstance(fr.response, dict):
                continue
            resp = fr.response
            for field in ("output", "raw", "raw_headers"):
                value = resp.get(field)
                if isinstance(value, str) and len(value) > CONTEXT_TRUNCATE_CHARS:
                    resp[field] = value[:CONTEXT_TRUNCATE_CHARS] + "\n...(古いターンのため要約済み、生ログは破棄)"


async def _call_model(
    app, client: genai.Client, contents: list, config: types.GenerateContentConfig, model: str
):
    """generate_content with a short retry-with-backoff for transient server
    errors (503 UNAVAILABLE under high demand — observed recurring in
    practice during testing, not hypothetical). Esc-interrupt and errors that
    still fail after retries propagate to the caller unchanged."""
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            return await app.run_interruptible(
                client.aio.models.generate_content(model=model, contents=contents, config=config)
            )
        except Interrupted:
            raise
        except Exception as exc:
            last_exc = exc
            if attempt < 2:
                await app.post_event(
                    "system", f"[dim]APIエラー({exc}) — {2 ** attempt}秒後に再試行[/dim]"
                )
                await asyncio.sleep(2**attempt)
    assert last_exc is not None
    raise last_exc


def _estimate_cost(usage, model: str) -> float:
    rates = _PRICING.get(model)
    if not rates or usage is None:
        return 0.0
    cost = (usage.prompt_token_count or 0) / 1e6 * rates["input"]
    cost += (usage.candidates_token_count or 0) / 1e6 * rates["output"]
    cost += (usage.thoughts_token_count or 0) / 1e6 * rates["output"]
    return cost


def _turn_was_productive(call_parts: list, response_parts: list) -> bool:
    """Did this turn move the operation forward? Used to detect a stall (a run
    of tool-active turns with no new progress) so the loop can inject a
    re-plan. Progress == a finding reported, new open ports, a discovered path,
    a live/interesting HTTP endpoint, or substantive bash output. Deliberately
    conservative: a false 'productive' just delays a re-plan, a false 'stalled'
    only costs one extra reasoning turn (gated by a cooldown)."""
    for part in call_parts:
        fc = getattr(part, "function_call", None)
        if fc and fc.name == "report" and (fc.args or {}).get("channel") == "finding":
            return True
    for part in response_parts:
        fr = getattr(part, "function_response", None)
        if fr is None:
            continue
        resp = fr.response if isinstance(fr.response, dict) else {}
        if fr.name == "nmap_scan" and resp.get("open_ports"):
            return True
        if fr.name == "dir_enum" and resp.get("found"):
            return True
        if fr.name == "http_probe":
            status = str(resp.get("status", ""))
            if status[:1] in ("2", "3") or status in ("401", "403"):
                return True
        if fr.name == "bash":
            out = resp.get("output", "")
            if "error" not in resp and isinstance(out, str):
                stripped = out.strip()
                low = stripped.lower()
                # Long output usually means the command actually returned data
                # — but a failing exploit/curl is also long and noisy, and that
                # flailing is exactly the wall we want to catch. Treat output
                # carrying a failure signature as *not* progress.
                failed = any(
                    m in low
                    for m in _BASH_FAILURE_MARKERS
                )
                if len(stripped) >= 40 and not failed:
                    return True
    return False


# Substrings that mark a shell result as a failed attempt rather than progress,
# so a run of flailing commands trips the stall detector instead of reading as
# forward motion just because the error text is long.
_BASH_FAILURE_MARKERS = (
    "refused",
    "timed out",
    "timeout",
    "not found",
    "no such",
    "could not",
    "couldn't",
    "denied",
    "unreachable",
    "no route",
    "failed",
    "error",
)


def _plugin_declarations(plugins: list[ToolPlugin]) -> list[types.FunctionDeclaration]:
    return [
        types.FunctionDeclaration(name=p.name, description=p.description, parameters=p.parameters)
        for p in plugins
    ]


async def run_agent(
    app,
    target: str,
    workdir: Path | None = None,
    initial_instruction: str | None = None,
    ssh_host: str | None = None,
    profile: Profile | None = None,
) -> None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        await app.post_event(
            "system",
            "[bold red]GEMINI_API_KEY が未設定です。.env に設定してから起動し直してください。[/bold red]",
        )
        return

    profile = profile or Profile()
    client = genai.Client()
    workdir = workdir or Path.home()

    # Profile-driven config: persona, model override, and auto-loaded tool
    # plugins — all optional, all falling back to the built-ins when the
    # profile leaves them unset.
    persona = profile.persona
    full_model = profile.model or FULL_MODEL
    lite_model = LITE_MODEL

    load_result = load_plugins(profile.plugin_dirs)
    plugin_map = {p.name: p for p in load_result.plugins}
    tool_obj = types.Tool(
        function_declarations=[
            BASH_DECLARATION,
            REPORT_DECLARATION,
            NMAP_SCAN_DECLARATION,
            HTTP_PROBE_DECLARATION,
            DIR_ENUM_DECLARATION,
            PLAN_DECLARATION,
            *_plugin_declarations(load_result.plugins),
        ]
    )
    for err in load_result.errors:
        await app.post_event("system", f"[yellow]プラグイン警告: {err}[/yellow]")
    if plugin_map:
        await app.post_event(
            "system", f"[dim]プラグイン読み込み: {', '.join(sorted(plugin_map))}[/dim]"
        )

    # Scope guard: authorized-target enforcement + audit log. The CLI target is
    # auto-allowed when scope is set; empty scope means enforcement is off.
    scope_entries = list(profile.scope)
    if scope_entries:
        scope_entries.append(target)
    guard = ScopeGuard(Scope(scope_entries), LOG_DIR / "audit.log", target)
    if guard.enabled:
        await app.post_event(
            "system", f"[dim]スコープ強制: 有効(認可範囲 {', '.join(guard.scope.raw)})[/dim]"
        )
    else:
        await app.post_event(
            "system",
            "[bold yellow]⚠ スコープ未設定 — 範囲チェック無効。配布時は profile に scope を設定してください[/bold yellow]",
        )

    shell = PersistentShell(ssh_host=ssh_host, cwd=workdir)
    await shell.start()
    await app.post_event("system", f"[dim]永続シェル起動(ssh_host={ssh_host or 'ローカル'})[/dim]")

    # Per-target memory: recall prior ports/findings across sessions, and keep
    # this session's findings salient regardless of context compaction.
    memory = TargetMemory.load(target)
    if memory.has_history():
        await app.post_event(
            "system",
            f"[dim]前回までの記憶をロード(ポート{len(memory.ports)} / finding{len(memory.findings)}、最終 {memory.last_seen})[/dim]",
        )

    current_mode = app.session_state.get("mode", "security")
    config = _build_config(
        target, current_mode, tool_obj, persona, memory.summary_for_prompt()
    )

    contents: list[types.Content] = []
    if initial_instruction:
        contents.append(types.Content(role="user", parts=[types.Part(text=initial_instruction)]))

    await app.post_event(
        "system",
        f"[dim]エージェント開始 — profile={profile.name}, target={target}, "
        f"model={full_model if _resolve_tier(app) == 'full' else lite_model}, mode={current_mode}[/dim]",
    )

    try:
        await _run_loop(
            app,
            client,
            config,
            contents,
            workdir,
            ssh_host,
            shell,
            target,
            current_mode,
            0.0,
            plugin_map=plugin_map,
            tool_obj=tool_obj,
            persona=persona,
            full_model=full_model,
            lite_model=lite_model,
            guard=guard,
            memory=memory,
        )
    finally:
        await shell.stop()


async def _run_loop(
    app,
    client: genai.Client,
    config: types.GenerateContentConfig,
    contents: list[types.Content],
    workdir: Path,
    ssh_host: str | None,
    shell: PersistentShell,
    target: str,
    current_mode: str,
    total_cost: float,
    *,
    plugin_map: dict[str, ToolPlugin] | None = None,
    tool_obj: types.Tool | None = None,
    persona: str = "",
    full_model: str = FULL_MODEL,
    lite_model: str = LITE_MODEL,
    guard: ScopeGuard | None = None,
    memory: TargetMemory | None = None,
) -> None:
    plugin_map = plugin_map or {}
    if guard is None:
        guard = ScopeGuard(Scope([]), LOG_DIR / "audit.log", target)
    if memory is None:
        memory = TargetMemory.load(target)
    # Plugins execute shell commands through the same persistent session the
    # rest of the agent uses, so cd/env/background PIDs they set stick too.
    plugin_ctx = PluginContext(
        target=target, ssh_host=ssh_host, workdir=workdir, run=shell.run
    )
    _notify_board(app, model=full_model if _resolve_tier(app) == "full" else lite_model)
    # Re-confirm every MAX_COST increment (0 = never) rather than once at a
    # fixed ceiling, so a long-running task keeps checking in as it burns
    # through further chunks of budget instead of only stopping once.
    cost_checkpoint = MAX_COST if MAX_COST > 0 else None
    # Track the memory summary the current config was built with, so a newly
    # discovered port/finding refreshes the system prompt on the next turn.
    memory_sig = memory.summary_for_prompt()
    # Self-correction bookkeeping: count consecutive unproductive tool-turns,
    # cool down after a re-plan fires, and force one full/high-thinking turn
    # when it does.
    unproductive_streak = 0
    replan_cooldown = 0
    force_full_next = False
    # Coverage-gate bookkeeping (see COVERAGE_NUDGE): did any attack work run
    # since the last operator instruction, and have we already forced the
    # one-per-segment breadth audit for this segment.
    did_work_since_instruction = False
    coverage_audit_done = False

    while True:
        # No instruction yet (bare `target` with no --task) -> do nothing and
        # wait. Never synthesize a "start recon" turn on our own; the operator
        # types the first instruction, always.
        if not contents:
            _activity(app, "")
            await app.post_event("system", "[dim]指示待ち — 下の入力欄から指示を入力してください[/dim]")
            instruction = await app.wait_for_instruction()
            contents.append(types.Content(role="user", parts=[types.Part(text=instruction)]))
            continue

        # Long runs accumulate raw tool output fast; collapse anything
        # outside the recent window before it either bloats the request or
        # buries the current phase's findings under old recon dumps.
        _compact_old_context(contents)

        # /mode can change between turns (operator typed it while we were
        # mid-loop), and the per-target memory summary changes as new
        # ports/findings land — rebuild the config once for whichever (or
        # both) changed, so the system prompt keeps carrying the latest recall
        # instead of freezing at whatever it was at startup.
        requested_mode = app.session_state.get("mode", "security")
        new_memory_sig = memory.summary_for_prompt()
        if requested_mode != current_mode or new_memory_sig != memory_sig:
            if requested_mode != current_mode:
                current_mode = requested_mode
                await app.post_event("system", f"[dim]モード適用: {current_mode}[/dim]")
            memory_sig = new_memory_sig
            config = _build_config(
                target, current_mode, tool_obj, persona, new_memory_sig
            )

        if replan_cooldown > 0:
            replan_cooldown -= 1

        tier = _resolve_tier(app)
        # A just-injected re-plan turn overrides the operator's /model tier for
        # that single turn: strategy rethinking is exactly what full + high
        # thinking is for, regardless of what the routine work was set to.
        if force_full_next:
            tier = "full"
            force_full_next = False
        turn_model = {"lite": lite_model, "full": full_model}[tier]
        _notify_board(app, model=turn_model)
        # Thinking budget follows the tier the operator already picked via
        # /model: lite is for turns they've judged routine, full is for
        # turns hard enough to warrant the pricier model — so full gets the
        # deep end of the thinking budget instead of one flat level applied
        # to every turn regardless of difficulty.
        turn_config = config.model_copy(
            update={
                "thinking_config": types.ThinkingConfig(
                    thinking_level=_TIER_THINKING_LEVEL[tier], include_thoughts=True
                )
            }
        )
        # On a provider safety block: one automatic retry that re-asserts the
        # authorized context (AUTH_CONTEXT_NUDGE), then — if it still blocks —
        # defer to the operator rather than trying to talk past the guardrail.
        response = None
        blocked = False
        interrupted = False
        for attempt in range(2):
            try:
                _activity(app, f"querying {turn_model}")
                response = await _call_model(app, client, contents, turn_config, turn_model)
            except Interrupted:
                await app.post_event("system", "[bold yellow]⏹ 中断しました(Esc)[/bold yellow]")
                instruction = await app.wait_for_instruction()
                contents.append(types.Content(role="user", parts=[types.Part(text=instruction)]))
                interrupted = True
                break
            except Exception as exc:
                await app.post_event("system", f"[bold red]APIエラー: {exc}[/bold red]")
                return

            if not response.candidates:
                blocked = True
            else:
                finish_reason = str(response.candidates[0].finish_reason or "").rsplit(".", 1)[-1]
                blocked = bool(finish_reason) and finish_reason not in _STOP_FINISH_REASONS

            if not blocked:
                break
            if attempt == 0:
                await app.post_event(
                    "system",
                    "[dim]ブロックされたため、認可の文脈を明示して1度だけ自動再試行します[/dim]",
                )
                contents.append(types.Content(role="user", parts=[types.Part(text=AUTH_CONTEXT_NUDGE)]))

        if interrupted:
            continue

        if blocked:
            reason = "候補なし" if not response.candidates else str(response.candidates[0].finish_reason)
            await app.post_event(
                "system",
                f"[bold yellow]認可の文脈を明示しても再度ブロックされました(reason={reason})。\n"
                "対象が認可範囲内か・指示内容が適切かを確認し、必要なら指示を見直してください。[/bold yellow]",
            )
            instruction = await app.wait_for_instruction()
            contents.append(types.Content(role="user", parts=[types.Part(text=instruction)]))
            continue

        candidate = response.candidates[0]

        turn_cost = _estimate_cost(response.usage_metadata, turn_model)
        total_cost += turn_cost
        _notify_board(app, cost=total_cost)
        um = response.usage_metadata
        await app.post_event(
            "system",
            f"[dim]turn cost: ${turn_cost:.4f} / total: ${total_cost:.4f} model={turn_model} "
            f"(in={um.prompt_token_count if um else '?'} "
            f"out={um.candidates_token_count if um else '?'} "
            f"thinking={um.thoughts_token_count if um else '?'})[/dim]",
        )

        if cost_checkpoint is not None and total_cost >= cost_checkpoint:
            await app.post_event(
                "system",
                f"[bold yellow]コスト上限 ${MAX_COST:.2f} ごとの確認 — 現在合計 ${total_cost:.4f}[/bold yellow]",
            )
            choice = await app.wait_for_choice(
                [("▶ 続行 (Enter)", "continue"), ("⏹ 停止して指示待ち", "stop")]
            )
            cost_checkpoint += MAX_COST
            if choice == "stop":
                instruction = await app.wait_for_instruction()
                contents.append(types.Content(role="user", parts=[types.Part(text=instruction)]))
                continue

        contents.append(candidate.content)

        function_response_parts: list[types.Part] = []
        plan_pending = False
        for part in candidate.content.parts:
            if part.text:
                await app.post_event("system", part.text)
            elif part.function_call:
                fc = part.function_call
                _activity(app, f"exec {fc.name}")
                if fc.name == "bash":
                    command = (fc.args or {}).get("command", "")
                    if not command:
                        function_response_parts.append(
                            types.Part.from_function_response(
                                name=fc.name, response={"error": "command が空です"}
                            )
                        )
                        continue
                    if not await guard_besteffort(app, guard, "bash", extract_hosts(command)):
                        function_response_parts.append(
                            types.Part.from_function_response(
                                name=fc.name,
                                response={"error": "認可スコープ外の対象のため operator が実行を中止しました"},
                            )
                        )
                        continue
                    await app.post_event("system", render_tool_call(f"Bash({command})"))
                    output = await shell.run(command)
                    await app.post_event("system", render_tool_result(preview_for_ui(output)))
                    function_response_parts.append(
                        types.Part.from_function_response(name=fc.name, response={"output": output})
                    )
                elif fc.name == "report":
                    args = fc.args or {}
                    channel = args.get("channel", "system")
                    text = args.get("text", "")
                    severity = args.get("severity")
                    evidence = args.get("evidence")
                    await app.post_event(channel, text, severity)
                    if channel == "finding":
                        memory.add_finding(severity, text, evidence or "")
                        memory.save()
                        if evidence:
                            await app.post_event("system", f"[dim]  ⎿ 根拠: {evidence}[/dim]")
                        else:
                            await app.post_event(
                                "system",
                                "[yellow]  ⎿ 根拠(evidence)なしの finding — 未確認なら recon で報告を[/yellow]",
                            )
                    function_response_parts.append(
                        types.Part.from_function_response(name=fc.name, response={"result": "ok"})
                    )
                elif fc.name == "nmap_scan":
                    args = fc.args or {}
                    nmap_target = args.get("target", "")
                    if not nmap_target:
                        function_response_parts.append(
                            types.Part.from_function_response(
                                name=fc.name, response={"error": "target が空です"}
                            )
                        )
                        continue
                    scope_err = guard_reliable(guard, "nmap_scan", [nmap_target])
                    if scope_err:
                        await app.post_event("system", f"[bold red]{scope_err}[/bold red]")
                        function_response_parts.append(
                            types.Part.from_function_response(name=fc.name, response={"error": scope_err})
                        )
                        continue
                    await app.post_event(
                        "system",
                        render_tool_call(
                            f"nmap_scan(target={nmap_target}, ports={args.get('ports') or '(top1000)'})"
                        ),
                    )
                    scan_result = await run_nmap_scan(
                        target=nmap_target,
                        ports=args.get("ports", "") or "",
                        service_detection=args.get("service_detection", True),
                        ssh_host=ssh_host,
                    )
                    if scan_result["open_ports"]:
                        ports_summary = ", ".join(
                            f"{p['port']}/{p['protocol']} {p['service']}" for p in scan_result["open_ports"]
                        )
                    else:
                        ports_summary = "(開いているポートなし)"
                    _notify_board(app, ports=scan_result["open_ports"])
                    if scan_result["open_ports"]:
                        memory.add_ports(scan_result["open_ports"])
                        memory.save()
                    await app.post_event("system", render_tool_result(ports_summary))
                    function_response_parts.append(
                        types.Part.from_function_response(name=fc.name, response=scan_result)
                    )
                elif fc.name == "http_probe":
                    args = fc.args or {}
                    probe_url = args.get("url", "")
                    if not probe_url:
                        function_response_parts.append(
                            types.Part.from_function_response(
                                name=fc.name, response={"error": "url が空です"}
                            )
                        )
                        continue
                    scope_err = guard_reliable(guard, "http_probe", [probe_url])
                    if scope_err:
                        await app.post_event("system", f"[bold red]{scope_err}[/bold red]")
                        function_response_parts.append(
                            types.Part.from_function_response(name=fc.name, response={"error": scope_err})
                        )
                        continue
                    await app.post_event("system", render_tool_call(f"http_probe(url={probe_url})"))
                    probe_result = await run_http_probe(probe_url, ssh_host=ssh_host)
                    summary = (
                        f"status={probe_result['status']} "
                        f"server={probe_result.get('server') or '(不明)'} "
                        f"title={probe_result['title'] or '(なし)'} "
                        f"tech={', '.join(probe_result['tech_hints']) or '(不明)'}"
                    )
                    await app.post_event("system", render_tool_result(summary))
                    function_response_parts.append(
                        types.Part.from_function_response(name=fc.name, response=probe_result)
                    )
                elif fc.name == "dir_enum":
                    args = fc.args or {}
                    enum_url = args.get("url", "")
                    if not enum_url:
                        function_response_parts.append(
                            types.Part.from_function_response(
                                name=fc.name, response={"error": "url が空です"}
                            )
                        )
                        continue
                    scope_err = guard_reliable(guard, "dir_enum", [enum_url])
                    if scope_err:
                        await app.post_event("system", f"[bold red]{scope_err}[/bold red]")
                        function_response_parts.append(
                            types.Part.from_function_response(name=fc.name, response={"error": scope_err})
                        )
                        continue
                    await app.post_event("system", render_tool_call(f"dir_enum(url={enum_url})"))
                    enum_result = await run_dir_enum(
                        enum_url, wordlist=args.get("wordlist", "") or "", ssh_host=ssh_host
                    )
                    if enum_result["found"]:
                        found_summary = ", ".join(
                            f"{f['path']}({f['status']})" for f in enum_result["found"]
                        )
                    else:
                        found_summary = "(発見なし)"
                    await app.post_event(
                        "system", render_tool_result(f"[{enum_result['source']}] {found_summary}")
                    )
                    function_response_parts.append(
                        types.Part.from_function_response(name=fc.name, response=enum_result)
                    )
                elif fc.name == "propose_plan":
                    args = fc.args or {}
                    plan_text = (
                        f"対象: {args.get('target', target)}\n"
                        f"手順:\n{args.get('steps', '(未記載)')}\n"
                        f"想定リスク: {args.get('risk', '(記載なし)')}"
                    )
                    await app.post_event(
                        "system",
                        f"[bold magenta][計画提案 — 承認待ち]\n{plan_text}[/bold magenta]",
                    )
                    function_response_parts.append(
                        types.Part.from_function_response(
                            name=fc.name, response={"result": "plan submitted, awaiting operator approval"}
                        )
                    )
                    plan_pending = True
                elif fc.name in plugin_map:
                    plugin = plugin_map[fc.name]
                    args = dict(fc.args or {})
                    if plugin.scope_targets is not None:
                        scope_err = guard_reliable(guard, fc.name, list(plugin.scope_targets(args) or []))
                        if scope_err:
                            await app.post_event("system", f"[bold red]{scope_err}[/bold red]")
                            function_response_parts.append(
                                types.Part.from_function_response(name=fc.name, response={"error": scope_err})
                            )
                            continue
                    elif not await guard_besteffort(
                        app, guard, fc.name, extract_hosts(" ".join(str(v) for v in args.values()))
                    ):
                        function_response_parts.append(
                            types.Part.from_function_response(
                                name=fc.name,
                                response={"error": "認可スコープ外の対象のため operator が実行を中止しました"},
                            )
                        )
                        continue
                    await app.post_event(
                        "system", render_tool_call(f"{fc.name}({_fmt_plugin_args(args)})")
                    )
                    try:
                        result = await plugin.run(args, plugin_ctx)
                    except Exception as exc:
                        result = {"error": f"plugin例外: {exc}"}
                    await app.post_event("system", render_tool_result(plugin.summarize(result)))
                    # from_function_response needs a mapping; wrap bare returns.
                    resp = result if isinstance(result, dict) else {"result": result}
                    function_response_parts.append(
                        types.Part.from_function_response(name=fc.name, response=resp)
                    )

        if plan_pending:
            # Proposing a plan and getting operator input is forward motion,
            # not a stall — reset the stall counter.
            unproductive_streak = 0
            # Hard gate: even though propose_plan is a tool call like any
            # other, don't let the loop auto-continue on it — force a real
            # wait for operator input.
            choice = await app.wait_for_choice(
                [
                    ("✅ 承認 (Enter)", "approve"),
                    ("✏️ 修正して伝える", "revise"),
                    ("❌ 却下", "reject"),
                ]
            )
            if choice == "approve":
                instruction = "承認します。計画通り進めてください。"
            elif choice == "reject":
                instruction = "却下します。この計画は実行しないでください。"
            else:
                instruction = await app.wait_for_instruction()
            # Send the function_response as its own turn, then the operator's
            # instruction as a separate one — NOT combined into a single
            # Content. Combining a function_response part with a plain text
            # part in one turn was suspected (and empirically confirmed
            # across multiple live runs — Redis test, camera test) to
            # correlate with the model returning a near-empty response
            # (out=None) on the very next turn, stalling right after plan
            # approval. Two consecutive user-role Contents are valid on the
            # Gemini API (no strict alternation requirement); splitting them
            # avoids whatever edge case the combined shape was hitting.
            contents.append(types.Content(role="user", parts=function_response_parts))
            contents.append(types.Content(role="user", parts=[types.Part(text=instruction)]))
            continue

        if function_response_parts:
            did_work_since_instruction = True
            if _turn_was_productive(candidate.content.parts, function_response_parts):
                unproductive_streak = 0
            else:
                unproductive_streak += 1
            contents.append(types.Content(role="user", parts=function_response_parts))
            # Stalled (a run of tool-turns with no new progress) and not in the
            # cooldown window → inject one high-effort re-plan turn instead of
            # letting the agent keep flailing or quietly give up.
            if unproductive_streak >= REPLAN_AFTER_UNPRODUCTIVE and replan_cooldown == 0:
                await app.post_event(
                    "system",
                    "[bold cyan]⟳ 進展が乏しいため、戦略を見直す高思考ターンを挟みます[/bold cyan]",
                )
                contents.append(types.Content(role="user", parts=[types.Part(text=REPLAN_NUDGE)]))
                force_full_next = True
                unproductive_streak = 0
                replan_cooldown = REPLAN_COOLDOWN_TURNS
            continue

        # No tool calls this turn — the agent is concluding/waiting, not stuck.
        unproductive_streak = 0
        _activity(app, "")
        # Coverage gate: if it did attack work this segment and is now trying to
        # wrap up, force one breadth audit before accepting the conclusion — so
        # an early "diagnosis complete" doesn't leave enumerated high-value
        # surfaces untried. Fires at most once per segment (see COVERAGE_NUDGE).
        if _should_audit_coverage(current_mode, did_work_since_instruction, coverage_audit_done):
            await app.post_event(
                "system",
                "[bold cyan]⟳ 結論前に攻撃面の網羅を確認する高思考ターンを挟みます[/bold cyan]",
            )
            contents.append(types.Content(role="user", parts=[types.Part(text=COVERAGE_NUDGE)]))
            force_full_next = True
            coverage_audit_done = True
            continue
        await app.post_event("system", "[dim]エージェント待機中 — 下の入力欄から指示を送れます[/dim]")
        instruction = await app.wait_for_instruction()
        if app.session_state.pop("force_plan", None):
            instruction = f"(操作を始める前に必ず propose_plan で計画を提示してください) {instruction}"
        # New operator instruction starts a fresh work segment — reset the gate.
        did_work_since_instruction = False
        coverage_audit_done = False
        contents.append(types.Content(role="user", parts=[types.Part(text=instruction)]))
