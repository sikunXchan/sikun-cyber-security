"""`scs init <name>` — scaffold a new personal agent.

Generates a profile TOML and a starter plugin so a student goes from nothing
to their own working agent in one command, then edits from a running example
instead of a blank file. Deliberately refuses to clobber existing files.
"""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROFILES_DIR = PROJECT_ROOT / "profiles"
PLUGINS_DIR = PROJECT_ROOT / "plugins"

_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

_PROFILE_TEMPLATE = """# {name} のエージェント・プロファイル
# 使い方: python main.py <対象> --profile {name}
# 省略した項目はデフォルト値になります。

name = "{name}"

# モデルの明示指定(任意)。省略時は既定モデル。
# model = "gemini-3.5-flash"

# このエージェント固有の性格・方針(システムプロンプトに追記されます)。
persona = \"\"\"
あなたは Web アプリの脆弱性診断が得意な、慎重派のエージェントです。
- 破壊的な操作の前には必ず propose_plan で確認を取る
- 発見は根本原因(CWE)とセットで報告する
\"\"\"

# プラグイン(自作ツール)を読み込むディレクトリ一覧。
# ここに置いた *.py が自動でツールとして登録されます。
plugins = ["plugins"]

# 認可された対象スコープ(IP / CIDR / ホスト名)。空なら範囲チェックは無効。
# 配布時は必ず設定すること。範囲外への操作を実行前にブロックして事故を防ぐ。
# scope = ["10.20.0.0/24", "192.168.56.0/24"]
scope = []
"""

_PLUGIN_TEMPLATE = '''"""{name} 用のサンプルプラグイン。

このファイルをコピー/編集して自分のツールを作れます。ルールは3つだけ:
1. ToolPlugin を作り、モジュール直下に `PLUGIN`(単体) か `PLUGINS`(リスト) で公開する
2. run(args, ctx) は async。args はモデルが渡す引数、ctx.run(cmd) でシェル実行できる
3. 返り値は JSON にできる dict にする(そのままモデルへツール結果として返る)

`python main.py <対象> --profile {name}` で起動するとこのツールが使えます。
"""

from __future__ import annotations

from sikun.plugins import PluginContext, ToolPlugin


async def _run(args: dict, ctx: PluginContext) -> dict:
    host = str(args.get("host") or ctx.target).strip()
    # ctx.run はローカル/SSH どちらでも同じように動く(プラグイン側は意識しない)
    output = await ctx.run(f"ping -c 2 -W 2 {{host}} 2>&1 || echo '(到達不可)'")
    reachable = "0% packet loss" in output or "bytes from" in output
    return {{"host": host, "reachable": reachable, "raw": output.strip()}}


PLUGIN = ToolPlugin(
    name="{name}_ping",
    description="対象ホストにICMP pingを送り、到達可能かどうかを構造化して返すサンプルツール。",
    parameters={{
        "type": "object",
        "properties": {{
            "host": {{"type": "string", "description": "確認する対象ホスト(省略時は認可対象)"}},
        }},
        "required": [],
    }},
    run=_run,
    summary=lambda r: f"{{r.get('host')}}: {{'到達可' if r.get('reachable') else '到達不可'}}",
    # このツールが触れる対象を申告 → scope強制が確実に効く(範囲外は実行前にブロック)。
    scope_targets=lambda args: [str(args.get("host") or "")],
)
'''


def _slug_ok(name: str) -> bool:
    return bool(_NAME_RE.match(name))


def init_agent(name: str) -> tuple[list[Path], list[str]]:
    """Create a profile + starter plugin for `name`. Returns (created, skipped)
    where skipped lists files that already existed and were left untouched."""
    if not _slug_ok(name):
        raise ValueError("名前は英数字・ハイフン・アンダースコアのみ使用できます")

    PROFILES_DIR.mkdir(exist_ok=True)
    PLUGINS_DIR.mkdir(exist_ok=True)

    targets = {
        PROFILES_DIR / f"{name}.toml": _PROFILE_TEMPLATE.format(name=name),
        PLUGINS_DIR / f"{name}_ping.py": _PLUGIN_TEMPLATE.format(name=name),
    }

    created: list[Path] = []
    skipped: list[str] = []
    for path, body in targets.items():
        if path.exists():
            skipped.append(str(path.relative_to(PROJECT_ROOT)))
            continue
        path.write_text(body, encoding="utf-8")
        created.append(path)
    return created, skipped
