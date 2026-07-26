"""detection_rule — 自分の攻撃が防御側にどう見えるかを Sigma 検知ルールにする(パープル)。

攻撃補助としての狙い: 実行した手法から「それを捕捉する検知ルール」を作ることで、
どのログ・どのフィールドで見つかるかが分かり、**強い防御側の裏をかく**材料になる。

モデルが与える意味的情報(何のログの/どのフィールドが/どんな値にマッチするか)から、
常に妥当な Sigma YAML を組み立てて手元の detections/ に保存する。ルール本文の生成は
このツールが決定的に行うので、壊れた YAML は出ない。

引数はプロバイダ差(ネストしたスキーマ非対応の場合がある)を避けるためフラットな文字列中心。
演習ホストには接触しない(手元にファイルを書くだけ)ので scope_targets は空。
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from sikun.plugins import PluginContext, ToolPlugin

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = PROJECT_ROOT / "detections"

_LEVELS = {"informational", "low", "medium", "high", "critical"}


def _scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'  # always safe


def _emit_lines(data, indent: int = 0) -> list[str]:
    pad = "  " * indent
    out: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            out.append(f"{pad}{key}:")
            out.extend(_emit_lines(value, indent + 1))
        elif isinstance(value, list):
            out.append(f"{pad}{key}:")
            for item in value:
                out.append(f"{pad}  - {_scalar(item)}")
        else:
            out.append(f"{pad}{key}: {_scalar(value)}")
    return out


def _yaml_dump(rule: dict) -> str:
    try:  # prefer PyYAML if the user happens to have it
        import yaml

        return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, default_flow_style=False)
    except Exception:
        return "\n".join(_emit_lines(rule)) + "\n"


def _parse_selection(text: str) -> dict:
    """One 'field: value' per line. A value with commas becomes a list (Sigma
    OR-matches a list). Split on the first ':' so values may contain colons
    (paths, URLs); Sigma field keys never do."""
    selection: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        # Skip empty match values — `field|contains: ""` matches everything and
        # makes a useless (noisy) rule; observed in real runs. A field that must
        # merely exist should be expressed with a non-empty value.
        if not key or not value or value in ('""', "''"):
            continue
        if "," in value:
            selection[key] = [x.strip() for x in value.split(",") if x.strip()]
        else:
            selection[key] = value
    return selection


def _parse_tags(raw) -> list[str]:
    if not raw:
        return []
    return [t.strip() for t in re.split(r"[,\s]+", str(raw)) if t.strip()]


def _slug(title: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", title.lower()).strip("_") or "rule"


async def _run(args: dict, ctx: PluginContext) -> dict:
    title = str(args.get("title") or "").strip()
    if not title:
        return {"error": "title を指定してください"}
    selection = _parse_selection(str(args.get("selection") or ""))
    if not selection:
        return {"error": "selection を1つ以上指定してください(例: 'CommandLine|contains: -sS')"}

    notes: list[str] = []
    level = str(args.get("level") or "medium").strip().lower()
    if level not in _LEVELS:
        notes.append(f"level '{level}' は不正なので medium にしました")
        level = "medium"

    rule: dict = {"title": title}
    description = str(args.get("description") or "").strip()
    if description:
        rule["description"] = description
    tags = _parse_tags(args.get("tags"))
    if tags:
        rule["tags"] = tags
    logsource = {}
    for key in ("category", "product", "service"):
        val = str(args.get(f"logsource_{key}") or "").strip()
        if val:
            logsource[key] = val
    rule["logsource"] = logsource or {"category": "unknown"}
    rule["detection"] = {
        "selection": selection,
        "condition": str(args.get("condition") or "selection").strip(),
    }
    rule["level"] = level

    sigma = _yaml_dump(rule)

    saved_to = None
    if args.get("save", True):
        try:
            DETECTIONS_DIR.mkdir(exist_ok=True)
            path = DETECTIONS_DIR / f"{_slug(title)}.yml"
            if path.exists():
                path = DETECTIONS_DIR / f"{_slug(title)}_{datetime.now().strftime('%H%M%S')}.yml"
            path.write_text(sigma, encoding="utf-8")
            saved_to = str(path.relative_to(PROJECT_ROOT))
        except OSError as exc:
            notes.append(f"保存に失敗: {exc}")

    return {
        "title": title,
        "level": level,
        # 攻撃者にとっての要点: どのログの・どのフィールドを見れば自分が捕捉されるか
        "data_source": {**rule["logsource"], "watched_fields": list(selection.keys())},
        "sigma": sigma,
        "saved_to": saved_to,
        "notes": notes,
    }


def _summary(result) -> str:
    if not isinstance(result, dict):
        return str(result)[:200]
    if result.get("error"):
        return result["error"]
    fields = ", ".join((result.get("data_source") or {}).get("watched_fields", []))
    where = result.get("saved_to") or "(未保存)"
    return f"[{result.get('level')}] {result.get('title')} → {where} / 監視フィールド: {fields}"


PLUGIN = ToolPlugin(
    name="detection_rule",
    description=(
        "実行した攻撃手法を検知する Sigma ルールを生成して手元の detections/ に保存する"
        "(パープルチーム視点)。攻撃が防御側のどのログ・どのフィールドで捕捉されるかが"
        "分かるので、検知を避ける/想定する材料になる。攻撃を1つ行ったら、それがどう見えるかを"
        "このツールで確認するとよい。演習ホストには接触しない。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "ルールのタイトル(例: 'Nmap SYN scan on host')"},
            "selection": {
                "type": "string",
                "description": (
                    "検知条件を1行1項目の 'フィールド: 値' で。値をカンマ区切りにするとOR。"
                    "例:\nCommandLine|contains: -sS\nImage|endswith: /nmap"
                ),
            },
            "description": {"type": "string", "description": "ルールの説明(任意)"},
            "logsource_category": {"type": "string", "description": "logsource category(例: process_creation, firewall)"},
            "logsource_product": {"type": "string", "description": "logsource product(例: linux, windows)"},
            "logsource_service": {"type": "string", "description": "logsource service(例: sshd, auditd)"},
            "condition": {"type": "string", "description": "detection condition(既定: selection)"},
            "level": {
                "type": "string",
                "description": "重要度: informational / low / medium / high / critical(既定 medium)",
            },
            "tags": {"type": "string", "description": "MITRE ATT&CK等のタグ(空白/カンマ区切り。例: 'attack.t1046 attack.discovery')"},
            "save": {"type": "boolean", "description": "detections/ に保存するか(既定 true)"},
        },
        "required": ["title", "selection"],
    },
    run=_run,
    summary=_summary,
    scope_targets=lambda args: [],  # 手元にファイルを書くだけ。演習ホストに接触しない
)
