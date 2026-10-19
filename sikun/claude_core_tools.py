"""SCS core tools exposed as Claude Agent SDK (in-process MCP) tools.

The Gemini engine ships three structured recon tools — ``nmap_scan`` /
``http_probe`` / ``dir_enum`` (``sikun.tools``) — as Gemini FunctionDeclarations.
This module re-exposes the SAME implementations to the Claude engine as MCP
tools, so a Claude worker gets the same calibrated, structured observations
(not just raw Bash) and the same reliable scope enforcement.

``core_tools(ssh_host)`` returns the SDK tool objects (the shell target is
bound in, mirroring the Gemini engine's ssh wiring). ``CORE_SCOPE`` maps each
tool's name to the function that extracts the host/URL it will touch, so the
permission gate (``sikun.permission``) can hard-block an out-of-scope call
before it runs — the same RELIABLE enforcement the Gemini engine's
``guard_reliable`` gives these tools.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from claude_agent_sdk import SdkMcpTool, tool

from sikun.tools import run_dir_enum, run_http_probe, run_nmap_scan

# JSON-Schema inputs for the three core recon tools (re-exposed to the Claude engine).
_NMAP_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "スキャン対象のIP/ホスト名"},
        "ports": {"type": "string", "description": "ポート範囲(例 '1-1000','22,80,443')。省略時は上位1000番"},
        "service_detection": {"type": "boolean", "description": "サービスバージョン検出(-sV)。既定true"},
        "protocol": {"type": "string", "enum": ["tcp", "udp"], "description": "既定tcp。UDPは明示指定"},
    },
    "required": ["target"],
}
_HTTP_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "対象URL(例 'http://10.0.0.5:8080/')。スキーム省略時はhttp://を補う"},
    },
    "required": ["url"],
}
_DIR_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "探索対象のベースURL"},
        "wordlist": {"type": "string", "description": "カンマ区切りの探索パス(省略時は組み込みの一般パス群)"},
    },
    "required": ["url"],
}


def _as_content(result: Any) -> dict[str, Any]:
    text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}]}


def core_tools(ssh_host: str | None = None) -> list[SdkMcpTool]:
    """Build the three core SDK tools with the shell target bound in."""

    @tool("nmap_scan",
          "対象ホストのポートスキャン・サービス検出を行い、開放ポート/サービス/バージョンを構造化して返す。"
          "bashでnmapを組み立てて生出力をパースするより信頼性が高いので、ポートスキャンはこれを優先。",
          _NMAP_SCHEMA)
    async def _nmap(args: dict[str, Any]) -> dict[str, Any]:
        return _as_content(await run_nmap_scan(
            args["target"], args.get("ports", ""), args.get("service_detection", True),
            ssh_host, args.get("protocol", "tcp")))

    @tool("http_probe",
          "対象URLにHTTPリクエストを送り、ステータス/ヘッダ/タイトル/技術推測/根拠付きHTTP設定観測を"
          "構造化して返す。curlで生ヘッダを読むより信頼性が高いので、Web初期調査はこれを優先。review は確定脆弱性ではない。",
          _HTTP_SCHEMA)
    async def _http(args: dict[str, Any]) -> dict[str, Any]:
        return _as_content(await run_http_probe(args["url"], ssh_host))

    @tool("dir_enum",
          "対象URL配下のディレクトリ/ファイルを探索し、見つかったパスとステータスを構造化して返す。"
          "soft-404/共通ログイン画面は ambiguous に分離。found も未検証候補。errors/complete/coverage を確認し未検査を安全と結論しない。",
          _DIR_SCHEMA)
    async def _dir(args: dict[str, Any]) -> dict[str, Any]:
        return _as_content(await run_dir_enum(args["url"], args.get("wordlist", ""), ssh_host))

    return [_nmap, _http, _dir]


# Reliable scope extraction per tool — handed to the permission gate so an
# out-of-scope target is hard-blocked before the tool runs.
CORE_SCOPE: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "nmap_scan": lambda a: [a["target"]] if a.get("target") else [],
    "http_probe": lambda a: [a["url"]] if a.get("url") else [],
    "dir_enum": lambda a: [a["url"]] if a.get("url") else [],
}
