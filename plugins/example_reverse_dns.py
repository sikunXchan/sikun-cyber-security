"""サンプルプラグイン: 逆引きDNS(読み取り専用の偵察ヘルパー)。

プラグインの書き方の実例です。このファイルは `plugins/` にあるので、既定
プロファイルで起動すると `reverse_dns` ツールが自動で使えるようになります。

書き方のルールは3つ:
1. ToolPlugin を作り、モジュール直下に PLUGIN(単体) か PLUGINS(リスト) で公開
2. run(args, ctx) は async。args=モデルが渡す引数、ctx.run(cmd)=シェル実行
3. 返り値は JSON にできる dict(そのままモデルへツール結果として返る)
"""

from __future__ import annotations

from sikun.plugins import PluginContext, ToolPlugin


async def _run(args: dict, ctx: PluginContext) -> dict:
    ip = str(args.get("ip", "")).strip()
    if not ip:
        return {"error": "ip が空です"}
    # getent(無ければ nslookup/host)にフォールバックして環境差を吸収する。
    output = await ctx.run(
        f"getent hosts {ip} 2>/dev/null "
        f"|| nslookup {ip} 2>/dev/null "
        f"|| host {ip} 2>/dev/null "
        f"|| echo '(解決できませんでした)'"
    )
    return {"ip": ip, "result": output.strip()}


PLUGIN = ToolPlugin(
    name="reverse_dns",
    description="IPアドレスの逆引き(PTR)を行い、対応するホスト名を返す読み取り専用の偵察ヘルパー。",
    parameters={
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "逆引きするIPアドレス"},
        },
        "required": ["ip"],
    },
    run=_run,
    summary=lambda r: (r.get("result") or r.get("error") or "")[:200] if isinstance(r, dict) else str(r),
    # このツールが触れる対象を申告 → scope強制が確実に効く(範囲外なら実行前にブロック)。
    scope_targets=lambda args: [str(args.get("ip", ""))],
)
