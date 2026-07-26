# プラグイン(自作ツール)の作り方

`plugins/` に `.py` を1つ置くだけで、その中で定義したツールがエージェントに
自動で登録されます。**コア(`sikun/agent*.py`, `tui.py`)は一切触りません。**

## 最小の例(約20行)

```python
from sikun.plugins import PluginContext, ToolPlugin

async def _run(args: dict, ctx: PluginContext) -> dict:
    host = str(args.get("host") or ctx.target)
    output = await ctx.run(f"ping -c 2 -W 2 {host}")   # ローカル/SSH 透過
    return {"host": host, "raw": output.strip()}

PLUGIN = ToolPlugin(
    name="my_ping",
    description="対象にpingして到達性を返す。",
    parameters={
        "type": "object",
        "properties": {"host": {"type": "string", "description": "対象ホスト"}},
        "required": [],
    },
    run=_run,
)
```

## ルールは3つだけ

1. **公開**: モジュール直下に `PLUGIN`(単体)か `PLUGINS`(リスト)を置く
2. **`run(args, ctx)` は `async`**
   - `args`: モデルが渡す引数(`parameters` のスキーマに対応)
   - `ctx.run(cmd)`: シェル実行。ローカルでもSSH先でも同じように動く
   - `ctx.target` / `ctx.ssh_host` / `ctx.workdir` も参照可
3. **返り値は JSON にできる dict** — そのままモデルへツール結果として返る

## 補足

- `parameters` は JSON Schema。**Claude / Gemini どちらのプロバイダでも同じ書き方**で動く
- `summary=lambda r: ...` を付けると、TUI に出る1行プレビューを整えられる
- ファイル名/ツール名が `_` で始まるものは読み込み対象外(ヘルパー用)
- 予約名(`bash`, `report`, `nmap_scan`, `http_probe`, `dir_enum`, `propose_plan`)は使えません
- 壊れたプラグインは**スキップされ、起動時に理由が表示**されます(セッションは止まりません)

## 雛形を生成する

```bash
python main.py --init mytool
```

`profiles/mytool.toml` と `plugins/mytool_ping.py`(編集用サンプル)が作られます。
