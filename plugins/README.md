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

## 安全装置対応(推奨)

`scope_targets` を宣言すると、そのツールが触れる対象がスコープ強制で**確実にチェック**され、
認可範囲外なら実行前にブロックされる(宣言しない場合は引数からのベストエフォート推定+確認になる):

```python
PLUGIN = ToolPlugin(
    name="whatweb", ...,
    scope_targets=lambda args: [args["url"]],   # ← このツールが触れる対象を申告
)
```

## 補足

- `parameters` は標準的な JSON Schema。コアを改造せず `.py` を置くだけで登録される
- `summary=lambda r: ...` を付けると、TUI に出る1行プレビューを整えられる
- ファイル名/ツール名が `_` で始まるものは読み込み対象外(ヘルパー用)
- 予約名(`bash`, `report`, `nmap_scan`, `http_probe`, `dir_enum`, `propose_plan`)は使えません
- 壊れたプラグインは**スキップされ、起動時に理由が表示**されます(セッションは止まりません)

## 雛形を生成する

```bash
python main.py --init mytool
```

`profiles/mytool.toml` と `plugins/mytool_ping.py`(編集用サンプル)が作られます。
