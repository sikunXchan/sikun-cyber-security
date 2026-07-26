# Sikun Cyber Security (SCS) — v1.0

Sikun-sima大学の攻防戦演習(攻撃側)用の自作AIエージェント。Gemini API をオーケストレーションの
中核に据え(Claude にも切替可)、攻撃特化ツール・RAG知識ベース・リッチターミナルUIを組み合わせて構築する。

**「実際に攻撃をやってみて学ぶ」**ための土台。各自が自分専用のエージェントを
**プロファイル + プラグイン**で組み立て、演習で使い、ツールを共有し合える。

> ⚠️ 演習で許可された対象環境に対してのみ使用すること。認可範囲外への使用は禁止。

## セットアップ

```bash
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # 自分の GEMINI_API_KEY(必要なら ANTHROPIC_API_KEY)を設定
```

APIキーは各自で用意する(`.env` は Git にコミットされない)。

## 実行

```bash
python main.py <対象ホスト>                    # 既定(default)プロファイルで起動
python main.py <対象ホスト> --profile web       # 自分のプロファイルで起動
python main.py <対象ホスト> --provider claude   # プロバイダを明示指定
python main.py <対象ホスト> --ssh user@pi       # 対象LAN上のホスト経由でbash実行
python main.py --logs                          # 過去セッションのログ一覧
```

## 自分専用エージェントの作り方

### 1. 雛形を生成

```bash
python main.py --init myagent
```

`profiles/myagent.toml`(プロファイル)と `plugins/myagent_ping.py`(サンプル自作ツール)が作られる。

### 2. プロファイルを編集(`profiles/myagent.toml`)

```toml
name = "myagent"
provider = "gemini"           # または "claude"
persona = "Web脆弱性診断が得意な慎重派。破壊的操作の前は必ず確認する。"
knowledge_base = "knowledge_base"
plugins = ["plugins"]
```

provider / モデル / 性格(persona)/ 参照する知識ベース / プラグインの場所を、
**コードを書かずに** 切り替えられる。

### 3. 自作ツール(プラグイン)を追加

`plugins/` に `.py` を置くだけで、その中のツールが自動でエージェントに登録される
(コアは無改造)。詳しくは [plugins/README.md](plugins/README.md)。最小例:

```python
from sikun.plugins import PluginContext, ToolPlugin

async def _run(args, ctx):
    output = await ctx.run(f"whatweb {args['url']}")   # ローカル/SSH 透過
    return {"url": args["url"], "raw": output.strip()}

PLUGIN = ToolPlugin(
    name="whatweb",
    description="対象URLの技術スタックを whatweb で調べる。",
    parameters={"type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"]},
    run=_run,
)
```

同じプラグインが Claude / Gemini どちらのプロバイダでもそのまま動く。

### 同梱プラグイン

- **`cve_lookup`** — recon で判明した製品名+バージョンから既知CVE/エクスプロイト候補を検索
  (searchsploit があれば優先、無ければ NVD 公開API)。recon→exploit の橋渡し
- **`detection_rule`** — 実行した攻撃を検知する Sigma ルールを生成して `detections/` に保存
  (パープル)。自分の攻撃がどのログ/フィールドで捕捉されるか分かる
- **`reverse_dns`** — IPの逆引き(プラグインの書き方サンプル)

## 安全装置(スコープ強制)

配布時の事故(認可範囲外のホストへの誤爆)を防ぐため、プロファイルに **`scope`**
(許可する IP / CIDR / ホスト名)を設定できる。起動時に指定した対象は自動で許可される。

```toml
# profiles/team3.toml
scope = ["10.20.3.0/24", "10.20.9.0/24"]   # 認可された網の和集合
```

- **構造化ツール / `scope_targets` を宣言したプラグイン** — 対象が確実に分かるので、
  範囲外なら**実行前にブロック**(誤検知なし)
- **生 bash / 未宣言プラグイン** — コマンドから対象を推定するベストエフォート。範囲外
  らしき対象を検出したら**実行前に確認**(安全側の既定は中止)
- **監査ログ** — 触れた対象と許可/ブロックの判定を `logs/audit.log`(JSONL)に追記

> ⚠️ これは**うっかり事故の防止**と**事後追跡(accountability)**のための仕組みで、
> 悪意ある熟練者を止めるものではない(それは交戦規則+配布先の管理=手続きの役割)。
> 真の封じ込めは、演習LANにしか到達できない踏み台の egress firewall で行うこと。

## 構成

- `main.py` — CLIエントリ(`--profile` / `--init` / `--provider` / `--ssh` / `--logs`)
- `sikun/agent_gemini.py` — Gemini バックエンド・コア(RAG動的化・永続シェル・thinking配分・構造化ツール)
- `sikun/agent.py` — Claude バックエンド(tool-use ループ)
- `sikun/tools.py` — bash / report / propose_plan + 構造化ツール(nmap_scan / http_probe / dir_enum)
- `sikun/plugins.py` — **プラグイン基盤**(自作ツールの自動読み込み)
- `sikun/profile.py` — **エージェント・プロファイル**(TOML設定)
- `sikun/scaffold.py` — `--init` の雛形生成
- `sikun/rag.py` — 知識ベースの埋め込み検索(RAG)
- `sikun/tui.py` — Textual製リッチUI(トランスクリプト + 戦況ボード)
- `knowledge_base/` — RAG用の攻撃手法・脆弱性情報
- `profiles/` — エージェント・プロファイル(TOML)
- `plugins/` — 自作ツール(プラグイン)

## テスト

```bash
python tests/test_foundation.py     # 追加依存なしで実行できる(オフライン)
# または
pip install -r requirements-dev.txt && pytest
```

## セッション中のコマンド

入力欄で使えるスラッシュコマンド:

- `/mode security|general` — 攻撃モード / 汎用アシスタントモード
- `/model lite|full` — 軽量モデル / 通常モデル(Gemini)
- `/plan` — 次のタスクで計画提示を強制
- `Esc` — 実行中のターンを中断
