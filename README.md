# Sikun Cyber Security (SCS)

**認可された対象に対する攻撃的セキュリティ診断(ペネトレーションテスト)を自律的に行うAIエージェント。**
Gemini API をオーケストレーションの中核に据え、攻撃特化ツール・プラグイン基盤・
リッチターミナルUIを組み合わせて構築する。安価なLLM + 安全なスキャフォールディングで、
偵察から実証・報告・検知ルール化までを一気通貫で自動化する。

各自が自分専用のエージェントを**プロファイル + プラグイン**で組み立てて拡張できる。

> ⚠️ **テスト実施の明示的な認可が与えられた対象に対してのみ使用すること。**
> 認可範囲外への使用は禁止。scope による範囲強制と監査ログを備えるが、これは事故防止・
> 説明責任のための仕組みであり、利用者自身が認可の確認と法令遵守の責任を負う。

## セットアップ

```bash
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # 自分の GEMINI_API_KEY を設定
```

APIキーは各自で用意する(`.env` は Git にコミットされない)。

## 実行

```bash
python main.py <対象ホスト>                    # 攻撃診断モード(既定プロファイル)で起動
python main.py --study                         # 学習・解析モードで起動(対象ホスト不要・毎日使える)
python main.py <対象ホスト> --profile web       # 自分のプロファイルで起動
python main.py <対象ホスト> --ssh user@pi       # 対象LAN上のホスト経由でbash実行
python main.py --logs                          # 過去セッションのログ一覧
```

3つのモード(セッション中に `/mode` で切替可):

- **`security`(攻撃診断)** — 認可された対象へのペネトレーションテスト。偵察→実証→報告→修復・検知。
  認可された標的が要るので**たまに使う**「見せ場」
- **`study`(学習・解析)** — 攻撃せず、CVE/攻撃手法の学習・セキスペ対策・持ち込んだ成果物
  (コード/設定/難読化スクリプト/ログ/依存)の防御的な静的解析。標的不要で**毎日開ける**常用モード
- **`general`(汎用)** — セキュリティに限らない一般的な作業アシスタント

## ネイティブデスクトップUI(`gui.py`)

`main.py`(Textual製TUI)と同じエージェント・コア(`sikun/agent_gemini.py`)を、
ダッシュボード風のネイティブウィンドウ(pywebview)で動かせる。

```bash
pip install -r requirements.txt   # pywebview も含む
python gui.py <対象ホスト>
python gui.py --study             # 学習・解析モード
python gui.py <対象ホスト> --profile web --ssh user@pi
```

画面は3つ:

- **Dashboard** — トランスクリプト(recon/exploit/finding/tool呼び出し)+ SITREP
  サイドバー(コスト・ポート・findings)。TUIの `sikun/tui.py` と同じイベントストリームを表示する
- **Reports** — `remediations/`(修復アドバイス)と `detections/`(Sigmaルール)を一覧・閲覧
- **Settings** — `profiles/*.toml` をその場で編集・保存

Linux では OS 側に WebView ランタイムが要る(例: `apt install python3-gi gir1.2-webkit2-4.1`)。
macOS/Windows は標準の WebKit / WebView2 がそのまま使われる。

## 自分専用エージェントの作り方

### 1. 雛形を生成

```bash
python main.py --init myagent
```

`profiles/myagent.toml`(プロファイル)と `plugins/myagent_ping.py`(サンプル自作ツール)が作られる。

### 2. プロファイルを編集(`profiles/myagent.toml`)

```toml
name = "myagent"
persona = "Web脆弱性診断が得意な慎重派。破壊的操作の前は必ず確認する。"
plugins = ["plugins"]
```

モデル / 性格(persona)/ プラグインの場所を、
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

プラグインはコアを一切改造せず `.py` を置くだけで登録される(バックエンド非依存の設計)。

### 同梱プラグイン

- **`cve_lookup`** — recon で判明した製品名+バージョンから既知CVE/エクスプロイト候補を検索
  (searchsploit があれば優先、無ければ NVD 公開API)。recon→exploit の橋渡し
- **`metasploit`** — Metasploit Framework を RPC(msfrpcd + pymetasploit3)経由で構造化操作。
  `msf_search`(モジュール検索)/ `msf_module_info`(オプション確認)/ `msf_run`(実行・scope強制)/
  `msf_sessions`(セッション一覧)/ `msf_session_run`(meterpreter/shell内でコマンド=ポストエクスプロイト)。
  セッションはSCSセッション中維持される。要 `metasploit-framework`(OS側)+ `pymetasploit3`(pip)
- **`privesc_enum`** — 足場取得後の Linux 権限昇格ベクタを一括列挙(sudo/SUID/capability/cron/
  書き込み可能ファイル/カーネル)。GTFOBins既知SUIDや NOPASSWD sudo を notable として抽出
- **`ghidra_decompile`** — Ghidra のヘッドレス解析で、ソースの無いバイナリ(.exe/ELF/マルウェア/
  CTFのrev/ファームウェア)を逆コンパイルし擬似Cを返す。**「Ghidraを読めない」人の代わりに AI が
  読んで説明・脆弱性指摘する**のが狙い。GUI不使用。ソースがあるものには使わない。要 Ghidra(GHIDRA_HOME)
- **`mobsf_scan` / `mobsf_scans`** — MobSF(Mobile Security Framework)にモバイルアプリ
  (APK/IPA/APPX)をアップロードして静的解析し、権限・危険な権限・コード解析findings・証明書の
  問題・トラッカー・セキュリティスコア(0-100)を要約して返す。ソースの無いモバイルアプリ解析用。
  要 MobSF サーバー起動(`MOBSF_URL`)+ `MOBSF_API_KEY`
- **`remediate`** — 実証した finding の**修復アドバイス**(根本原因・具体的な修正手順・優先度・
  CWE/OWASP参照)を生成して `remediations/` に保存(ブルー/防御側)。攻撃を「見つけた」で
  終わらせず、開発者がそのまま直せる形にする。優先度は severity から自動決定
- **`detection_rule`** — 実行した攻撃を検知する Sigma ルールを生成して `detections/` に保存
  (パープル)。自分の攻撃がどのログ/フィールドで捕捉されるか分かる
- **`reverse_dns`** — IPの逆引き(プラグインの書き方サンプル)

findings は**検証必須**: `report(finding)` は再現の証拠を `evidence` 引数に添えるルール
(未確認なら recon で「要確認」)。誤検知を出さないための仕組み。

## 安全装置(スコープ強制)

配布時の事故(認可範囲外のホストへの誤爆)を防ぐため、プロファイルに **`scope`**
(許可する IP / CIDR / ホスト名)を設定できる。起動時に指定した対象は自動で許可される。

```toml
# profiles/lab.toml
scope = ["10.20.3.0/24", "10.20.9.0/24"]   # 認可された網の和集合
```

- **構造化ツール / `scope_targets` を宣言したプラグイン** — 対象が確実に分かるので、
  範囲外なら**実行前にブロック**(誤検知なし)
- **生 bash / 未宣言プラグイン** — コマンドから対象を推定するベストエフォート。範囲外
  らしき対象を検出したら**実行前に確認**(安全側の既定は中止)
- **監査ログ** — 触れた対象と許可/ブロックの判定を `logs/audit.log`(JSONL)に追記

> ⚠️ これは**うっかり事故の防止**と**事後追跡(accountability)**のための仕組みで、
> 悪意ある熟練者を止めるものではない(それは交戦規則+配布先の管理=手続きの役割)。
> 真の封じ込めは、認可対象ネットワークにしか到達できない踏み台の egress firewall で行うこと。

## 構成

- `main.py` — CLIエントリ(`--profile` / `--init` / `--ssh` / `--logs`)
- `gui.py` — ネイティブデスクトップUIエントリ(pywebview、`sikun/webapp.py` を使う)
- `sikun/agent_gemini.py` — エージェント・コア(Gemini tool-use ループ・永続シェル・thinking配分・構造化ツール・永続メモリ・行き詰まり検知による戦略の自己修正・結論前の攻撃面の網羅チェック)
- `sikun/prompts.py` — システムプロンプト・テンプレート(security / general モード)
- `sikun/tools.py` — 永続シェル + 構造化ツール実装(nmap_scan / http_probe / dir_enum)
- `sikun/plugins.py` — **プラグイン基盤**(自作ツールの自動読み込み)
- `sikun/profile.py` — **エージェント・プロファイル**(TOML設定)
- `sikun/scaffold.py` — `--init` の雛形生成
- `sikun/memory.py` — ターゲット別の永続メモリ(セッション間でポート/finding を継続)
- `sikun/tui.py` — Textual製リッチUI(トランスクリプト + 戦況ボード)
- `sikun/webapp.py` / `sikun/web/` — pywebview製ネイティブUI(`sikun/tui.py` と同じイベント/ボード・インターフェースを実装)
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

- `/mode security|study|general` — 攻撃診断 / 学習・解析 / 汎用アシスタント
- `/model lite|full` — 軽量モデル / 通常モデル(Gemini)
- `/plan` — 次のタスクで計画提示を強制
- `Esc` — 実行中のターンを中断
