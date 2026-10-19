# SCS オーケストレータ=ワーカー設計図(Claude Agent SDK 版)

> 対象読者: SCS を Gemini から Claude Agent SDK へ載せ替え、かつ
> 「親エージェントがユーザー指示を分解し、複数の子エージェントに配る」
> マルチエージェント構成へ拡張したい開発者。
>
> 用途前提: **大学の認可されたCTF(AIツール可)/ホワイトハッカー養成**。
> `profiles/*.toml` の `scope` と `audit.log` による認可対象の強制は、この
> 設計でも最優先で維持する(むしろ強化する)。

---

## 0. 方針(最初に合意しておく前提)

1. **UIは触らない。** Textual TUI(`main.py`)/ pywebview GUI(`gui.py`)/ Web
   (`sikun/webapp.py`)はそのまま。差し替えるのは中のエンジンだけ。SCSは
   最初からエンジン(`sikun/agent_gemini.py`)とUIが分離しているので、これが
   成立する。

2. **エンジンを `agent_gemini.py` → `agent_claude.py` に載せ替える。** Claude
   Agent SDK はエージェントループ・コンテキスト管理・組み込みツール・サブ
   エージェントを内蔵しているので、SCSが手書きしている `_run_loop` /
   `_compact_old_context` / 自己修正ロジックの多くは SDK 側に委譲できる。

3. **安全分類器はモデル側で動く前提で設計する。** 子を何体に分けても各子は
   同じ分類器(`stop_reason: "refusal"`)を通る。マルチエージェント化は
   「速度と分業」のための設計であり、ゲートを外す手段ではない。認可事実を
   scope とプロンプトに明示し、作業を具体ステップに分けることで**誤検知を
   減らす**のが正しい方向。

4. **認可ガード(scope + audit)は一等市民として残す。** SCS の `ScopeGuard`
   が担っていた「認可範囲外への誤爆防止+監査証跡」を、Agent SDK の
   hook / permission に移植する(§6)。

---

## 1. 現状SCS → Agent SDK 対応表(何を捨て、何を残すか)

| SCS の構成要素 | 役割 | Agent SDK 版での扱い |
|---|---|---|
| `_run_loop`(ツールループ本体) | request→execute→loop | **SDK が肩代わり**(`query()` が回す)。自前ループは原則不要 |
| `_compact_old_context` | 長時間runの文脈圧縮 | **SDK のコンテキスト管理に委譲** |
| 自己修正(4連続不毛ターン検知) | 行き詰まり回避 | 一部は SDK 任せ。固有ロジックが要ればフックで再実装 |
| `_estimate_cost` | コスト表示 | SDK/API の usage から再実装(HUD 用に残す価値あり) |
| コアツール `bash`/`nmap_scan`/`http_probe`/`dir_enum` | 実行系 | `bash` は SDK 組み込み Bash に寄せる。nmap/http/dir は**カスタムツール(MCP)として移植** |
| `propose_plan` | 破壊的操作前の確認 | **permission フック**として再実装(§6) |
| `ToolPlugin`(plugins/*.py) | 学生の自作ツール | **MCP ツール定義へ変換**。`scope_targets` は permission 判定に流用 |
| `ScopeGuard` + `Scope`(audit.log) | 認可対象強制+監査 | **permission コールバック + hook** に移植(§6)。最重要 |
| `profiles/*.toml`(persona/model/plugins/scope) | エージェント定義 | ほぼそのまま。`persona`→system prompt、`scope`→permission、`plugins`→MCPツール集合 |
| イベントチャネル(TUIへ) | 可視化 | SDK のストリーム/フックイベントを既存イベント形式に変換して流す |

ポイント: **SCS の「プラグイン=ツール」「プロファイル=エージェント定義」
「scope=認可」という抽象は、Agent SDK にほぼ1対1で載る。** 作り直しでは
なく「配線の付け替え」。

---

## 2. 目標アーキテクチャ

```
                         ┌──────────────────────────────┐
   ユーザー指示 ───────▶ │  Orchestrator(親エージェント) │
   (リアルな             │  - 指示を解釈                 │
    シチュエーション)    │  - タスクをDAGに分解(§4)     │
                         │  - 層ごとに子へ分配           │
                         │  - 結果を統合し次の一手を決定 │
                         └───────────────┬──────────────┘
                                         │ 分配(独立ノードのみ並列)
         ┌───────────────┬───────────────┼───────────────┬───────────────┐
         ▼               ▼               ▼               ▼               ▼
   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
   │ recon    │   │ web      │   │ crypto   │   │ reversing│   │ forensics│  ← 子(サブエージェント)
   │ worker   │   │ worker   │   │ worker   │   │ worker   │   │ worker   │
   └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘
        │              │              │              │              │
        └──────────────┴──────┬───────┴──────────────┴──────────────┘
                              ▼
                   ┌────────────────────────┐
                   │ 共通コア層              │
                   │ - ツールレジストリ(MCP)│
                   │ - scope/permission/audit│
                   │ - イベント→既存UIへ     │
                   └────────────────────────┘
```

- **親も子も同じコア層(ツール・scope・イベント)を共有する。** 子ごとに
  「許可ツールの部分集合」と「scope」を絞るのが分業の肝。
- 子は**役割(category)**で分ける。CTFの出題カテゴリ(recon/web/crypto/
  reversing/forensics/pwn/misc)がそのまま子の型になる。

---

## 3. エンジン載せ替え(`agent_claude.py`)

Claude Agent SDK は `query(prompt, options)` を中心に、組み込みツール
(Read/Write/Edit/Bash/Glob/Grep/WebSearch/WebFetch)+ MCP + サブエージェント
を提供する(ソース: Anthropic 公式 Agent SDK ドキュメント
`code.claude.com/docs/en/agent-sdk`、および claude-api スキル
「Building an Agent: Four Approaches」表 option 4)。

> ⚠ **API名の確定が必要**: サブエージェント定義・hook・permission コール
> バックの**正確な引数名/シグネチャは、上記 Agent SDK ドキュメントで確認して
> から実装する。** claude-api スキルは Agent SDK のコードは生成対象外と明記
> しており、ここで擬似シグネチャを断定しない(記憶からの捏造を避ける)。
> 下記の擬似コードは**構造の設計**であって、確定APIではない。

骨子(擬似コード・構造のみ):

```python
# sikun/agent_claude.py (新設) — 構造のイメージ
#
# options には概ね次を渡す:
#   - system prompt   ← profile.persona + モード別プロンプト(sikun/prompts.py を流用)
#   - allowed tools   ← コアツール + profile のプラグイン由来 MCP ツール
#   - permission hook ← ScopeGuard を移植した認可判定(§6)
#   - subagents       ← カテゴリ別ワーカー定義(§5)
#
# UI へのイベントは、SDK のストリーム/フックイベントを
# sikun.events の render_* 形式に変換して既存チャネルへ流す。

async def run_agent(target, profile, mode, app, ...):
    tools      = build_tool_registry(profile)        # §3.1
    scope      = build_scope(profile, target)        # §6
    subagents  = build_workers(profile, scope)       # §5
    system     = compose_system_prompt(profile, mode)

    async for event in sdk_query(
        prompt=initial_prompt(target, mode),
        system=system,
        tools=tools,
        subagents=subagents,
        on_permission=make_permission_cb(scope, audit_log),  # §6
        on_event=lambda e: forward_to_ui(app, e),
    ):
        ...  # 統合・HUD更新・停止判定
```

### 3.1 プラグイン → MCP ツール変換

`ToolPlugin`(name/description/parameters/run/scope_targets)は、そのまま
MCP ツール1本に写せる。変換関数を1つ書けば、既存 `plugins/*.py` を**無改修**で
再利用できる(SCS の「コアに触らずツールを足せる」という売りを維持)。

```python
def plugin_to_mcp_tool(p: ToolPlugin, ctx_factory):
    # p.parameters は既に JSON-Schema。description/ name もそのまま。
    # p.run(args, PluginContext) を MCP ツールの実行ハンドラでラップ。
    # p.scope_targets(args) があれば permission 判定へ渡す(§6)。
    ...
```

---

## 4. オーケストレータの分解ロジック(依存グラフ)★本命

親の仕事は「指示を**タスクDAG**に落とし、独立ノードだけを並列化し、依存して
いる手順は同じ子の中で逐次実行させる」こと。

### 4.1 タスクの内部表現

```python
@dataclass
class SubTask:
    id: str                 # "recon-1"
    category: str           # "recon" / "web" / "crypto" / ...
    goal: str               # 子に渡す具体ゴール(1問1ゴール)
    depends_on: list[str]   # 先に完了すべき SubTask.id
    tools: list[str]        # この子に許可するツール部分集合
    scope: list[str]        # この子が触ってよい対象(親scopeの部分集合)
```

### 4.2 分解の原則(粒度ルール)

- **◎ 独立ノードに分ける**: カテゴリ間など情報依存が薄い塊は別ノード→並列。
- **✕ 連鎖する手順を細切れにしない**: 「Aの出力をBが即使う」ような連鎖は
  `depends_on` で繋ぐか、**1つの SubTask にまとめて同じ子に連続実行**させる。
  親が逐一仲介するとコンテキストが切れて遅くなる。
- 判定基準: 「子Xの途中成果物を、子Yが**その場で**必要とするか?」
  - する → 同じ子にまとめる(または depends_on)
  - しない → 別ノードで並列

### 4.3 実行アルゴリズム(層ごと並列)

```python
async def orchestrate(user_instruction, scope, app):
    dag = decompose(user_instruction, scope)     # LLM に DAG を生成させる(§4.4)
    results = {}
    for layer in topological_layers(dag):        # 依存の無いもの同士が同じ層
        # 同一層は互いに独立 → 並列ディスパッチ
        layer_out = await gather(
            dispatch_worker(t, results, scope, app) for t in layer
        )
        results.update(zip((t.id for t in layer), layer_out))
        if app.should_stop(results):             # フラグ発見等で早期終了
            break
    return synthesize(results)                    # 親が統合し報告
```

- `topological_layers`: DAG をトポロジカルソートし、**同じ依存深さのノードを
  1層に束ねる**。層内は並列、層間は逐次。
- `dispatch_worker(t, results, ...)`: `t.depends_on` の結果を入力に渡して、
  `t.category` のサブエージェントを起動。

### 4.4 DAG の作り方(2通り、組み合わせ可)

1. **LLM 生成**: 親に「指示を SubTask の JSON 配列(§4.1 スキーマ)で出せ」と
   構造化出力させる。柔軟だが検証が要る。
2. **ルールベースの骨格**: CTFはカテゴリが定型なので、カテゴリ検出→定番の
   子セットを雛形として用意し、LLM には「どの子を有効化し、どう繋ぐか」だけ
   判断させる。暴走しにくい。
   → **推奨: 2を土台に1で微調整**(SCSの `propose_plan` 文化=計画を一度
   見せて承認、とも相性が良い)。

### 4.5 具体例(認可ラボ機材「ネットワーク機器の盗聴課題」)

```
decompose 出力(DAG):
  recon-1  (recon)     depends_on=[]            # 機器・開放ポート・サービス特定
  web-1    (web)       depends_on=[recon-1]     # 管理画面/API 調査(recon結果を使う)
  app-1    (mobile)    depends_on=[]            # companion アプリ静的解析(MobSF)
  fw-1     (reversing) depends_on=[]            # ファームウェア逆コンパイル(Ghidra)

層分解:
  層0: [recon-1, app-1, fw-1]   ← 互いに独立 → 並列
  層1: [web-1]                  ← recon-1 の結果が要る → 層0の後
統合:
  親が全結果を集約し、攻撃面と対になる防御(暗号化・既定認証情報の廃止等)を報告
```

この「独立なものは並列、連鎖は依存エッジ」が、あなたの当初アイデア
「タスクを細分化して独立セッションで」の正しい形。

---

## 5. ワーカー(子)の設計

各子は **(a)役割プロンプト (b)許可ツールの部分集合 (c)継承scope
(d)構造化された戻り値** の4点で定義する。

```python
@dataclass
class WorkerSpec:
    category: str
    system: str              # 役割特化プロンプト(例: "Web脆弱性調査担当。…")
    allowed_tools: list[str] # 例: web worker = [http_probe, dir_enum, bash(限定)]
    model: str | None        # コスト最適化: recon=安いモデル, pwn=高いモデル等
```

- **戻り値は必ず構造化**して親に返す(自由文だと統合でブレる):

```json
{
  "category": "recon",
  "status": "done",
  "findings": [{"type": "open_port", "detail": "...", "evidence": "..."}],
  "next_hints": ["web-1 は 8080 の管理画面を見るとよい"],
  "scope_touched": ["10.0.0.5"]
}
```

- `next_hints` を親が読んで次層の子へ渡すと、**層をまたいだ連携**が自然に回る。
- `model` を子ごとに変えるとコスト最適化できる(偵察=軽量、Pwn/RE=高性能)。
  これは Agent SDK のサブエージェント設定、または Managed Agents のロスター
  (worker を別モデルIDで登録)で実現する(ソース: claude-api スキル
  「Managed Agents」マルチエージェント節)。自前ホストなら前者。

---

## 6. 認可ガードの移植(ScopeGuard → permission / hook)★CTFの肝

SCS の `ScopeGuard` は「宣言された対象を信頼度に応じて hard-block / confirm し、
`audit.log` に全件追記」する(`sikun/scope.py`)。これを Agent SDK の
**permission コールバック**に移植する。

```python
def make_permission_cb(scope: Scope, audit_log: Path):
    def on_tool_call(tool_name, args):
        # 1) ツールが対象を宣言(nmap target / plugin.scope_targets)→ RELIABLE 判定
        targets = declared_targets(tool_name, args)   # SCS の guard_reliable 相当
        if targets:
            if scope.enabled and not scope.allows_all(targets):
                audit(audit_log, tool_name, targets, "BLOCK")
                return DENY("認可範囲外: " + ", ".join(targets))
            audit(audit_log, tool_name, targets, "ALLOW")
            return ALLOW
        # 2) 生 bash 等 → BEST-EFFORT 抽出 → 疑わしければ confirm(propose_plan 文化)
        host_like = extract_hosts(args)               # SCS の guard_besteffort 相当
        if host_like and scope.enabled and scope.any_out_of_scope(host_like):
            return CONFIRM("対象が範囲外の可能性: " + ", ".join(host_like))
        return ALLOW
    return on_tool_call
```

- `propose_plan`(破壊的操作前の確認)は、この permission 層の **CONFIRM** に
  自然に吸収できる。
- **子にも同じ permission を必ず適用する。** 子ごとに scope を親scopeの
  部分集合へ絞れば、「web worker は管理画面ホストだけ」のような**最小権限**が
  作れる。
- `audit.log` は親子すべてのツール呼び出しを1本に集約(誰がどの対象を触ったか
  の証跡)。CTFの「認可対象だけ」を説明責任つきで担保する。

> API 名の確定: permission コールバック/フックの正確な登録方法は Agent SDK
> ドキュメントで確認すること(§3 の注記と同じ)。

---

## 7. 段階的移行計画(小さく検証しながら)

| Step | 内容 | 完了条件 |
|---|---|---|
| 1 | `agent_claude.py` を新設し、**単一エージェント**で等価動作(UI据え置き) | 既存の study/security モードが Claude で回る |
| 2 | permission/scope/audit を移植 | 範囲外ツール呼び出しが BLOCK され audit に残る |
| 3 | プラグイン→MCP変換で既存 `plugins/*.py` を無改修で再利用 | ghidra/mobsf/metasploit 等が子から使える |
| 4 | サブエージェント **1種**(recon)だけ追加 | 親→子1体の分配・結果統合が動く |
| 5 | 分解ロジック(§4)+ 複数カテゴリ並列 | 層0並列→層1逐次が DAG 通りに走る |
| 6 | 構造化戻り値で統合・HUD可視化 | findings/next_hints が親で集約表示される |

**Step1 で「等価動作」を先に取る**のが重要。いきなり並列化せず、エンジン
載せ替えだけを確定させてから分業を足す。

---

## 8. 未確定・要確認(一次情報で詰める)

- Claude Agent SDK の **サブエージェント定義 / hook / permission** の正確な
  API。→ `code.claude.com/docs/en/agent-sdk` で確認してから実コードを書く。
- 子ごとのモデル振り分けを「Agent SDK のサブエージェント」でやるか
  「Managed Agents のロスター」でやるか(自前ホスト=前者、Anthropicホスト=後者)。
- 分類器の誤検知傾向: 実際に `stop_reason: "refusal"` が出た指示文を観測し、
  §0-3 の方針(認可事実の明示+具体ステップ化)で減るかを計測する。

---

## 付録: 判断の背景にある事実(ソース)

- Claude Agent SDK = Claude Code のライブラリ版。組み込みツール+ループ+
  サブエージェント+MCP、自前ホスト。
  出典: claude-api スキル「Building an Agent: Four Approaches」option 4 /
  `code.claude.com/docs/en/agent-sdk`。
- 安全分類器はモデル側。Messages API に `stop_reason: "refusal"`
  (`stop_details.category` 例 `cyber`)が定義。SDK を変えても走る。
  出典: claude-api スキル「Stop Reasons」「Structured Stop Details」。
- SCS 既存構造: `sikun/agent_gemini.py`(run_agent/_run_loop)、
  `sikun/plugins.py`(ToolPlugin/scope_targets)、`sikun/scope.py`
  (ScopeGuard: RELIABLE hard-block / BEST-EFFORT confirm + audit.log)。
