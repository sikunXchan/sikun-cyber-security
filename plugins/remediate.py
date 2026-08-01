"""remediate — 実証した finding を「直し方」まで一気通貫にする修復アドバイザ(ブルー/防御側)。

攻撃で確定した脆弱性を入力に、根本原因・具体的な修正手順・優先度・CWE/OWASP 参照を
組み立てて手元の remediations/ に保存する。攻撃結果を「見つけた」で終わらせず、防御側が
そのまま着手できる形に落とすのが狙い。

設計は detection_rule と同じ思想:**修復知識の中身はこのツールが厳選して決定的に持つ**
(脆弱性クラス→根本原因/修正手順/CWE/OWASP のキュレーション表)。モデルは「どのクラスか」と
「対象固有の事実(該当箇所・観測)」だけを渡せばよいので、壊れた/的外れな助言は出にくい。
優先度は severity から決定的に決まる。対象ホストには接触しない(手元にファイルを書くだけ)
ので scope_targets は空。
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from sikun.plugins import PluginContext, ToolPlugin

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REMEDIATIONS_DIR = PROJECT_ROOT / "remediations"

# severity → 対応の緊急度。攻撃側の severity 語彙(critical/high/medium/low/info)に合わせる。
_PRIORITY = {
    "critical": ("P0", "即時対応(公開前提なら直ちに修正)"),
    "high": ("P1", "早急(次のリリースを待たず修正)"),
    "medium": ("P2", "計画的(次の定期リリースで修正)"),
    "low": ("P3", "任意(余力がある時に対応)"),
    "info": ("P3", "参考(ハードニング候補)"),
}

# 脆弱性クラス → キュレーション済み修復知識。root_cause/fixes は一般に正しい原則を、
# example は言語非依存で意図が伝わる最小例を置く(対象固有の詳細はモデルが detail で足す)。
_KB: dict[str, dict] = {
    "sqli": {
        "name": "SQL Injection",
        "cwe": "CWE-89",
        "owasp": "OWASP A03:2021 Injection / ASVS V5.3.4",
        "root_cause": "ユーザ入力を文字列連結でSQL文に埋め込んでおり、入力がクエリ構造を変えられる。",
        "fixes": [
            "パラメータ化クエリ/プリペアドステートメントを使い、入力を値としてのみ渡す(文字列連結を全廃)。",
            "ORM(Sequelize/Prisma 等)のバインドパラメータ機能を使い、生SQLの手組みを避ける。",
            "入力検証(型・長さ・許可リスト)を追加し、DB接続アカウントは最小権限にする。",
            "エラーメッセージにSQL断片やスタックを出さない(汎用エラーに丸める)。",
        ],
        "example": "db.query('SELECT * FROM users WHERE email = ?', [email])  // ← 連結ではなくプレースホルダ",
    },
    "nosqli": {
        "name": "NoSQL Injection",
        "cwe": "CWE-943",
        "owasp": "OWASP A03:2021 Injection",
        "root_cause": "クエリにユーザ制御のオブジェクト($gt/$ne 等の演算子)をそのまま渡している。",
        "fixes": [
            "入力を文字列として厳格に型検証し、オブジェクト/クエリ演算子の混入を拒否する。",
            "クエリ組み立て時に値を明示的にキャストし、演算子インジェクションを防ぐ。",
            "認証系はタイミング安全な比較と適切なハッシュ(bcrypt/argon2)で実装する。",
        ],
        "example": "if (typeof email !== 'string') reject();  // {\"$gt\":\"\"} のようなオブジェクトを弾く",
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "OWASP A03:2021 / ASVS V5.3.3",
        "root_cause": "ユーザ入力を無害化せずにHTML/DOMへ出力しており、スクリプトが実行される。",
        "fixes": [
            "出力コンテキスト(HTML本文/属性/JS/URL)に応じたエスケープを行う。",
            "フレームワークの自動エスケープを有効にし、innerHTML 等の危険なsinkを避ける。",
            "Content-Security-Policy を導入してインラインスクリプトを禁止する。",
            "入力検証は補助的に許可リストで行う(出力側エスケープが本命)。",
        ],
        "example": "el.textContent = userInput;  // innerHTML ではなく textContent を使う",
    },
    "broken_access_control": {
        "name": "Broken Access Control / 認可バイパス (IDOR含む)",
        "cwe": "CWE-284 / CWE-639",
        "owasp": "OWASP A01:2021",
        "root_cause": "サーバ側の認可チェックが欠落/不十分で、権限外の操作やオブジェクト参照ができる。",
        "fixes": [
            "全ての機密操作をサーバ側で認可チェックする(ロール検証・所有者検証)。",
            "オブジェクト参照は現在ユーザの権限に対して都度検証する(IDOR対策)。",
            "デフォルト拒否(deny by default)にし、管理機能はロールで保護する。",
            "認可判断をクライアント(UIの出し分け)に依存させない。",
        ],
        "example": "if (resource.ownerId !== currentUser.id) return res.status(403);",
    },
    "sensitive_data_exposure": {
        "name": "機密データ/ファイルの露出",
        "cwe": "CWE-200 / CWE-538",
        "owasp": "OWASP A01:2021 / A05:2021",
        "root_cause": "バックアップ・設定・資格情報ファイルが認証なしで公開ディレクトリに置かれている。",
        "fixes": [
            "公開ディレクトリから機密ファイル(.bak/.kdbx/鍵/設定)を除去する。",
            "静的配信のディレクトリリスティングを無効化する。",
            "配信は必要なファイルのみ許可リストで行い、それ以外は403/404にする。",
            "露出した資格情報・鍵は直ちにローテーションする。",
        ],
        "example": "autoIndex(false)  // ディレクトリ一覧を無効化。/ftp 等に機密を置かない",
    },
    "path_traversal": {
        "name": "Path Traversal / ディレクトリトラバーサル",
        "cwe": "CWE-22",
        "owasp": "OWASP A01:2021",
        "root_cause": "ユーザ入力をファイルパスに連結し、../ で基準ディレクトリ外へ抜けられる。",
        "fixes": [
            "入力はファイル名のみに正規化し、basename化+許可リスト照合する。",
            "デコード後の絶対パスが基準ディレクトリ配下にあることを検証する(realpath比較)。",
            "%2e・二重エンコード・ヌルバイトはデコードしてから検証する。",
        ],
        "example": "const p = path.resolve(BASE, name); if (!p.startsWith(BASE)) reject();",
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "owasp": "OWASP A10:2021",
        "root_cause": "ユーザ指定のURLへサーバが検証なしにリクエストしてしまう。",
        "fixes": [
            "宛先をスキーム/ホスト/ポートの許可リストで制限する。",
            "内部IP・loopback・クラウドメタデータ(169.254.169.254)を拒否する。",
            "リダイレクト追従を無効化し、DNSリバインディングに注意する。",
        ],
        "example": "if (isPrivateIP(resolved) || scheme !== 'https') reject();",
    },
    "ssti": {
        "name": "Server-Side Template Injection (SSTI)",
        "cwe": "CWE-1336 / CWE-94",
        "owasp": "OWASP A03:2021",
        "root_cause": "ユーザ入力をテンプレートエンジンに式として評価させている。",
        "fixes": [
            "ユーザ入力はテンプレートのデータとしてのみ渡し、テンプレート本文に混ぜない。",
            "サンドボックス化されたエンジン/ロジックレステンプレートを使う。",
            "eval 相当の危険な組み込みを無効化する。",
        ],
        "example": "render('page', { name });  // テンプレ文字列を入力から組み立てない",
    },
    "xxe": {
        "name": "XML External Entity (XXE)",
        "cwe": "CWE-611",
        "owasp": "OWASP A05:2021",
        "root_cause": "XMLパーサが外部エンティティ/DTDを解決する設定になっている。",
        "fixes": [
            "XMLパーサで外部エンティティとDTDの解決を無効化する。",
            "可能ならXMLではなくJSONを採用する。",
        ],
        "example": "parser.setFeature('disallow-doctype-decl', true)",
    },
    "insecure_deserialization": {
        "name": "危険なデシリアライズ",
        "cwe": "CWE-502",
        "owasp": "OWASP A08:2021",
        "root_cause": "信頼できないデータを型情報付きでデシリアライズしている。",
        "fixes": [
            "信頼できない入力をデシリアライズしない。必要なら署名/MACで完全性を検証する。",
            "許可リスト型のデシリアライザ、またはJSON等の安全な形式を使う。",
        ],
        "example": "JSON.parse(input)  // 任意オブジェクトを復元する形式(pickle等)を避ける",
    },
    "rce": {
        "name": "Remote Code Execution / コマンドインジェクション",
        "cwe": "CWE-77 / CWE-78 / CWE-94",
        "owasp": "OWASP A03:2021",
        "root_cause": "ユーザ入力をシェルや評価関数に渡し、任意コマンド/コードが実行される。",
        "fixes": [
            "シェルを介さず引数配列でプロセスを起動する(shell=false 相当)。",
            "eval/exec 相当を廃止する。",
            "どうしても外部コマンドが必要なら入力を厳格な許可リストで制限する。",
        ],
        "example": "execFile('convert', [safeArg])  // exec('convert ' + userInput) は不可",
    },
    "weak_auth": {
        "name": "認証の不備",
        "cwe": "CWE-287 / CWE-307",
        "owasp": "OWASP A07:2021",
        "root_cause": "弱いパスワード保管/レート制限欠如/脆弱なトークン設計。",
        "fixes": [
            "パスワードは bcrypt/argon2 でハッシュし、ログイン試行にレート制限とロックアウトを入れる。",
            "多要素認証を導入し、セッション/JWTは強い署名鍵と短い有効期限で運用する。",
            "パスワードリセットの本人確認を強化する。",
        ],
        "example": "await bcrypt.hash(pw, 12)  // 平文/高速ハッシュ(MD5等)での保管をやめる",
    },
    "security_misconfig": {
        "name": "セキュリティ設定不備",
        "cwe": "CWE-16 / CWE-756",
        "owasp": "OWASP A05:2021",
        "root_cause": "詳細エラーの露出・デフォルト設定・不要機能の有効化などの設定ミス。",
        "fixes": [
            "本番で詳細スタックトレースを無効化し、汎用エラーページに丸める。",
            "不要なサービス/エンドポイント/デフォルト資格情報を削除する。",
            "セキュリティヘッダ(CSP/HSTS/X-Content-Type-Options 等)を設定する。",
        ],
        "example": "app.set('env','production'); app.use(helmet());",
    },
    "csrf": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "cwe": "CWE-352",
        "owasp": "OWASP A01:2021",
        "root_cause": "状態変更リクエストに反CSRFトークンが無く、他サイトから強制実行できる。",
        "fixes": [
            "状態変更リクエストに反CSRFトークン(同期トークン)を要求する。",
            "クッキーに SameSite=Lax/Strict を設定する。",
        ],
        "example": "app.use(csrf()); // フォームに _csrf トークンを埋める",
    },
    "open_redirect": {
        "name": "Open Redirect",
        "cwe": "CWE-601",
        "owasp": "OWASP A01:2021",
        "root_cause": "リダイレクト先URLをユーザ入力から検証なしに決めている。",
        "fixes": [
            "リダイレクト先を相対パス、または許可リストのURLに限定する。",
            "外部ドメインへのリダイレクトを禁止する。",
        ],
        "example": "if (!target.startsWith('/')) target = '/';",
    },
}

# よくある別名・自然言語 → 正規クラスキー。モデルが finding の言い回しで渡してきても拾えるように。
_ALIASES = {
    "sql injection": "sqli", "sql": "sqli", "sqli": "sqli",
    "nosql injection": "nosqli", "nosql": "nosqli", "nosqli": "nosqli",
    "cross-site scripting": "xss", "cross site scripting": "xss", "xss": "xss",
    "idor": "broken_access_control", "access control": "broken_access_control",
    "broken access control": "broken_access_control", "authz": "broken_access_control",
    "authorization bypass": "broken_access_control", "authorisation bypass": "broken_access_control",
    "authorization": "broken_access_control", "認可バイパス": "broken_access_control",
    "info disclosure": "sensitive_data_exposure", "information disclosure": "sensitive_data_exposure",
    "sensitive data exposure": "sensitive_data_exposure", "data exposure": "sensitive_data_exposure",
    "file exposure": "sensitive_data_exposure", "directory listing": "sensitive_data_exposure",
    "機密ファイルの露出": "sensitive_data_exposure",
    "lfi": "path_traversal", "path traversal": "path_traversal",
    "directory traversal": "path_traversal", "traversal": "path_traversal",
    "ssrf": "ssrf",
    "ssti": "ssti", "template injection": "ssti",
    "xxe": "xxe",
    "deserialization": "insecure_deserialization", "insecure deserialization": "insecure_deserialization",
    "rce": "rce", "command injection": "rce", "os command injection": "rce",
    "remote code execution": "rce", "code injection": "rce",
    "auth": "weak_auth", "authentication": "weak_auth", "weak auth": "weak_auth",
    "brute force": "weak_auth", "broken authentication": "weak_auth",
    "misconfig": "security_misconfig", "misconfiguration": "security_misconfig",
    "security misconfiguration": "security_misconfig", "error handling": "security_misconfig",
    "csrf": "csrf",
    "open redirect": "open_redirect", "redirect": "open_redirect",
}


def _slug(title: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", title.lower()).strip("_") or "remediation"


def _resolve_class(raw: str) -> tuple[str | None, dict | None]:
    """Map a free-form vuln-class string to a curated KB entry. Try the exact
    key, then the alias table, then a substring scan so 'SQL injection in login'
    still resolves to sqli."""
    key = re.sub(r"[\s/_-]+", " ", raw.strip().lower()).strip()
    if not key:
        return None, None
    compact = key.replace(" ", "_")
    if compact in _KB:
        return compact, _KB[compact]
    if key in _ALIASES:
        canon = _ALIASES[key]
        return canon, _KB[canon]
    for alias, canon in _ALIASES.items():  # substring fallback
        if alias in key:
            return canon, _KB[canon]
    return None, None


def _build_markdown(rule: dict) -> str:
    lines = [f"# 修復アドバイス: {rule['title']}", ""]
    lines.append(f"- **脆弱性クラス**: {rule['class_name']} ({rule['cwe']})")
    lines.append(f"- **深刻度**: {rule['severity']} → **優先度 {rule['priority']}** — {rule['priority_note']}")
    lines.append(f"- **該当箇所**: {rule['location'] or '(未指定)'}")
    lines.append(f"- **参照**: {rule['owasp']}")
    lines.append("")
    lines.append("## 根本原因")
    lines.append(rule["root_cause"])
    if rule["detail"]:
        lines.append("")
        lines.append(f"観測された事実: {rule['detail']}")
    lines.append("")
    lines.append(f"## 修正手順(優先度 {rule['priority']})")
    for i, fix in enumerate(rule["fixes"], 1):
        lines.append(f"{i}. {fix}")
    if rule["example"]:
        lines.append("")
        lines.append("## 実装イメージ")
        lines.append("```")
        lines.append(rule["example"])
        lines.append("```")
    return "\n".join(lines) + "\n"


async def _run(args: dict, ctx: PluginContext) -> dict:
    title = str(args.get("title") or "").strip()
    if not title:
        return {"error": "title(直す対象の finding 名)を指定してください"}
    raw_class = str(args.get("vuln_class") or "").strip()
    if not raw_class:
        return {"error": "vuln_class を指定してください(例: sqli, xss, path_traversal, broken_access_control)"}

    notes: list[str] = []
    canon, kb = _resolve_class(raw_class)
    if kb is None:
        notes.append(
            f"未知の脆弱性クラス '{raw_class}' — 汎用の修復方針で出力しました。"
            f"既知クラス: {', '.join(sorted(_KB))}"
        )
        kb = {
            "name": raw_class,
            "cwe": "CWE-?",
            "owasp": "OWASP Top 10(該当項目を確認)",
            "root_cause": "(このクラスのキュレーション済み知識が未登録)",
            "fixes": [
                "入力を信頼せず、サーバ側で検証・エスケープ・認可チェックを行う。",
                "最小権限とデフォルト拒否の原則を適用する。",
                "該当CWE/OWASPの公式ガイダンスに従って恒久対策を実装する。",
            ],
            "example": "",
        }
        canon = raw_class

    severity = str(args.get("severity") or "medium").strip().lower()
    if severity not in _PRIORITY:
        notes.append(f"severity '{severity}' は不正なので medium にしました")
        severity = "medium"
    priority, priority_note = _PRIORITY[severity]

    rule = {
        "title": title,
        "class_key": canon,
        "class_name": kb["name"],
        "cwe": kb["cwe"],
        "owasp": kb["owasp"],
        "severity": severity,
        "priority": priority,
        "priority_note": priority_note,
        "location": str(args.get("location") or "").strip(),
        "detail": str(args.get("detail") or "").strip(),
        "root_cause": kb["root_cause"],
        "fixes": list(kb["fixes"]),
        "example": kb.get("example", ""),
    }

    markdown = _build_markdown(rule)

    saved_to = None
    if args.get("save", True):
        try:
            REMEDIATIONS_DIR.mkdir(exist_ok=True)
            path = REMEDIATIONS_DIR / f"{_slug(title)}.md"
            if path.exists():
                path = REMEDIATIONS_DIR / f"{_slug(title)}_{datetime.now().strftime('%H%M%S')}.md"
            path.write_text(markdown, encoding="utf-8")
            saved_to = str(path.relative_to(PROJECT_ROOT))
        except OSError as exc:
            notes.append(f"保存に失敗: {exc}")

    return {
        "title": title,
        "vuln_class": canon,
        "cwe": kb["cwe"],
        "severity": severity,
        "priority": priority,
        "fixes": rule["fixes"],
        "markdown": markdown,
        "saved_to": saved_to,
        "notes": notes,
    }


def _summary(result) -> str:
    if not isinstance(result, dict):
        return str(result)[:200]
    if result.get("error"):
        return result["error"]
    where = result.get("saved_to") or "(未保存)"
    n = len(result.get("fixes") or [])
    return f"[{result.get('priority')}] {result.get('title')} ({result.get('cwe')}) → 修正手順{n}件 / {where}"


PLUGIN = ToolPlugin(
    name="remediate",
    description=(
        "実証した finding に対する**修復アドバイス**(根本原因・具体的な修正手順・優先度・"
        "CWE/OWASP参照)を生成して手元の remediations/ に保存する(防御側/ブルー視点)。"
        "脆弱性を『見つけた』で終わらせず、開発者がそのまま直せる形にする。finding を1つ"
        "確定させたら、その脆弱性クラスでこのツールを呼んで修正案も添えるとよい。"
        "vuln_class は既知クラス(sqli, nosqli, xss, broken_access_control, "
        "sensitive_data_exposure, path_traversal, ssrf, ssti, xxe, "
        "insecure_deserialization, rce, weak_auth, security_misconfig, csrf, "
        "open_redirect)から選ぶ。優先度は severity から自動決定。対象ホストには接触しない。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "直す対象の finding 名(例: 'Login の SQLi による認証バイパス')"},
            "vuln_class": {
                "type": "string",
                "description": (
                    "脆弱性クラス。既知キー: sqli, nosqli, xss, broken_access_control, "
                    "sensitive_data_exposure, path_traversal, ssrf, ssti, xxe, "
                    "insecure_deserialization, rce, weak_auth, security_misconfig, csrf, open_redirect"
                ),
            },
            "severity": {
                "type": "string",
                "description": "深刻度: critical/high/medium/low/info(finding と揃える。既定 medium)。優先度P0-P3に変換される",
            },
            "location": {"type": "string", "description": "該当箇所(例: 'POST /rest/user/login の email パラメータ')"},
            "detail": {"type": "string", "description": "対象固有の観測事実(任意。使ったpayloadや返ってきた挙動など)"},
            "save": {"type": "boolean", "description": "remediations/ に保存するか(既定 true)"},
        },
        "required": ["title", "vuln_class"],
    },
    run=_run,
    summary=_summary,
    scope_targets=lambda args: [],  # 手元にファイルを書くだけ。対象ホストに接触しない
)
