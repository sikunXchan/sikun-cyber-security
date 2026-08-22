"""mobsf — MobSF(Mobile Security Framework)を REST API 経由で構造化ツールにする(モバイルアプリ解析)。

狙い: SCS は Web/ネットワーク(nmap/http_probe/metasploit)と汎用バイナリ(Ghidra)は扱えるが、
**モバイルアプリ(APK/IPA/APPX)専用の解析**が抜けていた。MobSF はアップロード→静的解析→JSONレポート
取得という一連の操作を REST API だけで完結できる自動解析エンジンなので、Ghidra と同じ「ユーザーが
持ち込んだ成果物を解析する」思想でプラグイン化する。動的解析(エミュレータ必須)やiOS/Android実機系の
API は対象外(重すぎる・環境依存が強すぎる)。あくまで**静的解析**のみ。

エンドポイント・パラメータ名は MobSF 本体のソース(urls.py / views/api/api_static_analysis.py /
views/scanning.py / views/android/*.py)を実際に読んで確認済み:
- POST /api/v1/upload      multipart file= → {hash, scan_type, ...}
- POST /api/v1/scan        form hash=<md5>&re_scan=0|1 → フルレポートJSON(重い。キャッシュされ、
                            re_scan=0(既定)なら2回目以降は再解析されない)
- POST /api/v1/scorecard   form hash=<md5> → {security_score: 0-100, ...}
- GET  /api/v1/scans       ?page=&page_size= → {content: [...], count, num_pages}
  (RecentScansDB のフィールド名は大文字: MD5/FILE_NAME/APP_NAME/PACKAGE_NAME/SCAN_TYPE/TIMESTAMP)
- 認証ヘッダは `Authorization: <api_key>`

実装上の重要な注意(実際に踏んだ設計判断):
- **フルレポートJSONは巨大**(コード解析結果・マニフェスト・証明書情報等で数百KB〜数MB)。
  PersistentShell.run() は出力を末尾 MAX_OUTPUT_CHARS(8000字)に切り詰めるため、生のレポートを
  そのまま ctx.run 経由で受け取ると JSON が壊れる。そこで `/api/v1/scan` の結果は
  `curl -o <file>` で ctx.run 先のホストに直接書き出させ、ctx.run の戻り値には触れさせない。
  その後、同じホスト上で python3 の小さなスクリプト(heredocで書き出し。Ghidraプラグインの
  Java スクリプト書き出しと同じ手法)にレポートを読ませ、**厳選した要点だけ**を印字させる。
  これは cve_lookup.py が「NVDの冗長なJSONを grep でソース側で削ってから受け取る」のと同じ設計。
- MobSF未導入/未起動、APIキー未設定、アップロード対象ファイル不在は、どれもクラッシュせず
  明確なエラーを返す。

対象ホストには接触しない(MobSFサーバー自体はオペレーター側で動かす想定。手元のアプリファイルを
渡して解析するだけ)ので scope_targets は空。

正直な限界: 本開発環境に MobSF が導入されていないため、API仕様はソースコードで裏取り済みだが
**生きたMobSFサーバーとの実通信は未検証**。導入環境での実機確認が必要。
"""

from __future__ import annotations

import json
import os
import shlex

from sikun.plugins import PluginContext, ToolPlugin

_DEFAULT_URL = "http://127.0.0.1:8000"
_WORK_DIR = "/tmp/sikun_mobsf"
_REPORT_FILE = _WORK_DIR + "/report.json"
_DIGEST_SCRIPT = _WORK_DIR + "/digest.py"

# レポートJSONから要点だけを抜き出すスクリプト。フィールド名は MobSF ソース
# (db_interaction.py / code_analysis.py / cert_analysis.py)で確認済み。
# 引数: [1]=report.jsonのパス [2]=security_score(int文字列 or "none")
_DIGEST_PY = '''import sys, json

report_path = sys.argv[1]
raw_score = sys.argv[2] if len(sys.argv) > 2 else "none"
try:
    security_score = int(raw_score)
except ValueError:
    security_score = None

try:
    with open(report_path, encoding="utf-8", errors="replace") as f:
        report = json.load(f)
except Exception as exc:
    print(json.dumps({"error": "レポートJSONの読み込みに失敗: %s" % exc}))
    sys.exit(0)

if isinstance(report, dict) and report.get("error"):
    print(json.dumps({"error": str(report.get("error"))}))
    sys.exit(0)

def band(score):
    if score is None:
        return "unknown"
    if score < 30:
        return "critical"
    if score < 40:
        return "high"
    if score < 60:
        return "medium"
    return "low"

perms = report.get("permissions") or {}
dangerous = [k for k, v in perms.items() if isinstance(v, dict) and v.get("status") == "dangerous"]

code = report.get("code_analysis") or {}
summary = code.get("summary") or {}
findings = code.get("findings") or {}
top_high = []
for rule, d in findings.items():
    meta = (d or {}).get("metadata") or {}
    if meta.get("severity") == "high":
        top_high.append(meta.get("description") or rule)
top_high = top_high[:6]

cert = report.get("certificate_analysis") or {}
cert_issues = []
for item in (cert.get("certificate_findings") or []):
    if isinstance(item, (list, tuple)) and len(item) >= 2:
        cert_issues.append(str(item[-1]))
cert_issues = cert_issues[:6]

trackers = report.get("trackers")
if isinstance(trackers, dict):
    tracker_count = trackers.get("detected_trackers", len(trackers))
elif isinstance(trackers, list):
    tracker_count = len(trackers)
else:
    tracker_count = None

exported = report.get("exported_activities")
exported_count = len(exported) if isinstance(exported, list) else (exported if isinstance(exported, int) else None)

urls = report.get("urls")
if not isinstance(urls, list):
    urls = code.get("urls") if isinstance(code.get("urls"), list) else []

digest = {
    "app_name": report.get("app_name"),
    "package_name": report.get("package_name"),
    "version_name": report.get("version_name"),
    "file_name": report.get("file_name"),
    "scan_type": report.get("scan_type") or report.get("type"),
    "security_score": security_score,
    "risk": band(security_score),
    "permission_count": len(perms),
    "dangerous_permissions": dangerous[:20],
    "code_findings": {
        "high": summary.get("high", 0),
        "warning": summary.get("warning", 0),
        "info": summary.get("info", 0),
        "secure": summary.get("secure", 0),
    },
    "top_high_severity_findings": top_high,
    "certificate_issues": cert_issues,
    "tracker_count": tracker_count,
    "exported_component_count": exported_count,
    "url_count": len(urls) if isinstance(urls, list) else None,
}
print(json.dumps(digest, ensure_ascii=False))
'''


def _config() -> tuple[str, str | None]:
    url = (os.environ.get("MOBSF_URL") or _DEFAULT_URL).rstrip("/")
    key = os.environ.get("MOBSF_API_KEY")
    return url, key


def _extract_json(raw: str) -> str:
    """ctx.run の戻り値([exit=N]プレフィックスや余計な行が混ざりうる)から
    JSON本体らしき範囲だけを切り出す。cve_lookup.py と同じ考え方。"""
    if not raw:
        return ""
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        return ""
    return raw[start : end + 1]


async def _reachable(ctx: PluginContext, url: str) -> bool:
    out = await ctx.run(
        f"curl -sS --max-time 5 -o /dev/null -w '%{{http_code}}' {shlex.quote(url + '/')} 2>/dev/null"
    )
    code = (out or "").strip().splitlines()[-1] if out else ""
    return code.isdigit() and code != "000"


async def _ensure_ready(ctx: PluginContext, need_key: bool = True) -> dict | None:
    """MobSFのURL/APIキー/疎通を確認する。問題があれば説明的な error dict を返す(None なら準備OK)。"""
    url, key = _config()
    if need_key and not key:
        return {
            "error": (
                "MOBSF_API_KEY が未設定です。MobSF管理画面の 'API Docs' で表示されるキーを "
                ".env に MOBSF_API_KEY=... として設定してください(MOBSF_URL も既定値以外なら設定)。"
            )
        }
    if not await _reachable(ctx, url):
        return {
            "error": (
                f"MobSF({url})に接続できません。MobSF サーバーが起動しているか確認してください"
                "(例: docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf、"
                "または pip でのローカル起動)。別ホスト/ポートなら環境変数 MOBSF_URL で指定できます。"
            )
        }
    return None


async def _run_scan(args: dict, ctx: PluginContext) -> dict:
    file_path = str(args.get("file_path") or "").strip()
    if not file_path:
        return {"error": "file_path(解析するAPK/IPA/APPXのパス)を指定してください"}
    re_scan = "1" if args.get("re_scan") else "0"

    err = await _ensure_ready(ctx)
    if err:
        return err
    url, key = _config()

    exists = (await ctx.run(f"test -f {shlex.quote(file_path)} && echo yes || echo no")).split()
    if "yes" not in exists:
        return {"error": f"ファイルが見つかりません: {file_path}(MobSFが動くホスト上のパスを指定)"}

    await ctx.run(f"mkdir -p {shlex.quote(_WORK_DIR)} && rm -f {shlex.quote(_REPORT_FILE)}")

    # 1) アップロード(小さいレスポンス。ctx.run 経由で直接受け取ってよい)
    upload_raw = await ctx.run(
        f"curl -sS --max-time 120 -H {shlex.quote('Authorization: ' + key)} "
        f"-F {shlex.quote('file=@' + file_path)} {shlex.quote(url + '/api/v1/upload')}"
    )
    upload_json = _extract_json(upload_raw)
    if not upload_json:
        return {"error": "アップロードのレスポンスを解析できませんでした", "raw": (upload_raw or "")[-500:]}
    try:
        upload_resp = json.loads(upload_json)
    except ValueError:
        return {"error": "アップロードのレスポンスがJSONとして不正でした", "raw": upload_json[:500]}
    if upload_resp.get("error"):
        return {"error": f"アップロード失敗: {upload_resp['error']}"}
    file_hash = upload_resp.get("hash")
    if not file_hash:
        return {"error": "アップロード応答に hash が含まれていません", "raw": upload_resp}

    # 2) 静的解析実行(レスポンスは巨大なので直接ファイルへ書き出す。ctx.run の戻り値には
    #    HTTPステータスコードだけを流す=8000字切り詰めトラップを回避)
    scan_status = await ctx.run(
        f"curl -sS --max-time 900 -H {shlex.quote('Authorization: ' + key)} "
        f"-d {shlex.quote('hash=' + file_hash)} -d {shlex.quote('re_scan=' + re_scan)} "
        f"-o {shlex.quote(_REPORT_FILE)} -w '%{{http_code}}' {shlex.quote(url + '/api/v1/scan')}"
    )
    status_code = (scan_status or "").strip().splitlines()[-1] if scan_status else ""
    if status_code and status_code not in ("200",):
        tail = await ctx.run(f"tail -c 500 {shlex.quote(_REPORT_FILE)} 2>/dev/null")
        return {"error": f"静的解析に失敗しました(HTTP {status_code})", "detail": (tail or "")[:500]}

    # 3) スコアカード(小さいレスポンス)
    score_raw = await ctx.run(
        f"curl -sS --max-time 30 -H {shlex.quote('Authorization: ' + key)} "
        f"-d {shlex.quote('hash=' + file_hash)} {shlex.quote(url + '/api/v1/scorecard')}"
    )
    score_json = _extract_json(score_raw)
    security_score = None
    if score_json:
        try:
            security_score = json.loads(score_json).get("security_score")
        except ValueError:
            pass

    # 4) レポートを要約(python3 スクリプトをホスト側に書き出して実行。巨大なJSONを
    #    そのまま ctx.run の戻り値に乗せない)
    await ctx.run(
        f"cat > {shlex.quote(_DIGEST_SCRIPT)} << 'SIKUN_MOBSF_EOF'\n{_DIGEST_PY}\nSIKUN_MOBSF_EOF"
    )
    score_arg = str(security_score) if isinstance(security_score, int) else "none"
    digest_raw = await ctx.run(
        f"python3 {shlex.quote(_DIGEST_SCRIPT)} {shlex.quote(_REPORT_FILE)} {shlex.quote(score_arg)}"
    )
    digest_json = _extract_json(digest_raw)
    if not digest_json:
        return {
            "error": "レポートの要約に失敗しました(python3 が無い、またはレポート形式が想定外)。",
            "hash": file_hash,
            "log_tail": (digest_raw or "")[-500:],
        }
    try:
        digest = json.loads(digest_json)
    except ValueError:
        return {"error": "要約結果がJSONとして不正でした", "hash": file_hash, "raw": digest_json[:500]}
    if digest.get("error"):
        digest["hash"] = file_hash
        return digest

    digest["hash"] = file_hash
    digest["note"] = (
        f"詳細な生レポートは MobSF の Web UI({url}/recent_scans/)で hash={file_hash} を開けば見られる。"
        "危険な権限・high severityの findings・証明書の問題を優先して説明すること。"
    )
    return digest


async def _run_scans(args: dict, ctx: PluginContext) -> dict:
    err = await _ensure_ready(ctx)
    if err:
        return err
    url, key = _config()
    try:
        limit = int(args.get("limit") or 10)
    except (TypeError, ValueError):
        limit = 10
    limit = max(1, min(limit, 50))

    raw = await ctx.run(
        f"curl -sS --max-time 15 -H {shlex.quote('Authorization: ' + key)} "
        f"{shlex.quote(url + '/api/v1/scans?page=1&page_size=' + str(limit))}"
    )
    body = _extract_json(raw)
    if not body:
        return {"error": "スキャン一覧の取得に失敗しました", "raw": (raw or "")[-500:]}
    try:
        resp = json.loads(body)
    except ValueError:
        return {"error": "スキャン一覧のレスポンスがJSONとして不正でした", "raw": body[:500]}
    if resp.get("error"):
        return {"error": resp["error"]}

    items = []
    for row in resp.get("content") or []:
        items.append(
            {
                "hash": row.get("MD5"),
                "app_name": row.get("APP_NAME"),
                "file_name": row.get("FILE_NAME"),
                "package_name": row.get("PACKAGE_NAME"),
                "scan_type": row.get("SCAN_TYPE"),
                "timestamp": row.get("TIMESTAMP"),
            }
        )
    return {"count": resp.get("count", len(items)), "scans": items}


def _sum_scan(result) -> str:
    if not isinstance(result, dict):
        return str(result)[:200]
    if result.get("error"):
        return result["error"]
    cf = result.get("code_findings") or {}
    return (
        f"[{result.get('risk')}] {result.get('app_name') or result.get('file_name')} "
        f"score={result.get('security_score')} "
        f"findings(high={cf.get('high', 0)}/warn={cf.get('warning', 0)}) "
        f"危険な権限{len(result.get('dangerous_permissions') or [])}件"
    )


def _sum_scans(result) -> str:
    if not isinstance(result, dict):
        return str(result)[:200]
    if result.get("error"):
        return result["error"]
    return f"{result.get('count', 0)}件のスキャン履歴"


PLUGINS = [
    ToolPlugin(
        name="mobsf_scan",
        description=(
            "MobSF(Mobile Security Framework)にモバイルアプリ(APK/IPA/APPX)をアップロードして"
            "静的解析を実行し、結果を要約して返す(権限・危険な権限・コード解析findings件数・"
            "high severity上位・証明書の問題・トラッカー数・セキュリティスコア0-100)。"
            "ソースの無いモバイルアプリを診断・監査するのに使う(ソースがあるならstudyモードで"
            "直接ソースを読む方がよい)。同じファイルの2回目以降はキャッシュされ高速(re_scanで強制再解析)。"
            "対象ホストには接触しない。要 MobSF サーバー起動(MOBSF_URL、既定 http://127.0.0.1:8000)"
            "と MOBSF_API_KEY 環境変数。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "解析するAPK/IPA/APPXのパス(MobSFが動くホスト上のパス)"},
                "re_scan": {"type": "boolean", "description": "trueで強制的に再解析(既定false=キャッシュがあれば利用)"},
            },
            "required": ["file_path"],
        },
        run=_run_scan,
        summary=_sum_scan,
        scope_targets=lambda args: [],
    ),
    ToolPlugin(
        name="mobsf_scans",
        description=(
            "MobSF に保存されている直近のスキャン履歴(hash・アプリ名・パッケージ名・種別・日時)を"
            "一覧する。以前解析したアプリのhashを再確認したい時や、何をスキャン済みか把握したい時に使う。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "最大件数(既定10・上限50)"},
            },
        },
        run=_run_scans,
        summary=_sum_scans,
        scope_targets=lambda args: [],
    ),
]
