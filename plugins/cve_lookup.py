"""cve_lookup — recon の「製品名 + バージョン」から既知CVE/エクスプロイト候補を引く。

recon→exploit の橋渡し。「ポートは開いてる、で止まる」を防ぐための攻撃補助ツール。

データ源は2段フォールバック:
1. ローカルに `searchsploit`(exploit-db)があればそれを使う
   → オフラインで動き、実際のエクスプロイトのパスまで分かる(最も実戦的)
2. 無ければ NVD の公開API(キー不要)に問い合わせて CVE 候補を返す
どちらも使えなければ、その旨を notes で返す。

このツールは**演習ホスト自体には接触しない**(外部のCVE DBを引くだけ)ので、
scope_targets は空 = スコープ強制の対象外。
"""

from __future__ import annotations

import json
import shlex

from sikun.plugins import PluginContext, ToolPlugin


def _extract_json(raw: str) -> str:
    """Pull the JSON object out of raw shell output. The persistent shell
    prefixes results with `[exit=N]` and tools can emit banners, so slice from
    the first '{' to the last '}' rather than json.loads-ing the whole blob."""
    if not raw:
        return ""
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        return ""
    return raw[start : end + 1]


def _parse_searchsploit_json(raw: str, max_results: int) -> list[dict]:
    blob = _extract_json(raw)
    if not blob:
        return []
    try:
        data = json.loads(blob)
    except (ValueError, TypeError):
        return []
    out: list[dict] = []
    for item in (data.get("RESULTS_EXPLOIT") or [])[:max_results]:
        out.append(
            {
                "source": "exploit-db",
                "id": item.get("EDB-ID") or "",
                "title": (item.get("Title") or "").strip(),
                "path": item.get("Path") or "",
            }
        )
    return out


def _parse_nvd_json(raw: str, max_results: int) -> list[dict]:
    blob = _extract_json(raw)
    if not blob:
        return []
    try:
        data = json.loads(blob)
    except (ValueError, TypeError):
        return []
    out: list[dict] = []
    for entry in (data.get("vulnerabilities") or [])[:max_results]:
        cve = (entry or {}).get("cve") or {}
        description = ""
        for d in cve.get("descriptions") or []:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        severity, score = "", None
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if arr:
                cvss = (arr[0] or {}).get("cvssData") or {}
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity") or (arr[0] or {}).get("baseSeverity") or ""
                break
        out.append(
            {
                "source": "nvd",
                "id": cve.get("id", ""),
                "severity": severity,
                "score": score,
                "title": description[:200],
            }
        )
    return out


def _build_query(args: dict) -> str:
    product = str(args.get("product") or args.get("service") or "").strip()
    version = str(args.get("version") or "").strip()
    return " ".join(p for p in (product, version) if p).strip()


async def _run(args: dict, ctx: PluginContext) -> dict:
    query = _build_query(args)
    if not query:
        return {"error": "product(または service)を指定してください"}
    try:
        max_results = int(args.get("max_results") or 15)
    except (TypeError, ValueError):
        max_results = 15
    max_results = max(1, min(max_results, 50))

    candidates: list[dict] = []
    sources_tried: list[str] = []
    notes: list[str] = []

    # 1) searchsploit(あれば)— オフラインで実際のexploitパスまで分かる
    which = await ctx.run("command -v searchsploit || echo none")
    if "none" not in which.split():
        sources_tried.append("searchsploit")
        raw = await ctx.run(f"searchsploit --json {shlex.quote(query)} 2>/dev/null")
        candidates.extend(_parse_searchsploit_json(raw, max_results))
    else:
        notes.append("searchsploit 未インストール(exploit-db検索はスキップ)")

    # 2) NVD 公開API — searchsploit で埋まらない分を補う
    if len(candidates) < max_results:
        remaining = max_results - len(candidates)
        sources_tried.append("nvd")
        nvd_cmd = (
            "curl -sS -G --max-time 20 "
            "https://services.nvd.nist.gov/rest/json/cves/2.0 "
            f"--data-urlencode {shlex.quote('keywordSearch=' + query)} "
            f"--data-urlencode {shlex.quote('resultsPerPage=' + str(remaining))} "
            "2>/dev/null"
        )
        raw = await ctx.run(nvd_cmd)
        nvd = _parse_nvd_json(raw, remaining)
        if not nvd:
            notes.append("NVDからの結果なし(ネットワーク制限、curl未導入、またはヒットなし)")
        candidates.extend(nvd)

    return {
        "query": query,
        "count": len(candidates),
        "candidates": candidates,
        "sources_tried": sources_tried,
        "notes": notes,
    }


def _summary(result) -> str:
    if not isinstance(result, dict):
        return str(result)[:200]
    if result.get("error"):
        return result["error"]
    head = ", ".join(
        (c.get("id") or c.get("title", "")[:30]) for c in (result.get("candidates") or [])[:5]
    )
    count = result.get("count", 0)
    return f"{count}件" + (f": {head}" if head else "") + (" ..." if count > 5 else "")


PLUGIN = ToolPlugin(
    name="cve_lookup",
    description=(
        "nmap_scan/http_probe で判明した**ミドルウェア/サービスの製品名+バージョン**から、"
        "既知のCVE/エクスプロイト候補を検索して構造化して返す(recon→exploitの橋渡し)。"
        "重要: 渡すのは対象アプリの通称(例: dvwa, wordpressサイト名)ではなく、その裏で動く"
        "ソフトの製品名(例: apache, nginx, openssh, mysql, php, vsftpd)。http_probe の server "
        "フィールドや nmap_scan の version からバージョンも一緒に渡すとヒット率が上がる。"
        "ローカルに searchsploit があれば優先し、無ければ NVD 公開APIに問い合わせる。"
        "演習ホスト自体には接触しない。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "product": {
                "type": "string",
                "description": (
                    "ミドルウェア/サービスの製品名(例: apache, nginx, openssh, mysql, php, vsftpd)。"
                    "対象アプリの通称ではなくその裏で動くソフト名を渡す"
                ),
            },
            "version": {
                "type": "string",
                "description": "バージョン(例: 2.3.4)。分かれば指定するとヒット精度が上がる",
            },
            "max_results": {"type": "integer", "description": "最大件数(既定15・上限50)"},
        },
        "required": ["product"],
    },
    run=_run,
    summary=_summary,
    scope_targets=lambda args: [],  # 外部CVE DBを引くだけ。演習ホストに接触しない
)
