"""metasploit — Metasploit Framework を RPC 経由で構造化ツールとして操作する(フル連携)。

これまで msf 連携は実体が無く、生 bash で `msfconsole -x` を叩くしかなかった(遅い・壊れやすい・
セッションが継続しない)。ここでは msfrpcd + pymetasploit3 で**永続接続**を張り、モジュール検索・
実行から meterpreter/シェルのセッション管理・ポストエクスプロイトまでを構造化して扱う。

設計上の要点:
- 接続クライアントは**モジュールレベルのシングルトン**として保持する。プラグインは SCS の1セッション
  中ロードされ続けるので、あるターンで開いたセッションが後続ターンでも生きている(RPCデーモン側で
  維持される)。これが「バッチ実行では持てない永続セッション」を可能にする核。
- 対象に触れる `msf_run` は `scope_targets` に RHOSTS を宣言 → ScopeGuard が範囲外を実行前ハードブロック。
- msfrpcd は SCS と同じホスト(ローカル)で起動し 127.0.0.1 に接続する前提。SSHピボット越しの
  リモート msf を使う場合はポートフォワードが別途必要(notes で案内)。
- Metasploit / pymetasploit3 が無い、デーモンに繋がらない場合は**クラッシュせず**明確なエラーを返す。
"""

from __future__ import annotations

import secrets

from sikun.plugins import PluginContext, ToolPlugin

_RPC_HOST = "127.0.0.1"
_RPC_PORT = 55553
_RPC_USER = "msf"
# セッション限りのランダムなRPCパスワード(平文の固定値を避ける)。
_RPC_PASS = secrets.token_urlsafe(18)

# 検証済み: pymetasploit3 のモジュール名は type プレフィックス無しの短縮名を使う
# (client.modules.use('exploit', 'unix/ftp/vsftpd_234_backdoor'))。
_MODULE_TYPES = ("exploit", "auxiliary", "post", "payload", "encoder", "nop", "evasion")

# 接続シングルトン(プロセス内で使い回す)
_client = None


def _split_module(name: str) -> tuple[str | None, str]:
    """'exploit/unix/ftp/vsftpd_234_backdoor' → ('exploit', 'unix/ftp/...')。
    プレフィックスが無ければ type 不明として (None, name) を返す。"""
    name = (name or "").strip().strip("/")
    if "/" in name:
        head, rest = name.split("/", 1)
        if head in _MODULE_TYPES:
            return head, rest
    return None, name


def _parse_options(text: str) -> dict:
    """'RHOSTS=1.2.3.4, RPORT=21, SSL=false' 形式を dict に。値にコロン等を含めても
    最初の '=' で割るのでパスやURLも渡せる。"""
    opts: dict = {}
    if not text:
        return opts
    # カンマ or 改行区切りのどちらでも受ける
    for chunk in text.replace("\n", ",").split(","):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        k, v = chunk.split("=", 1)
        k, v = k.strip(), v.strip()
        if k:
            opts[k] = v
    return opts


async def _msfrpcd_present(ctx: PluginContext) -> bool:
    out = await ctx.run("command -v msfrpcd || echo none")
    return "none" not in out.split()


async def _port_is_up(ctx: PluginContext) -> bool:
    out = await ctx.run(
        f"(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ':{_RPC_PORT} ' "
        "&& echo up || echo down"
    )
    return "up" in out.split()


def _connect():
    """pymetasploit3 で msfrpcd に接続(-S 起動=SSL無しに合わせ ssl=False)。
    成功で MsfRpcClient、失敗で例外。"""
    from pymetasploit3.msfrpc import MsfRpcClient

    return MsfRpcClient(
        _RPC_PASS, username=_RPC_USER, server=_RPC_HOST, port=_RPC_PORT, ssl=False
    )


async def _ensure_client(ctx: PluginContext):
    """RPCクライアントを用意して返す。返り値は (client, error_dict)。
    どこかで詰まったら client=None と、利用者が次に何をすべきか分かる error を返す。"""
    global _client

    try:
        import pymetasploit3  # noqa: F401
    except ImportError:
        return None, {
            "error": "pymetasploit3 が未インストールです。`pip install pymetasploit3` を実行してください。"
        }

    # 既存接続が生きていれば再利用(core.version で疎通確認)
    if _client is not None:
        try:
            _client.core.version
            return _client, None
        except Exception:
            _client = None  # 切れていた → 張り直す

    if not await _msfrpcd_present(ctx):
        return None, {
            "error": (
                "metasploit-framework が見つかりません(msfrpcd 不在)。"
                "Kali なら既定で導入済み、Debian/Ubuntu 系は公式インストーラや "
                "`apt install metasploit-framework` で導入してください。"
            )
        }

    # デーモンが未起動なら起動して待つ(初回はフレームワーク読み込みで20〜40秒かかる)
    if not await _port_is_up(ctx):
        await ctx.run(
            f"nohup msfrpcd -P {_RPC_PASS} -U {_RPC_USER} -S -a {_RPC_HOST} -p {_RPC_PORT} "
            ">/tmp/sikun_msfrpcd.log 2>&1 & echo started"
        )
        up = False
        for _ in range(20):  # 最大 ~40秒
            await ctx.run("sleep 2")
            if await _port_is_up(ctx):
                up = True
                break
        if not up:
            return None, {
                "error": (
                    "msfrpcd を起動しましたが応答しません(/tmp/sikun_msfrpcd.log を確認)。"
                    "初回は起動が遅いので、少し待ってからもう一度呼んでください。"
                )
            }

    try:
        _client = _connect()
    except Exception as exc:
        return None, {"error": f"msfrpcd への接続に失敗しました: {exc}"}
    return _client, None


# ---------------------------------------------------------------------------
# ツール実装
# ---------------------------------------------------------------------------
async def _run_search(args: dict, ctx: PluginContext) -> dict:
    query = str(args.get("query") or "").strip()
    if not query:
        return {"error": "query を指定してください(例: 'vsftpd', 'CVE-2011-2523', 'samba')"}
    try:
        limit = int(args.get("limit") or 15)
    except (TypeError, ValueError):
        limit = 15
    limit = max(1, min(limit, 50))

    client, err = await _ensure_client(ctx)
    if err:
        return err
    try:
        results = client.modules.search(query) or []
    except Exception as exc:
        return {"error": f"検索に失敗しました: {exc}"}

    modules = [
        {
            "type": r.get("type"),
            "name": r.get("fullname") or f"{r.get('type')}/{r.get('name')}",
            "rank": r.get("rank"),
            "disclosure_date": r.get("disclosure_date"),
            "description": (r.get("description") or "").strip()[:200],
        }
        for r in results[:limit]
    ]
    return {"query": query, "count": len(modules), "total": len(results), "modules": modules}


async def _run_info(args: dict, ctx: PluginContext) -> dict:
    raw = str(args.get("module") or "").strip()
    if not raw:
        return {"error": "module を指定してください(例: 'exploit/unix/ftp/vsftpd_234_backdoor')"}
    mtype, mname = _split_module(raw)
    mtype = mtype or str(args.get("module_type") or "exploit").strip()

    client, err = await _ensure_client(ctx)
    if err:
        return err
    try:
        mod = client.modules.use(mtype, mname)
    except Exception as exc:
        return {"error": f"モジュールの取得に失敗しました({mtype}/{mname}): {exc}"}

    info = {}
    try:
        info = mod.info or {}
    except Exception:
        pass
    result = {
        "module": f"{mtype}/{mname}",
        "name": info.get("name") or getattr(mod, "name", ""),
        "rank": info.get("rank") or getattr(mod, "rank", ""),
        "description": (info.get("description") or "").strip(),
        "options": list(getattr(mod, "options", []) or []),
        "required": list(getattr(mod, "required", []) or []),
    }
    if mtype == "exploit":
        try:
            result["targets"] = mod.targets
            result["payloads"] = list(mod.payloads or [])[:20]
        except Exception:
            pass
    return result


async def _run_exploit(args: dict, ctx: PluginContext) -> dict:
    raw = str(args.get("module") or "").strip()
    rhosts = str(args.get("rhosts") or "").strip()
    if not raw:
        return {"error": "module を指定してください"}
    if not rhosts:
        return {"error": "rhosts(対象)を指定してください"}
    mtype, mname = _split_module(raw)
    mtype = mtype or str(args.get("module_type") or "exploit").strip()
    payload = str(args.get("payload") or "").strip()
    options = _parse_options(str(args.get("options") or ""))

    client, err = await _ensure_client(ctx)
    if err:
        return err
    try:
        mod = client.modules.use(mtype, mname)
    except Exception as exc:
        return {"error": f"モジュールの取得に失敗しました({mtype}/{mname}): {exc}"}

    # 対象と任意オプションを設定(dict風の代入)
    try:
        mod["RHOSTS"] = rhosts
        for k, v in options.items():
            mod[k] = v
    except Exception as exc:
        return {"error": f"オプション設定に失敗しました: {exc}"}

    # 実行前の既存セッションIDを控え、後で新規に開いたものだけを差分検出する
    try:
        before = set((client.sessions.list or {}).keys())
    except Exception:
        before = set()

    try:
        exec_result = mod.execute(payload=payload) if payload else mod.execute()
    except Exception as exc:
        return {"error": f"モジュール実行に失敗しました: {exc}"}

    # exploit はジョブ非同期なので、新規セッションが開くのを少し待って差分を取る
    new_sessions: list = []
    if mtype in ("exploit", "auxiliary"):
        for _ in range(6):  # 最大 ~12秒
            await ctx.run("sleep 2")
            try:
                current = client.sessions.list or {}
            except Exception:
                current = {}
            new_ids = [sid for sid in current if sid not in before]
            if new_ids:
                new_sessions = [
                    {
                        "id": sid,
                        "type": current[sid].get("type"),
                        "target_host": current[sid].get("target_host") or current[sid].get("session_host"),
                        "info": current[sid].get("info"),
                        "via": current[sid].get("via_exploit"),
                    }
                    for sid in new_ids
                ]
                break

    return {
        "module": f"{mtype}/{mname}",
        "rhosts": rhosts,
        "payload": payload or None,
        "execute": exec_result,  # {'job_id':..,'uuid':..} 等
        "opened_session": bool(new_sessions),
        "sessions": new_sessions,
        "note": (
            "セッションが開いた場合は msf_sessions / msf_session_run で継続操作できる。"
            if new_sessions
            else "新規セッションは検出されなかった(auxiliary、遅延、または失敗の可能性)。"
            "msf_sessions で後追い確認するか、返り値と対象の状態を確認すること。"
        ),
    }


async def _run_sessions(args: dict, ctx: PluginContext) -> dict:
    client, err = await _ensure_client(ctx)
    if err:
        return err
    try:
        sessions = client.sessions.list or {}
    except Exception as exc:
        return {"error": f"セッション一覧の取得に失敗しました: {exc}"}
    out = [
        {
            "id": sid,
            "type": s.get("type"),
            "target_host": s.get("target_host") or s.get("session_host"),
            "tunnel_peer": s.get("tunnel_peer"),
            "info": s.get("info"),
            "via": s.get("via_exploit"),
        }
        for sid, s in sessions.items()
    ]
    return {"count": len(out), "sessions": out}


async def _run_session_cmd(args: dict, ctx: PluginContext) -> dict:
    sid = str(args.get("session_id") or "").strip()
    cmd = str(args.get("command") or "").strip()
    if not sid or not cmd:
        return {"error": "session_id と command の両方を指定してください"}

    client, err = await _ensure_client(ctx)
    if err:
        return err
    try:
        sessions = client.sessions.list or {}
    except Exception as exc:
        return {"error": f"セッション情報の取得に失敗しました: {exc}"}
    # RPCのキーは文字列/数値どちらもありうるので両対応
    key = sid if sid in sessions else (int(sid) if sid.isdigit() and int(sid) in sessions else None)
    if key is None:
        return {"error": f"セッション {sid} が見つかりません。msf_sessions で現在のIDを確認してください。"}

    stype = str(sessions[key].get("type") or "")
    try:
        sess = client.sessions.session(key)
    except Exception as exc:
        return {"error": f"セッション {sid} の取得に失敗しました: {exc}"}

    try:
        if stype == "meterpreter":
            # meterpreter はコマンド種別に依らず出力収集付きで実行
            output = sess.run_with_output(cmd, timeout=60)
        else:
            # shell セッションはプロンプト終端が無いので end_strs は使わず短めに収集
            sess.write(cmd + "\n")
            await ctx.run("sleep 2")
            output = sess.read()
    except Exception as exc:
        return {"error": f"コマンド実行に失敗しました: {exc}"}

    return {
        "session_id": sid,
        "session_type": stype,
        "command": cmd,
        "output": (output or "")[:4000],
    }


# ---------------------------------------------------------------------------
# サマリ(TUIの1行プレビュー)
# ---------------------------------------------------------------------------
def _sum_search(r) -> str:
    if not isinstance(r, dict) or r.get("error"):
        return r.get("error", str(r)[:200]) if isinstance(r, dict) else str(r)[:200]
    head = ", ".join(m["name"] for m in (r.get("modules") or [])[:3])
    return f"{r.get('count')}/{r.get('total')}件" + (f": {head} ..." if head else "")


def _sum_info(r) -> str:
    if not isinstance(r, dict) or r.get("error"):
        return r.get("error", "") if isinstance(r, dict) else str(r)[:200]
    return f"{r.get('module')} — required: {', '.join(r.get('required') or []) or '(なし)'}"


def _sum_exploit(r) -> str:
    if not isinstance(r, dict) or r.get("error"):
        return r.get("error", "") if isinstance(r, dict) else str(r)[:200]
    if r.get("opened_session"):
        ids = ", ".join(str(s["id"]) for s in r["sessions"])
        return f"{r.get('module')} → セッション {ids} 取得"
    return f"{r.get('module')} 実行 → セッションなし"


def _sum_sessions(r) -> str:
    if not isinstance(r, dict) or r.get("error"):
        return r.get("error", "") if isinstance(r, dict) else str(r)[:200]
    return f"{r.get('count')} セッション"


def _sum_session_cmd(r) -> str:
    if not isinstance(r, dict) or r.get("error"):
        return r.get("error", "") if isinstance(r, dict) else str(r)[:200]
    return f"[{r.get('session_type')}#{r.get('session_id')}] {r.get('command')}"


PLUGINS = [
    ToolPlugin(
        name="msf_search",
        description=(
            "Metasploit のモジュールを検索する(RPC経由)。cve_lookup で当たりを付けた"
            "サービス名/CVE/製品名から、実際に使える exploit/auxiliary モジュールを探す橋渡し。"
            "対象ホストには接触しない(msfrpcd に問い合わせるだけ)。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "検索語(例: 'vsftpd', 'samba', 'CVE-2011-2523')"},
                "limit": {"type": "integer", "description": "最大件数(既定15・上限50)"},
            },
            "required": ["query"],
        },
        run=_run_search,
        summary=_sum_search,
        scope_targets=lambda args: [],
    ),
    ToolPlugin(
        name="msf_module_info",
        description=(
            "Metasploit モジュールの詳細(説明・オプション・必須項目・exploitならtargets/payloads)を"
            "返す。msf_run で実行する前に、何を set すべきか(RHOSTS以外の必須オプション等)を確認するのに使う。"
            "対象ホストには接触しない。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "モジュール名(例: 'exploit/unix/ftp/vsftpd_234_backdoor')"},
                "module_type": {"type": "string", "description": "型を明示する場合(exploit/auxiliary/post 等。名前にプレフィックスがあれば不要)"},
            },
            "required": ["module"],
        },
        run=_run_info,
        summary=_sum_info,
        scope_targets=lambda args: [],
    ),
    ToolPlugin(
        name="msf_run",
        description=(
            "Metasploit モジュール(exploit/auxiliary)を対象に対して実行する。RHOSTS と任意オプション・"
            "payload を設定して execute し、新規に開いたセッションを検出して返す。実行前に "
            "msf_module_info で必須オプションを確認しておくこと。対象に触れる操作なので認可スコープ内のみ。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "モジュール名(例: 'exploit/unix/ftp/vsftpd_234_backdoor')"},
                "rhosts": {"type": "string", "description": "対象ホスト/IP(RHOSTS)。認可スコープ内であること"},
                "options": {
                    "type": "string",
                    "description": "追加オプション。'KEY=VALUE' をカンマ区切りで(例: 'RPORT=21, LHOST=10.0.0.1, LPORT=4444')",
                },
                "payload": {"type": "string", "description": "exploit の payload(例: 'cmd/unix/reverse')。不要なら空"},
                "module_type": {"type": "string", "description": "型を明示する場合(既定 exploit)"},
            },
            "required": ["module", "rhosts"],
        },
        run=_run_exploit,
        summary=_sum_exploit,
        # 対象(RHOSTS)を確実に宣言 → ScopeGuard が範囲外を実行前ハードブロック
        scope_targets=lambda args: [str(args.get("rhosts") or "").strip()] if args.get("rhosts") else [],
    ),
    ToolPlugin(
        name="msf_sessions",
        description=(
            "現在アクティブな Metasploit セッション(meterpreter/shell)の一覧を返す。"
            "msf_run で取得した足場を確認し、msf_session_run で継続操作するためのID確認に使う。"
        ),
        parameters={"type": "object", "properties": {}},
        run=_run_sessions,
        summary=_sum_sessions,
        scope_targets=lambda args: [],
    ),
    ToolPlugin(
        name="msf_session_run",
        description=(
            "開いている Metasploit セッション(meterpreter/shell)内でコマンドを実行する"
            "(ポストエクスプロイト)。session_id は msf_sessions で確認する。そのセッションは"
            "既に認可スコープ内の対象への exploit で開かれたものなので、その足場上での操作。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "対象セッションのID(msf_sessions で確認)"},
                "command": {"type": "string", "description": "実行するコマンド(meterpreterコマンド or シェルコマンド)"},
            },
            "required": ["session_id", "command"],
        },
        run=_run_session_cmd,
        summary=_sum_session_cmd,
        scope_targets=lambda args: [],
    ),
]
