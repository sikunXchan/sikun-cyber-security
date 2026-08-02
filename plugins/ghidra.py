"""ghidra — Ghidra のヘッドレス逆コンパイルを構造化ツールにする(バイナリ解析)。

狙い: 「ユーザーは Ghidra(逆アセンブリ/擬似コード)を読めない」——だからこそ、重い逆コンパイルを
Ghidra に機械的にやらせ、その擬似Cを SCS(モデル)が読んで日本語で噛み砕く分業が噛み合う。
GUI は一切使わず `analyzeHeadless` で完結する。study モードの「ソースの無いバイナリ(マルウェア/
CTFのrev/ファームウェア/クローズドソース)」解析の中核。ソースがあるものには使わない(その場合は
ソースを直接読めばよい)。

対象ホストには接触しない(手元のバイナリファイルを解析するだけ)ので scope_targets は空。

重要(正直な前提): 逆コンパイルは Ghidra 標準の DecompInterface イディオムで書いているが、
本開発環境に Ghidra が無いため**生きた実行は Ghidra 導入環境での確認が必要**。Ghidra 未導入・
解析失敗時はクラッシュせず明確なエラーを返す。
"""

from __future__ import annotations

import shlex

from sikun.plugins import PluginContext, ToolPlugin

# analyzeHeadless の探索候補(環境変数 GHIDRA_HOME 優先、次にPATH、次に定番の配置)
_HEADLESS_CANDIDATES = (
    '"$GHIDRA_HOME"/support/analyzeHeadless',
    "analyzeHeadless",
    "/opt/ghidra/support/analyzeHeadless",
)
_GLOB_CANDIDATE = "/opt/ghidra*/support/analyzeHeadless"

# スクリプト出力をフレームワークの饒舌なログから切り出すためのマーカー
_BEGIN = "===SIKUN_GHIDRA_BEGIN==="
_END = "===SIKUN_GHIDRA_END==="

_SCRIPT_DIR = "/tmp/sikun_ghidra"
_SCRIPT_NAME = "sikun_decompile.py"

# Ghidra ヘッドレス用 Jython(Python2系)スクリプト。postScript として実行され、
# 指定関数(既定 main、無ければ entry、それも無ければ関数名一覧)を逆コンパイルして
# マーカー間に擬似Cを出力する。DecompInterface は Ghidra 逆コンパイルの標準API。
_DECOMPILE_SCRIPT = """# -*- coding: utf-8 -*-
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
want = args[0] if len(args) > 0 else "main"
limit = 40

decomp = DecompInterface()
decomp.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()
fm = currentProgram.getFunctionManager()

funcs = []
it = fm.getFunctions(True)
while it.hasNext():
    funcs.append(it.next())

def emit(func):
    res = decomp.decompileFunction(func, 60, monitor)
    print("// FUNCTION: " + func.getName() + " @ " + str(func.getEntryPoint()))
    if res is not None and res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("// (decompile failed for " + func.getName() + ")")

print("%s" % "===SIKUN_GHIDRA_BEGIN===")
if want.upper() == "ALL":
    for f in funcs[:limit]:
        emit(f)
else:
    match = [f for f in funcs if f.getName() == want]
    if len(match) == 0 and want == "main":
        # main が無ければ entry を試す
        match = [f for f in funcs if f.getName() in ("entry", "_start", "start")]
    if len(match) == 0:
        print("// function '%s' not found. available functions:" % want)
        for f in funcs[:300]:
            print("//   " + f.getName())
    else:
        for f in match:
            emit(f)
print("%s" % "===SIKUN_GHIDRA_END===")
"""


def _extract_between(output: str, begin: str = _BEGIN, end: str = _END) -> str | None:
    """analyzeHeadless の饒舌な出力から、スクリプトがマーカー間に吐いた本文だけを取り出す。
    どちらかのマーカーが無ければ None(=スクリプトが正常に走らなかった)。"""
    i = output.find(begin)
    if i == -1:
        return None
    j = output.find(end, i + len(begin))
    if j == -1:
        return None
    return output[i + len(begin) : j].strip()


def _headless_command(binary: str, function: str, scriptdir: str, scriptname: str) -> str:
    """analyzeHeadless の起動コマンドを組み立てる。使い捨てプロジェクトを一時領域に作り、
    解析後に削除。解析時間は上限を付けて暴走を防ぐ。"""
    b = shlex.quote(binary)
    fn = shlex.quote(function or "main")
    sd = shlex.quote(scriptdir)
    return (
        f"{{ $HEADLESS }} {shlex.quote(scriptdir + '/proj')} sikun_tmp "
        f"-import {b} -scriptPath {sd} -postScript {shlex.quote(scriptname)} {fn} "
        f"-deleteProject -analysisTimeoutPerFile 180 2>&1"
    )


async def _resolve_headless(ctx: PluginContext) -> str | None:
    """analyzeHeadless の実体パスを解決する。見つからなければ None。"""
    checks = " || ".join(f"command -v {c} 2>/dev/null" for c in _HEADLESS_CANDIDATES)
    # PATH/GHIDRA_HOME/定番パスを順に試し、無ければ /opt/ghidra* を glob
    probe = (
        f'H=$({checks}); '
        f'[ -z "$H" ] && H=$(ls {_GLOB_CANDIDATE} 2>/dev/null | head -1); '
        f'[ -n "$H" ] && echo "$H" || echo none'
    )
    out = (await ctx.run(probe)).strip().splitlines()
    path = out[-1].strip() if out else "none"
    return None if (not path or path == "none") else path


async def _write_script(ctx: PluginContext) -> None:
    """逆コンパイル用 Jython を、Ghidra が動くホスト(ctx.run 先)の一時領域に書き出す。"""
    heredoc = (
        f"mkdir -p {shlex.quote(_SCRIPT_DIR)} && "
        f"cat > {shlex.quote(_SCRIPT_DIR + '/' + _SCRIPT_NAME)} << 'SIKUN_GHIDRA_EOF'\n"
        f"{_DECOMPILE_SCRIPT}\n"
        "SIKUN_GHIDRA_EOF"
    )
    await ctx.run(heredoc)


async def _run_decompile(args: dict, ctx: PluginContext) -> dict:
    binary = str(args.get("binary") or "").strip()
    if not binary:
        return {"error": "binary(解析するバイナリのパス)を指定してください"}
    function = str(args.get("function") or "main").strip() or "main"

    # 対象ファイルの存在確認(ctx.run 先のホスト基準)
    exists = (await ctx.run(f"test -f {shlex.quote(binary)} && echo yes || echo no")).split()
    if "yes" not in exists:
        return {"error": f"ファイルが見つかりません: {binary}(Ghidra が動くホスト上のパスを指定)"}

    headless = await _resolve_headless(ctx)
    if headless is None:
        return {
            "error": (
                "Ghidra が見つかりません(analyzeHeadless 不在)。Ghidra を導入し、"
                "環境変数 GHIDRA_HOME を設定するか PATH に support/analyzeHeadless を通してください。"
            )
        }

    await _write_script(ctx)
    cmd = _headless_command(binary, function, _SCRIPT_DIR, _SCRIPT_NAME).replace(
        "{ $HEADLESS }", shlex.quote(headless)
    )
    raw = await ctx.run(cmd)

    body = _extract_between(raw)
    if body is None:
        tail = (raw or "").strip()[-800:]
        return {
            "error": "逆コンパイル出力を取得できませんでした(解析失敗/タイムアウト/Ghidraエラーの可能性)。",
            "hint": "大きいバイナリは時間がかかる。関数を絞る/再試行を検討。",
            "log_tail": tail,
        }

    not_found = "not found. available functions:" in body
    return {
        "binary": binary,
        "function": function,
        "found": not not_found,
        # 擬似C(モデルがこれを読んで説明・脆弱性指摘する)。長すぎる場合は切る。
        "decompiled": body[:12000],
        "note": (
            "指定関数が見つからず、利用可能な関数名一覧を返した。function を指定して再度呼ぶこと。"
            if not_found
            else "この擬似Cを読んで、処理内容・危険な関数(strcpy/system 等)・脆弱性を説明すること。"
        ),
    }


def _summary(result) -> str:
    if not isinstance(result, dict):
        return str(result)[:200]
    if result.get("error"):
        return result["error"]
    n = len(result.get("decompiled") or "")
    status = "関数一覧" if not result.get("found") else f"擬似C {n}文字"
    return f"{result.get('binary')}::{result.get('function')} → {status}"


PLUGIN = ToolPlugin(
    name="ghidra_decompile",
    description=(
        "Ghidra のヘッドレス解析で、ソースの無いバイナリ(.exe/ELF/.so/ファームウェア/マルウェア/"
        "CTFのバイナリ)を逆コンパイルし、指定関数(既定 main)のC風擬似コードを返す。GUIは使わない。"
        "返ってきた擬似コードを読んで、処理内容・危険な関数・脆弱性を説明するのに使う。"
        "**ソースコードが手に入るものには使わない**(その場合はソースを直接読む)。"
        "関数名が分からなければ function を省略(main→entry を試す)か、一度呼ぶと関数名一覧が返る。"
        "対象ホストには接触しない(手元のファイルを解析するだけ)。要 Ghidra 導入(GHIDRA_HOME)。"
    ),
    parameters={
        "type": "object",
        "properties": {
            "binary": {"type": "string", "description": "解析するバイナリのパス(Ghidraが動くホスト上のパス)"},
            "function": {
                "type": "string",
                "description": "逆コンパイルする関数名(既定 main)。'ALL' で先頭40関数をまとめて。不明なら省略で関数一覧が返る",
            },
        },
        "required": ["binary"],
    },
    run=_run_decompile,
    summary=_summary,
    scope_targets=lambda args: [],  # 手元のバイナリを解析するだけ。対象ホストに接触しない
)
