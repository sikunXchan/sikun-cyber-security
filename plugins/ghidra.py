"""ghidra — Ghidra のヘッドレス逆コンパイルを構造化ツールにする(バイナリ解析)。

狙い: 「ユーザーは Ghidra(逆アセンブリ/擬似コード)を読めない」——だからこそ、重い逆コンパイルを
Ghidra に機械的にやらせ、その擬似Cを SCS(モデル)が読んで日本語で噛み砕く分業が噛み合う。
GUI は一切使わず `analyzeHeadless` で完結する。study モードの「ソースの無いバイナリ(マルウェア/
CTFのrev/ファームウェア/クローズドソース)」解析の中核。ソースがあるものには使わない(その場合は
ソースを直接読めばよい)。

対象ホストには接触しない(手元のバイナリファイルを解析するだけ)ので scope_targets は空。

実装メモ(実機検証済み — Ghidra 12.1.2 で確認):
- postScript は **Java の GhidraScript** で書く。Ghidra 11.3+/12 は Jython を廃止しており、`.py`
  スクリプトは PyGhidra 前提になったため、追加依存の要らない Java(.java は自動コンパイルされる)
  を採用。JDK は Ghidra 自体が要求するので必ずある。
- 逆コンパイル結果は analyzeHeadless の饒舌なログに紛れさせず、**専用ファイルに書き出して読む**。
- analyzeHeadless はプロジェクト格納ディレクトリが既存であることを要求する(自動でmkdirしない)。
- Ghidra 未導入 / ファイル不在 / 解析失敗でもクラッシュせず明確なエラーを返す。
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
# GHIDRA_HOME 未設定でも拾えるよう、よくある展開先を glob で探す
_GLOB_CANDIDATES = ("/opt/ghidra*/support/analyzeHeadless", "$HOME/ghidra/ghidra_*_PUBLIC/support/analyzeHeadless")

_WORK_DIR = "/tmp/sikun_ghidra"
_SCRIPT_NAME = "SikunDecompile.java"  # クラス名=ファイル名(GhidraScriptの規約)
_OUT_FILE = _WORK_DIR + "/out.txt"
_PROJ_NAME = "sikun_tmp"

# Ghidra ヘッドレス用 Java GhidraScript。postScript として実行され、指定関数(既定 main、
# 無ければ entry、それも無ければ関数名一覧)を逆コンパイルして出力ファイルに書き出す。
# args[0]=関数名 / args[1]=出力パス。DecompInterface は Ghidra 逆コンパイルの標準API。
_DECOMPILE_SCRIPT = """import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class SikunDecompile extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String want = args.length > 0 ? args[0] : "main";
        String outPath = args.length > 1 ? args[1] : "/tmp/sikun_ghidra/out.txt";
        int limit = 40;

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        List<Function> funcs = new ArrayList<Function>();
        for (Function f : fm.getFunctions(true)) funcs.add(f);

        PrintWriter w = new PrintWriter(outPath, "UTF-8");
        try {
            List<Function> match = new ArrayList<Function>();
            if (want.equalsIgnoreCase("ALL")) {
                for (int i = 0; i < funcs.size() && i < limit; i++) match.add(funcs.get(i));
            } else {
                for (Function f : funcs) if (f.getName().equals(want)) match.add(f);
                if (match.isEmpty() && want.equals("main")) {
                    for (Function f : funcs) {
                        String n = f.getName();
                        if (n.equals("entry") || n.equals("_start") || n.equals("start")) match.add(f);
                    }
                }
            }
            if (match.isEmpty()) {
                w.println("// function '" + want + "' not found. available functions:");
                for (int i = 0; i < funcs.size() && i < 300; i++)
                    w.println("//   " + funcs.get(i).getName());
            } else {
                for (Function f : match) {
                    w.println("// FUNCTION: " + f.getName() + " @ " + f.getEntryPoint());
                    DecompileResults res = decomp.decompileFunction(f, 60, monitor);
                    if (res != null && res.decompileCompleted())
                        w.println(res.getDecompiledFunction().getC());
                    else
                        w.println("// (decompile failed for " + f.getName() + ")");
                }
            }
        } finally {
            w.close();
        }
    }
}
"""


def _headless_command(binary: str, function: str, workdir: str, scriptname: str, outpath: str) -> str:
    """analyzeHeadless の起動コマンドを組み立てる。プロジェクト格納先は workdir(既存)を使い、
    解析後に -deleteProject で片付ける。解析時間には上限。stderr も拾う。"""
    b = shlex.quote(binary)
    fn = shlex.quote(function or "main")
    wd = shlex.quote(workdir)
    op = shlex.quote(outpath)
    return (
        f"{{ $HEADLESS }} {wd} {_PROJ_NAME} "
        f"-import {b} -scriptPath {wd} -postScript {shlex.quote(scriptname)} {fn} {op} "
        f"-deleteProject -analysisTimeoutPerFile 180 2>&1"
    )


async def _resolve_headless(ctx: PluginContext) -> str | None:
    """analyzeHeadless の実体パスを解決する。見つからなければ None。"""
    checks = " || ".join(f"command -v {c} 2>/dev/null" for c in _HEADLESS_CANDIDATES)
    globs = "; ".join(f'ls {g} 2>/dev/null | head -1' for g in _GLOB_CANDIDATES)
    probe = (
        f'H=$({checks}); '
        f'[ -z "$H" ] && H=$({{ {globs}; }} | head -1); '
        f'[ -n "$H" ] && echo "$H" || echo none'
    )
    out = (await ctx.run(probe)).strip().splitlines()
    path = out[-1].strip() if out else "none"
    return None if (not path or path == "none") else path


async def _write_script(ctx: PluginContext) -> None:
    """逆コンパイル用 Java GhidraScript を、Ghidra が動くホスト(ctx.run 先)の作業領域に書き出し、
    前回の残骸(出力ファイル・プロジェクト)を掃除する。"""
    q = shlex.quote
    heredoc = (
        f"mkdir -p {q(_WORK_DIR)} && "
        f"rm -f {q(_OUT_FILE)} {q(_WORK_DIR + '/' + _PROJ_NAME + '.gpr')} && "
        f"rm -rf {q(_WORK_DIR + '/' + _PROJ_NAME + '.rep')} && "
        f"cat > {q(_WORK_DIR + '/' + _SCRIPT_NAME)} << 'SIKUN_GHIDRA_EOF'\n"
        f"{_DECOMPILE_SCRIPT}\n"
        "SIKUN_GHIDRA_EOF"
    )
    await ctx.run(heredoc)


async def _run_decompile(args: dict, ctx: PluginContext) -> dict:
    binary = str(args.get("binary") or "").strip()
    if not binary:
        return {"error": "binary(解析するバイナリのパス)を指定してください"}
    function = str(args.get("function") or "main").strip() or "main"

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
    cmd = _headless_command(binary, function, _WORK_DIR, _SCRIPT_NAME, _OUT_FILE).replace(
        "{ $HEADLESS }", shlex.quote(headless)
    )
    raw = await ctx.run(cmd)

    # 出力ファイルを読む(スクリプトがここに擬似C or 関数一覧を書く)
    body = await ctx.run(
        f"[ -s {shlex.quote(_OUT_FILE)} ] && cat {shlex.quote(_OUT_FILE)} || echo __SIKUN_NO_OUTPUT__"
    )
    if "__SIKUN_NO_OUTPUT__" in body or not body.strip():
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
        "decompiled": body.strip()[:12000],
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
