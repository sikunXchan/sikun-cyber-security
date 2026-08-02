"""selfcheck — 起動時のローカル体制点検(SCS MORNING SWEEP)。

`--status` 起動で走る。対象ホストには触れず、**自分のマシンの読み取り専用の点検**だけを
サッと行い、ネオン調で1項目ずつ [OK]/[!] を流して最後に「異常なし / 要注意 N件」を宣言する。

狙いは市販AVの代替ではなく、AVが手薄な領域——**設定・体制の穴(開放ポート/未適用パッチ/
失敗ログイン/SUID 等)を、透明に(何を見たか分かる形で)点検する**こと。要注意が出たら
そのまま対話でSCSに深掘りさせられる。

各チェックは (name, cmd, parse) の組。parse は生出力から (status, detail) を返す純関数なので
単体テストできる。status は OK / WARN / INFO / SKIP。
"""

from __future__ import annotations

import asyncio
import datetime
from typing import Awaitable, Callable

_STYLE = {
    "OK": "[bold #39ff14][ OK ][/bold #39ff14]",
    "WARN": "[bold #ffb000][ !  ][/bold #ffb000]",
    "INFO": "[bold #00f0ff][ i  ][/bold #00f0ff]",
    "SKIP": "[dim #6a7a99][ -  ][/dim #6a7a99]",
}


def _clean(out: str) -> str:
    """Strip the persistent shell's '[exit=N]\\n' prefix, leaving raw output."""
    out = out or ""
    if out.startswith("[exit="):
        nl = out.find("\n")
        out = out[nl + 1:] if nl >= 0 else ""
    return out.strip()


def _p_ports(out: str) -> tuple[str, str]:
    ports = sorted({p for p in _clean(out).split() if p.isdigit()}, key=int)
    if not ports:
        return "INFO", "待ち受けポートなし"
    shown = ", ".join(ports[:8]) + (" …" if len(ports) > 8 else "")
    return "INFO", f"{len(ports)}個: {shown}"


def _p_firewall(out: str) -> tuple[str, str]:
    o = _clean(out).lower()
    if "__noufw__" in o or "not found" in o:
        return "INFO", "ufw 未導入"
    # check "inactive" before "active" — the latter is a substring of the former
    if "inactive" in o:
        return "WARN", "inactive(無効)"
    if "active" in o:
        return "OK", "active"
    if "root" in o:
        return "SKIP", "要 root で未取得"
    return "INFO", "不明"


def _p_failed_logins(out: str) -> tuple[str, str]:
    o = _clean(out)
    if not o or o.lower() in ("na", "n/a"):
        return "SKIP", "ログ取得不可"
    try:
        n = int(o.split()[0])
    except (ValueError, IndexError):
        return "SKIP", "解析不可"
    return ("WARN" if n > 10 else "OK"), f"{n} 件 / 24h"


def _p_disk_load(out: str) -> tuple[str, str]:
    parts = _clean(out).split()
    disk = parts[0] if parts else "?"
    load = parts[1] if len(parts) > 1 else "?"
    try:
        pct = int(disk.rstrip("%"))
    except ValueError:
        pct = 0
    return ("WARN" if pct >= 90 else "OK"), f"disk {disk} / load {load}"


def _p_updates(out: str) -> tuple[str, str]:
    parts = _clean(out).split()
    if not parts or parts[0] in ("na", "__noapt__"):
        return "SKIP", "apt 無し"
    try:
        total = int(parts[0]); sec = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return "SKIP", "解析不可"
    if sec > 0:
        return "WARN", f"{total} 件(うち security {sec})"
    if total > 0:
        return "WARN", f"{total} 件"
    return "OK", "最新"


def _p_suid(out: str) -> tuple[str, str]:
    o = _clean(out)
    try:
        n = int(o.split()[0])
    except (ValueError, IndexError):
        return "SKIP", "取得不可"
    return "INFO", f"{n} 個(既知の範囲を確認)"


def _p_docker(out: str) -> tuple[str, str]:
    o = _clean(out)
    if not o or o.lower() == "na":
        return "SKIP", "docker 無し"
    try:
        n = int(o.split()[0])
    except (ValueError, IndexError):
        return "SKIP", "取得不可"
    return "OK", f"{n} コンテナ稼働"


def _p_sessions(out: str) -> tuple[str, str]:
    parts = _clean(out).split()
    try:
        n = int(parts[0]) if parts else 0
    except ValueError:
        n = 0
    return "OK", f"{n} セッション"


# (label, shell command, parser). All read-only, localhost only.
CHECKS: list[tuple[str, str, Callable[[str], tuple[str, str]]]] = [
    ("listening ports", "ss -tlnH 2>/dev/null | grep -oE ':[0-9]+ ' | tr -d ': '", _p_ports),
    ("firewall (ufw)", "command -v ufw >/dev/null && ufw status 2>&1 | head -1 || echo __NOUFW__", _p_firewall),
    ("failed logins", "journalctl _COMM=sshd -q --since '-24h' 2>/dev/null | grep -ci failed "
                      "|| grep -ci 'Failed password' /var/log/auth.log 2>/dev/null || echo na", _p_failed_logins),
    ("disk / load", "echo \"$(df -hP / | awk 'NR==2{print $5}') $(cut -d' ' -f1 /proc/loadavg)\"", _p_disk_load),
    ("pending updates", "if command -v apt-get >/dev/null; then L=$(apt-get -s upgrade 2>/dev/null); "
                        "echo \"$(printf '%s' \"$L\" | grep -c '^Inst') "
                        "$(printf '%s' \"$L\" | grep '^Inst' | grep -ci secur)\"; else echo na; fi", _p_updates),
    ("SUID binaries", "find /usr /bin /sbin -perm -4000 -type f 2>/dev/null | wc -l", _p_suid),
    ("docker", "command -v docker >/dev/null && docker ps -q 2>/dev/null | wc -l || echo na", _p_docker),
    ("active sessions", "who 2>/dev/null | wc -l", _p_sessions),
]


async def run_selfcheck(
    run: Callable[[str], Awaitable[str]],
    post: Callable[..., Awaitable[None]],
) -> int:
    """Run the sweep, streaming each result to the transcript. Returns the
    number of WARN results (0 = 異常なし)."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    await post("system", f"\n[bold #00f0ff]◈ SCS MORNING SWEEP[/bold #00f0ff] [dim #6a7a99]// {now}[/dim #6a7a99]")
    await post("system", "[dim #6a7a99]" + "─" * 46 + "[/dim #6a7a99]")

    warns = 0
    for name, cmd, parse in CHECKS:
        try:
            out = await run(cmd)
            status, detail = parse(out)
        except Exception:
            status, detail = "SKIP", "実行エラー"
        if status == "WARN":
            warns += 1
        dots = "." * max(2, 20 - len(name))
        await post(
            "system",
            f"[#b26bff]▸[/#b26bff] {name} [dim #6a7a99]{dots}[/dim #6a7a99] "
            f"{_STYLE[status]} [#c7f5ff]{detail}[/#c7f5ff]",
        )
        await asyncio.sleep(0.22)  # dramatic pacing

    await post("system", "[dim #6a7a99]" + "─" * 46 + "[/dim #6a7a99]")
    if warns == 0:
        await post("system", "[bold #39ff14]◈ STATUS: ✓ NOMINAL — 異常なし[/bold #39ff14]\n")
    else:
        await post(
            "system",
            f"[bold #ffb000]◈ STATUS: {warns} WARN — 気になる項目あり[/bold #ffb000] "
            "[dim #6a7a99](『[/dim #6a7a99][#c7f5ff]要注意の項目を調べて[/#c7f5ff][dim #6a7a99]』と言えば深掘りします)[/dim #6a7a99]\n",
        )
    return warns
