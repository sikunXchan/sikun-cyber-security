"""privesc_enum — Linux 権限昇格ベクタの構造化列挙(foothold→昇格の橋渡し)。

足場(shell)を取った後の「次の一手」を探すツール。linpeas 的な一括チェックを
1回の実行で走らせ、結果を**構造化して**返す(生の大量出力を人間/モデルが目視する
代わりに、カテゴリ別 + 高価値ベクタ notable を抽出)。攻撃(昇格経路の発見)にも、
自己診断(自分のホストの昇格穴つぶし)にも使える。

読み取り専用の列挙のみ。ctx.run が向いている先(ローカル or SSH先の踏み台)の
その場のホストを調べるだけで、ネットワーク越しに別ホストを叩かないため
scope_targets は空。
"""

from __future__ import annotations

from pathlib import Path

from sikun.plugins import PluginContext, ToolPlugin

# GTFOBins で SUID 悪用が知られている代表的なバイナリ(basename)。SUID で見つかったら
# 権限昇格に直結しうるので notable として拾う。網羅ではなく高頻度なものの抜粋。
_GTFOBINS_SUID = {
    "bash", "sh", "dash", "zsh", "find", "vim", "vi", "nano", "less", "more", "man",
    "awk", "gawk", "nmap", "perl", "python", "python2", "python3", "ruby", "lua",
    "cp", "mv", "tar", "zip", "unzip", "gdb", "make", "env", "nice", "docker",
    "node", "php", "socat", "ncat", "nc", "wget", "curl", "rsync", "ionice",
    "flock", "tee", "dd", "sed", "ed", "expect", "git", "ftp", "scp",
}

_SECTIONS = ["ID", "SUDO", "SUID", "KERNEL", "CRON", "CAPS", "PASSWD", "WORLD_WRITABLE"]


def _build_script() -> str:
    """One combined script with section markers — a single ctx.run() instead of
    ~8 round trips (matters over SSH). Everything is read-only enumeration."""
    return "\n".join(
        [
            "echo '###ID###'; id 2>/dev/null",
            "echo '###SUDO###'; sudo -n -l 2>/dev/null || echo '(no passwordless sudo)'",
            "echo '###SUID###'; find / -perm -4000 -type f 2>/dev/null | head -200",
            "echo '###KERNEL###'; uname -a 2>/dev/null; grep PRETTY_NAME /etc/os-release 2>/dev/null",
            "echo '###CRON###'; grep -vE '^\\s*#|^\\s*$' /etc/crontab 2>/dev/null; ls -la /etc/cron.d 2>/dev/null",
            "echo '###CAPS###'; getcap -r / 2>/dev/null | head -50",
            "echo '###PASSWD###'; ls -l /etc/passwd /etc/shadow 2>/dev/null",
            "echo '###WORLD_WRITABLE###'; find /etc /usr/local/bin /usr/local/sbin -perm -0002 -type f 2>/dev/null | head -50",
            "echo '###DONE###'",
        ]
    )


def _parse_sections(raw: str) -> dict[str, str]:
    """Split combined output on the ###SECTION### markers into a dict. Tolerant
    of the persistent shell's `[exit=N]` prefix and any leading noise."""
    sections: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("###") and stripped.endswith("###"):
            if current is not None:
                sections[current] = "\n".join(buf).strip()
            name = stripped.strip("#").strip()
            current = name if name != "DONE" else None
            buf = []
            continue
        if current is not None:
            buf.append(line)
    if current is not None:
        sections[current] = "\n".join(buf).strip()
    return sections


def _analyze(sections: dict[str, str]) -> list[str]:
    """Heuristics for high-value vectors → human-readable 'notable' lines."""
    notable: list[str] = []

    sudo = sections.get("SUDO", "")
    if "NOPASSWD" in sudo:
        notable.append("sudo NOPASSWD 設定あり — sudo -l の対象コマンドで昇格可能な可能性")
    elif "(ALL : ALL) ALL" in sudo or "(ALL) ALL" in sudo:
        notable.append("広範な sudo 権限あり(要パスワード)")

    suid_bins = [ln.strip() for ln in sections.get("SUID", "").splitlines() if ln.strip()]
    hits = sorted({b for b in (Path(p).name for p in suid_bins) if b in _GTFOBINS_SUID})
    if hits:
        notable.append(f"GTFOBins既知のSUIDバイナリ: {', '.join(hits)} — 昇格に直結しうる")

    caps = sections.get("CAPS", "")
    if "cap_setuid" in caps or "cap_dac_override" in caps or "cap_dac_read_search" in caps:
        notable.append("危険な file capability(cap_setuid 等)を持つバイナリあり")

    passwd = sections.get("PASSWD", "")
    for line in passwd.splitlines():
        parts = line.split()
        if not parts or len(parts[0]) < 10:
            continue
        perms = parts[0]  # ls -l permission string, e.g. -rw-r--r--
        # index 8 = group-write, 9-ish covered by count; >=2 'w' means beyond owner
        if "/etc/passwd" in line and perms.count("w") >= 2:
            notable.append("/etc/passwd が owner 以外にも書き込み可能に見える — 直接昇格の可能性")
        if "/etc/shadow" in line and perms[7] == "r":  # other-read bit
            notable.append("/etc/shadow が other から読み取り可能に見える — ハッシュ奪取の可能性")

    if sections.get("WORLD_WRITABLE", "").strip():
        notable.append("システム領域に world-writable ファイルあり(WORLD_WRITABLE参照)")

    cron = sections.get("CRON", "")
    if cron.strip():
        notable.append("カスタム cron エントリあり(書き込み可能スクリプトなら昇格に使える)")

    return notable


async def _run(args: dict, ctx: PluginContext) -> dict:
    raw = await ctx.run(_build_script())
    sections = _parse_sections(raw)
    notable = _analyze(sections)
    return {
        "host_user": sections.get("ID", ""),
        "kernel": sections.get("KERNEL", ""),
        "notable": notable,
        "sections": sections,
    }


def _summary(result) -> str:
    if not isinstance(result, dict):
        return str(result)[:200]
    notable = result.get("notable") or []
    if not notable:
        return "権限昇格の明確なベクタは検出されず(sections で詳細確認)"
    return f"notable {len(notable)}件: " + " / ".join(notable[:3]) + (" ..." if len(notable) > 3 else "")


PLUGIN = ToolPlugin(
    name="privesc_enum",
    description=(
        "足場(shell)を取った後の Linux 権限昇格ベクタを一括で列挙し、構造化して返す。"
        "sudo権限・SUID/SGIDバイナリ・file capability・cron・書き込み可能な重要ファイル・"
        "カーネル/OSバージョンを収集し、GTFOBins既知のSUIDやNOPASSWD sudo等の高価値ベクタを"
        "notable として抽出する。読み取り専用の列挙のみ。ローカル(またはSSH先の踏み台)の"
        "現在のホストを調べる。攻撃(昇格経路探し)にも自己診断(昇格穴つぶし)にも使える。"
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    run=_run,
    summary=_summary,
    scope_targets=lambda args: [],  # その場のホストを列挙するだけ。ネットワーク越しに叩かない
)
