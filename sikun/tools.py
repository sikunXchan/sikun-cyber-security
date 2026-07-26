"""Tool definitions for the agent loop.

- `bash`  : Anthropic-defined, schema-less tool. Executes real shell commands
            on this host (WSL2). ONLY run against the authorized exercise
            target — never against arbitrary hosts.
- `report`: custom tool the model calls to narrate progress into the right
            TUI panel (recon / exploit / finding / system). Keeps UI routing
            explicit instead of guessing from command text.
"""

from __future__ import annotations

import asyncio
import re
import shlex
import uuid
from pathlib import Path

BASH_TOOL = {"type": "bash_20250124", "name": "bash"}

REPORT_TOOL = {
    "name": "report",
    "description": (
        "UIの該当パネルに進捗・発見事項を表示する。実際の操作はbashツールで行い、"
        "このツールは状況説明や成果物の報告専用。攻撃ステップを踏むたびに、"
        "recon(偵察結果)/exploit(攻撃の試行・結果)/finding(確定した脆弱性・成果)"
        "のいずれかで呼び出すこと。"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "channel": {
                "type": "string",
                "enum": ["recon", "exploit", "finding", "system"],
                "description": "表示先パネル",
            },
            "text": {"type": "string", "description": "表示するメッセージ"},
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
                "description": "finding の場合の重要度(任意)",
            },
            "evidence": {
                "type": "string",
                "description": (
                    "finding の場合は必須。脆弱性を裏付ける再現コマンドとその出力の要点"
                    "(例: 実行した payload と、返ってきた具体的な証拠)。これを示せない"
                    "=未確認なら、finding ではなく recon チャンネルで『要確認』として報告する"
                ),
            },
        },
        "required": ["channel", "text"],
    },
}

PLAN_TOOL = {
    "name": "propose_plan",
    "description": (
        "実行系のアクション(攻撃・攻撃的な検証など、対象の状態を変えたり攻撃を成立させたり"
        "する操作)を取る前に、具体的な計画を提示してユーザーの承認を待つ。単なる説明・"
        "脆弱性の報告・診断(読み取り専用で実害のない調査)だけならこのツールは不要で、"
        "直接 bash/report で調査・報告に進んでよい。"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "対象"},
            "steps": {"type": "string", "description": "実施予定の手順(箇条書き推奨)"},
            "risk": {"type": "string", "description": "想定されるリスク・影響範囲"},
        },
        "required": ["steps"],
    },
}

TOOLS = [BASH_TOOL, REPORT_TOOL, PLAN_TOOL]

MAX_OUTPUT_CHARS = 8000
UI_PREVIEW_CHARS = 700


def preview_for_ui(output: str, max_chars: int = UI_PREVIEW_CHARS) -> str:
    """Truncate command output for display in the TUI (the model still gets
    the full — up to MAX_OUTPUT_CHARS — output via the tool result; this is
    only for what's shown live to the operator so the panel doesn't get
    swamped by a single verbose command)."""
    if len(output) <= max_chars:
        return output
    return output[:max_chars] + f"\n...(+{len(output) - max_chars} chars, 全文はモデルには渡っています)"


async def run_bash(command: str, cwd: Path, ssh_host: str | None = None) -> str:
    """Execute a shell command asynchronously (non-blocking for the Textual loop).

    When `ssh_host` is set (e.g. "sikunlily@192.168.11.37"), the command runs
    on that remote host via `ssh <host> bash -s`, piping the command over
    stdin rather than shell-escaping it into an argument — avoids quoting
    breakage regardless of what quotes/backticks the model's command contains.
    The model doesn't need to know it's remote; it just writes normal Linux
    commands. No persistent session either way — each call is a fresh
    subprocess/connection, so `cd`/env exports don't carry over between calls.
    """
    if ssh_host:
        proc = await asyncio.create_subprocess_exec(
            "ssh",
            ssh_host,
            "bash",
            "-s",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate(input=command.encode())
    else:
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
    output = stdout.decode(errors="replace")
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[-MAX_OUTPUT_CHARS:]
        output = "...(truncated)...\n" + output
    return output or "(no output)"


class PersistentShell:
    """A single long-lived bash process (local or over one held-open SSH
    connection) that the agent's `bash` tool calls run against, instead of a
    fresh subprocess per call.

    Fixes the workaround the agent itself had to do today — cramming
    `MITM_PID=$!` and multi-step attack-tool bookkeeping into one giant
    heredoc-style command because `cd`, exported env vars, and `$!` didn't
    survive between calls. With a real persistent session those just work.

    One instance per run_agent() call: start() once at the top, run() per
    `bash` tool invocation, stop() in a finally block.
    """

    def __init__(self, ssh_host: str | None = None, cwd: Path | None = None) -> None:
        self.ssh_host = ssh_host
        self.cwd = cwd or Path.home()
        self._proc: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        if self.ssh_host:
            self._proc = await asyncio.create_subprocess_exec(
                "ssh",
                self.ssh_host,
                "bash",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        else:
            self._proc = await asyncio.create_subprocess_shell(
                "bash",
                cwd=str(self.cwd),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

    async def run(self, command: str, timeout: float = 90.0) -> str:
        """Run `command` in the persistent session; cwd/env/background PIDs
        from earlier calls are still in effect. Returns combined stdout+stderr
        up to the completion marker, prefixed with the exit code."""
        if self._proc is None or self._proc.returncode is not None:
            return "(エラー: 永続シェルが起動していない、または既に終了しています)"

        marker = f"__SIKUN_DONE_{uuid.uuid4().hex}__"
        assert self._proc.stdin is not None and self._proc.stdout is not None
        self._proc.stdin.write(f"{command}\necho {marker}:$?\n".encode())
        await self._proc.stdin.drain()

        lines: list[str] = []
        exit_code = "?"
        try:
            while True:
                raw_line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=timeout)
                if not raw_line:
                    lines.append("\n[シェルプロセスが予期せず終了しました]")
                    break
                text = raw_line.decode(errors="replace")
                if text.startswith(marker):
                    exit_code = text.strip().split(":", 1)[-1]
                    break
                lines.append(text)
        except asyncio.TimeoutError:
            lines.append(f"\n[コマンドが{timeout}秒でタイムアウトしました。バックグラウンド実行(末尾に&)を検討してください]")

        output = "".join(lines)
        if len(output) > MAX_OUTPUT_CHARS:
            output = "...(truncated)...\n" + output[-MAX_OUTPUT_CHARS:]
        return f"[exit={exit_code}]\n{output}" if output.strip() else f"(no output) [exit={exit_code}]"

    async def stop(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.write(b"exit\n")
                await self._proc.stdin.drain()
            await asyncio.wait_for(self._proc.wait(), timeout=5)
        except (asyncio.TimeoutError, ProcessLookupError, BrokenPipeError, ConnectionResetError):
            self._proc.kill()
        except Exception:
            pass


# nmap -oG port entries are exactly 8 "/"-separated fields:
# port/state/protocol/owner/service/rpc_info/version/extra_info
_GREPABLE_FIELD_COUNT = 8


async def run_nmap_scan(
    target: str,
    ports: str = "",
    service_detection: bool = True,
    ssh_host: str | None = None,
) -> dict:
    """Structured port scan: builds the nmap command, runs it, and parses the
    grepable (-oG) output into a list of open ports/services — the model
    doesn't have to hand-write the nmap invocation or regex the human-readable
    output itself, which is what actually goes wrong in raw-bash recon (typo'd
    flags, mis-parsed columns). Returns both the parsed list and raw output so
    the model can fall back to reading the text if parsing missed something.
    """
    # -Pn: skip host-discovery ping and assume the target is up. Without it,
    # nmap silently reports "0 hosts up" and skips the port scan entirely on
    # plenty of real targets (localhost over WSL2's loopback among them) —
    # confirmed empirically, not a hypothetical edge case.
    flags = ["nmap", "-Pn"]
    if service_detection:
        flags.append("-sV")
    if ports:
        flags.extend(["-p", ports])
    flags.extend(["-oG", "-", target])
    command = " ".join(flags)

    raw = await run_bash(command, Path.home(), ssh_host=ssh_host)

    # Parse line-by-line rather than with a single whole-blob regex: a plain
    # `re.search(r"Ports: (.+?)(?:\tIgnored State|$)", raw)` silently matched
    # nothing whenever the "Ports:" line wasn't the literal last line of the
    # output AND had no "Ignored State" suffix — exactly the case for a
    # single targeted port with nothing to ignore (e.g. `-p 6379` on an open
    # port). `.` doesn't cross newlines and `$` without MULTILINE only
    # anchors to the end of the whole string, so the match failed and
    # open_ports silently came back empty even though the port was open —
    # confirmed empirically (nmap itself found the port; the parser dropped it).
    open_ports: list[dict] = []
    for line in raw.splitlines():
        if "Ports: " not in line:
            continue
        ports_part = line.split("Ports: ", 1)[1]
        ports_part = ports_part.split("\tIgnored State", 1)[0]
        for entry in ports_part.split(", "):
            fields = entry.strip().split("/")
            if len(fields) < _GREPABLE_FIELD_COUNT or fields[1] != "open":
                continue
            port, _state, protocol, _owner, service, _rpc, version, _extra = fields[:8]
            open_ports.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "service": service or "unknown",
                    "version": version.strip() or "unknown",
                }
            )

    return {"target": target, "open_ports": open_ports, "raw": raw}


_TECH_HINTS: list[tuple[str, str]] = [
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("x-powered-by: php", "PHP"),
    ("phpsessid", "PHP"),
    ("laravel_session", "Laravel"),
    ("x-drupal-cache", "Drupal"),
    ("x-generator: drupal", "Drupal"),
    ("csrftoken", "Django"),
    ("django", "Django"),
    ("jsessionid", "Java/JSP"),
    ("x-aspnet-version", "ASP.NET"),
    ("x-aspnetmvc-version", "ASP.NET MVC"),
    ("server: nginx", "nginx"),
    ("server: apache", "Apache"),
    ("server: cloudflare", "Cloudflare"),
    ("express", "Express/Node.js"),
    ("next.js", "Next.js"),
]


def _guess_tech(headers: dict[str, str], body: str) -> list[str]:
    haystack = (" ".join(f"{k}: {v}" for k, v in headers.items()) + " " + body[:4000]).lower()
    return sorted({label for needle, label in _TECH_HINTS if needle in haystack})


def _parse_http_headers(raw: str) -> tuple[str, dict[str, str]]:
    """`curl -D -` with -L prints one status-line + header block per redirect
    hop, back to back. Split on status lines and keep the *last* hop (the
    page actually rendered) rather than the first, which a single regex over
    the whole dump would grab by accident on any redirecting target."""
    hops = re.split(r"(?m)^HTTP/\S+\s+(\d+)[^\r\n]*\r?\n", raw)
    # capturing-group split interleaves: [pre, code1, block1, code2, block2, ...]
    if len(hops) < 3:
        return "?", {}
    status = hops[-2]
    header_block = hops[-1]
    headers: dict[str, str] = {}
    for line in header_block.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    return status, headers


async def run_http_probe(url: str, ssh_host: str | None = None) -> dict:
    """Structured HTTP recon: status code, response headers, page title, and
    a best-effort tech-stack guess from header/HTML fingerprints — the model
    doesn't have to re-derive curl's multi-hop header dump or hand-parse HTML
    by eye every time it wants to know what's running behind a port. Same
    'parse once, in code' shape as run_nmap_scan.

    Headers and body are each capped well under PersistentShell/run_bash's
    MAX_OUTPUT_CHARS truncation limit — that truncation keeps the *tail* of
    the output, so an uncapped body would silently eat the headers block
    (which comes first) off the front on any page with a long HTML body.
    """
    if not re.match(r"^https?://", url):
        url = f"http://{url}"
    quoted = shlex.quote(url)
    command = (
        f"echo __SIKUN_HEADERS__; "
        f"curl -sS -D - -o /dev/null --max-time 15 -L {quoted} | head -c 3000; "
        f"echo; echo __SIKUN_BODY__; "
        f"curl -sS --max-time 15 -L {quoted} | head -c 4000"
    )
    raw = await run_bash(command, Path.home(), ssh_host=ssh_host)

    headers_raw, _, body = raw.partition("__SIKUN_BODY__")
    headers_raw = headers_raw.replace("__SIKUN_HEADERS__", "", 1)
    status, headers = _parse_http_headers(headers_raw)

    title = ""
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()

    # Surface the Server header (usually version-bearing, e.g. "Apache/2.4.49")
    # as a first-class field — the version is exactly what cve_lookup needs, and
    # tech_hints alone (bare "Apache") dropped it, so the model would look up the
    # app name instead of the middleware+version. Also expose x-powered-by
    # (PHP/ASP.NET versions live there).
    server = next((v for k, v in headers.items() if k.lower() == "server"), "")
    powered_by = next((v for k, v in headers.items() if k.lower() == "x-powered-by"), "")

    return {
        "url": url,
        "status": status,
        "server": server,
        "x_powered_by": powered_by,
        "headers": headers,
        "title": title,
        "tech_hints": _guess_tech(headers, body),
        "raw_headers": headers_raw.strip(),
    }


# Small built-in sweep used when neither gobuster nor a custom wordlist is
# available on the target — enough to catch the usual low-hanging fruit
# (exposed .git/.env, admin panels, debug endpoints) without depending on
# SecLists or dirb's wordlists being installed on whatever host this runs on.
_DEFAULT_DIR_WORDLIST = [
    "", "admin", "administrator", "login", "wp-admin", "wp-login.php", "api", "api/v1",
    "backup", "backups", ".git/config", ".env", ".env.example", "config", "config.php",
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "server-status", "phpinfo.php",
    "uploads", "images", "static", "assets", "js", "css", "test", "dev", "staging",
    "swagger", "swagger-ui", "graphql", "actuator", "actuator/health", "console",
    "cgi-bin", ".htaccess", "web.config", "README.md", "install", "setup", "debug",
    "phpmyadmin", "adminer", "manager/html", "status", "health",
]


async def run_dir_enum(url: str, wordlist: str = "", ssh_host: str | None = None) -> dict:
    """Structured content/directory discovery. Prefers `gobuster dir` when
    it's installed on the target (fast, and its `(Status: N) [Size: M]`
    output format is stable enough to parse reliably); otherwise falls back
    to sweeping a small built-in common-paths wordlist with plain curl, so
    the tool still works on a bare host that only has curl on it. Returns
    parsed {path, status, size} entries plus the raw scanner output so the
    model can fall back to reading the text if parsing missed something —
    same contract as run_nmap_scan.
    """
    if not re.match(r"^https?://", url):
        url = f"http://{url}"
    base = url.rstrip("/")

    paths = [p.strip().lstrip("/") for p in wordlist.split(",") if p.strip()] or _DEFAULT_DIR_WORDLIST

    which = (await run_bash("command -v gobuster || echo none", Path.home(), ssh_host=ssh_host)).strip()

    if which and which != "none":
        wl_path = f"/tmp/sikun_dir_wordlist_{uuid.uuid4().hex}.txt"
        wl_body = "\n".join(paths)
        await run_bash(
            f"cat > {shlex.quote(wl_path)} << 'SIKUN_EOF'\n{wl_body}\nSIKUN_EOF",
            Path.home(),
            ssh_host=ssh_host,
        )
        command = (
            f"gobuster dir -u {shlex.quote(base)} -w {shlex.quote(wl_path)} "
            f"-q --no-color --timeout 10s 2>&1; rm -f {shlex.quote(wl_path)}"
        )
        raw = await run_bash(command, Path.home(), ssh_host=ssh_host)
        source = "gobuster"
        found = []
        for line in raw.splitlines():
            m = re.match(r"^(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line.strip())
            if m:
                found.append({"path": m.group(1), "status": int(m.group(2)), "size": int(m.group(3))})
    else:
        script = (
            "for p in " + " ".join(shlex.quote(p) for p in paths) + "; do\n"
            f'  code=$(curl -s -o /dev/null -w "%{{http_code}}" --max-time 8 "{base}/$p")\n'
            '  echo "$code $p"\n'
            "done"
        )
        raw = await run_bash(script, Path.home(), ssh_host=ssh_host)
        source = "builtin-curl-fallback"
        found = []
        for line in raw.splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) != 2 or not parts[0].isdigit():
                continue
            code = int(parts[0])
            if code in (0, 404):
                continue
            found.append({"path": parts[1] or "/", "status": code, "size": None})

    return {"url": base, "source": source, "found": found, "raw": raw}
