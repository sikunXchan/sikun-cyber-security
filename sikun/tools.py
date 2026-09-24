"""Shell execution and structured recon tools for the agent loop.

The agent's tool *schemas* live with the agent backend (sikun.agent_gemini);
this module holds the implementations they call: a long-lived PersistentShell
for bash, and the structured recon runners (nmap_scan / http_probe / dir_enum)
that parse tool output into typed results instead of handing the model raw
dumps. All of it runs against the authorized target only — never arbitrary
hosts.
"""

from __future__ import annotations

import asyncio
import html
import os
import re
import shlex
import shutil
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from sikun.http_checks import inspect_http

MAX_OUTPUT_CHARS = 8000
UI_PREVIEW_CHARS = 700


def _bash_executable() -> str:
    """Prefer Git Bash on Windows; the system32 bash.exe is a WSL launcher."""
    if os.name == "nt":
        git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git" / "bin" / "bash.exe"
        if git_bash.is_file():
            return str(git_bash)
    return shutil.which("bash") or "bash"


def preview_for_ui(output: str, max_chars: int = UI_PREVIEW_CHARS) -> str:
    """Truncate command output for display in the TUI (the model still gets
    the full — up to MAX_OUTPUT_CHARS — output via the tool result; this is
    only for what's shown live to the operator so the panel doesn't get
    swamped by a single verbose command)."""
    if len(output) <= max_chars:
        return output
    return output[:max_chars] + f"\n...(+{len(output) - max_chars} chars, 全文はモデルには渡っています)"


async def run_bash(command: str, cwd: Path, ssh_host: str | None = None,
                   *, max_output_chars: int = MAX_OUTPUT_CHARS) -> str:
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
        proc = await asyncio.create_subprocess_exec(
            _bash_executable(), "-s",
            cwd=str(cwd),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate(input=command.encode())
    output = stdout.decode(errors="replace")
    if len(output) > max_output_chars:
        output = output[-max_output_chars:]
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
        # Live working directory of the persistent session (updated from each
        # command's completion marker, which carries $PWD). Used by the HUD.
        self.cwd_live = str(self.cwd)
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
            self._proc = await asyncio.create_subprocess_exec(
                _bash_executable(),
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
        # marker carries exit code AND the live cwd ($PWD) so the HUD can show
        # where the shell is, at zero extra cost (no separate pwd call).
        self._proc.stdin.write(f"{command}\necho {marker}:$?:$PWD\n".encode())
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
                # The marker may not sit at the start of a line: a command whose
                # output lacks a trailing newline (e.g. `curl` of a JSON body)
                # leaves the marker echo concatenated onto that last output line.
                # Match it anywhere and keep whatever real output preceded it,
                # otherwise readline() waits forever for a marker line that never
                # comes and the call dead-hangs until timeout.
                if marker in text:
                    before, _, after = text.partition(marker)
                    if before:
                        lines.append(before)
                    # after looks like ":<exit>:<pwd>" (pwd absent on old shells)
                    parts = after.strip().split(":", 2)
                    if len(parts) >= 2 and parts[1]:
                        exit_code = parts[1]
                    if len(parts) >= 3 and parts[2]:
                        self.cwd_live = parts[2]
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


def _parse_nmap_xml(raw: str, target: str) -> dict:
    result = {"target": target, "open_ports": [], "uncertain_ports": [],
              "hosts": [], "coverage": [], "complete": False, "raw": raw[:8000]}
    start, end = raw.find("<nmaprun"), raw.rfind("</nmaprun>")
    try:
        if start < 0 or end < 0 or "...(truncated)..." in raw:
            raise ValueError("Nmap XML output missing or truncated")
        root = ET.fromstring(raw[start:end + len("</nmaprun>")])
    except (ET.ParseError, ValueError) as exc:
        result["error"] = str(exc)
        return result
    result["coverage"] = [dict(info.attrib) for info in root.findall("scaninfo")]
    for host in root.findall("host"):
        addresses = [a.get("addr", "") for a in host.findall("address")
                     if a.get("addrtype") in ("ipv4", "ipv6")]
        hostname = host.find("hostnames/hostname")
        address = next(iter(addresses), hostname.get("name", target) if hostname is not None else target)
        state = host.find("status")
        result["hosts"].append({"host": address, "addresses": addresses,
                                "state": state.get("state", "unknown") if state is not None else "unknown",
                                "extra_ports": [dict(p.attrib) for p in host.findall("ports/extraports")]})
        for port in host.findall("ports/port"):
            state = port.find("state")
            status = state.get("state", "unknown") if state is not None else "unknown"
            if status == "closed":
                continue
            service = port.find("service")
            attrs = service.attrib if service is not None else {}
            version = " ".join(attrs[k] for k in ("product", "version", "extrainfo") if attrs.get(k))
            item = {"host": address, "port": port.get("portid", ""),
                    "protocol": port.get("protocol", ""), "state": status,
                    "service": attrs.get("name", "unknown"), "version": version or "unknown",
                    "product": attrs.get("product", ""), "product_version": attrs.get("version", ""),
                    "tunnel": attrs.get("tunnel", ""), "method": attrs.get("method", ""),
                    "confidence": attrs.get("conf", ""),
                    "cpes": [c.text for c in service.findall("cpe") if c.text] if service is not None else []}
            result["open_ports" if status == "open" else "uncertain_ports"].append(item)
    finished = root.find("runstats/finished")
    result["complete"] = finished is not None and finished.get("exit") == "success"
    if not result["complete"]:
        result["error"] = finished.get("errormsg", "Nmap did not finish successfully") if finished is not None else "Nmap completion status missing"
    return result


async def run_nmap_scan(target: str, ports: str = "", service_detection: bool = True,
                        ssh_host: str | None = None, protocol: str = "tcp") -> dict:
    """Retain service identity, uncertainty and actual scan coverage from XML."""
    error = ""
    if not target or target.startswith("-") or any(c.isspace() for c in target):
        error = "A single host/IP/CIDR target is required"
    if protocol not in ("tcp", "udp"):
        error = "protocol must be tcp or udp"
    if ports and ports != "-":
        for span in ports.split(","):
            if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", span):
                error = "Invalid port range"
                break
            values = list(map(int, span.split("-")))
            if not all(1 <= n <= 65535 for n in values) or values[0] > values[-1]:
                error = "Ports must be within 1-65535 in ascending ranges"
    if error:
        return {"target": target, "open_ports": [], "uncertain_ports": [], "complete": False, "error": error}
    flags = ["nmap", "-Pn", "-sU" if protocol == "udp" else "-sT"]
    if ":" in target:
        flags.append("-6")
    if service_detection:
        flags.append("-sV")
    if ports:
        flags.extend(["-p", ports])
    flags.extend(["-oX", "-", target])
    try:
        raw = await run_bash(shlex.join(flags), Path.home(), ssh_host=ssh_host, max_output_chars=2_000_000)
    except OSError as exc:
        raw = f"Execution failed: {exc}"
    return _parse_nmap_xml(raw, target)


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
    # Framework names in article text are not fingerprints of the serving app.
    lower = {k.lower(): v.lower() for k, v in headers.items()}
    header_text = " ".join(f"{k}: {v}" for k, v in lower.items())
    hints = {label for needle, label in _TECH_HINTS
             if needle not in {"django", "express", "next.js", "wp-content", "wp-includes"}
             and needle in header_text}
    if lower.get("x-powered-by", "").startswith("express"):
        hints.add("Express/Node.js")
    sample = body[:6000].lower()
    if "wp-content/" in sample or "wp-includes/" in sample:
        hints.add("WordPress")
    if "/_next/" in sample or "__next_data__" in sample:
        hints.add("Next.js")
    if 'name="csrfmiddlewaretoken"' in sample or "name='csrfmiddlewaretoken'" in sample:
        hints.add("Django")
    return sorted(hints)


def _header_items(raw: str) -> tuple[str, list[tuple[str, str]]]:
    hops = re.split(r"(?m)^HTTP/\S+\s+(\d+)[^\r\n]*\r?\n", raw)
    if len(hops) < 3:
        return "?", []
    items = []
    for line in hops[-1].splitlines():
        if not line.strip():
            break
        if ":" in line:
            key, _, value = line.partition(":")
            items.append((key.strip(), value.strip()))
    return hops[-2], items


def _parse_http_headers(raw: str) -> tuple[str, dict[str, str]]:
    status, items = _header_items(raw)
    return status, dict(items)


def _http_url(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None:
        raise ValueError("An HTTP(S) URL without embedded credentials is required")
    if any(ord(c) < 32 for c in url):
        raise ValueError("Control characters in URL")
    _ = parsed.port  # Validate malformed/out-of-range ports before execution.
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


async def _http_snapshot(url: str, ssh_host: str | None = None) -> dict:
    """One bounded GET; keep duplicate headers and never follow an unchecked redirect."""
    marker = "__SIKUN_" + uuid.uuid4().hex
    command = "\n".join([
        'scs_tmp=$(mktemp -d) || exit 1',
        "trap 'rm -f -- \"$scs_tmp/headers\" \"$scs_tmp/body\" \"$scs_tmp/error\"; rmdir -- \"$scs_tmp\"' EXIT",
        'curl --disable --silent --show-error --globoff --proto =http,https '
        '--connect-timeout 5 --max-time 15 --max-filesize 262144 '
        '--header "Accept-Encoding: identity" --dump-header "$scs_tmp/headers" '
        '--output "$scs_tmp/body" --url ' + shlex.quote(url) + ' 2>"$scs_tmp/error"',
        'scs_exit=$?',
        'printf "' + marker + '_META %s " "$scs_exit"',
        'wc -c < "$scs_tmp/body" 2>/dev/null || echo 0',
        'printf "' + marker + '_HEADER_SIZE "',
        'wc -c < "$scs_tmp/headers" 2>/dev/null || echo 0',
        'printf "' + marker + '_HEADERS\\n"',
        'head -c 24000 "$scs_tmp/headers" 2>/dev/null',
        'printf "\\n' + marker + '_BODY\\n"',
        'head -c 6000 "$scs_tmp/body" 2>/dev/null',
        'printf "\\n' + marker + '_ERROR\\n"',
        'head -c 500 "$scs_tmp/error" 2>/dev/null',
    ])
    try:
        raw = await run_bash(command, Path.home(), ssh_host=ssh_host, max_output_chars=32000)
    except OSError as exc:
        raw = "\n" + marker + "_ERROR\n" + f"Execution failed: {exc}"
    meta = re.search(re.escape(marker) + r"_META (\d+)\s+(\d+)", raw)
    headers_raw = raw.partition(marker + "_HEADERS\n")[2].partition("\n" + marker + "_BODY\n")[0]
    body = raw.partition("\n" + marker + "_BODY\n")[2].partition("\n" + marker + "_ERROR\n")[0]
    error = raw.partition("\n" + marker + "_ERROR\n")[2].strip()
    status, items = _header_items(headers_raw)
    exit_code, size = (int(meta[1]), int(meta[2])) if meta else (-1, 0)
    header_size = re.search(re.escape(marker) + r"_HEADER_SIZE\s+(\d+)", raw)
    headers_complete = header_size is not None and int(header_size[1]) <= 24000
    complete = exit_code == 0 and status != "?" and headers_complete and "...(truncated)..." not in raw
    return {"url": url, "status": status, "header_items": items, "headers": dict(items),
            "raw_headers": headers_raw, "body": body, "size": size, "complete": complete,
            "body_complete": complete and size <= 6000,
            "error": error or ("HTTP response incomplete" if not complete else "")}


async def run_http_probe(url: str, ssh_host: str | None = None) -> dict:
    try:
        url = _http_url(url)
    except ValueError as exc:
        return {"url": url, "status": "?", "title": "", "tech_hints": [], "complete": False, "error": str(exc)}
    snapshot = await _http_snapshot(url, ssh_host)
    headers, body = snapshot["headers"], snapshot["body"]
    lower = {key.lower(): value for key, value in headers.items()}
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    checks = inspect_http(url, snapshot["status"], snapshot["header_items"], body,
                          complete=snapshot["body_complete"]) if snapshot["complete"] else []
    return {key: value for key, value in snapshot.items() if key != "body"} | {
        "title": html.unescape(re.sub(r"\s+", " ", match[1]).strip()) if match else "",
        "server": lower.get("server", ""), "x_powered_by": lower.get("x-powered-by", ""),
        "tech_hints": _guess_tech(headers, body), "security_checks": checks,
        "redirect_to": lower.get("location", "") if snapshot["status"].startswith("3") else "",
        "notes": ["Redirects are not followed; check the destination scope before probing it.",
                  "Configuration observations require impact validation before reporting a vulnerability."]}


# Small built-in sweep calibrated against each parent's missing-path responses.
# Enough to identify common discovery candidates
# (exposed .git/.env, admin panels, debug endpoints) without depending on
# SecLists or dirb's wordlists being installed on whatever host this runs on.
_DEFAULT_DIR_WORDLIST = [
    "", "admin", "administrator", "login", "wp-admin", "wp-login.php", "api", "api/v1",
    "backup", "backups", ".git/config", ".git/HEAD", ".env", ".env.example", "config", "config.php",
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "server-status", "phpinfo.php",
    "uploads", "images", "static", "assets", "js", "css", "test", "dev", "staging",
    "swagger", "swagger-ui", "graphql", "actuator", "actuator/health", "console",
    "cgi-bin", ".htaccess", "web.config", "README.md", "install", "setup", "debug",
    "phpmyadmin", "adminer", "manager/html", "status", "health",
    # 侵入口が見つからない時に効く一般的な発見系(JSからのルート抽出/メタ情報/VCS露出)
    "metrics", "api-docs", "swagger.json", "openapi.json", "api/docs", "rest",
    "main.js", "app.js", "main.js.map", "app.js.map", "bundle.js", "ftp",
    "backup.zip", "backup.tar.gz", "db.sqlite", "package.json", "server.js", ".DS_Store",
]


def _normalized_response(snapshot: dict, path: str) -> tuple:
    # Only normalize the requested path. Do not mask numbers, arbitrary tokens,
    # or equal-length bodies: those can distinguish real resources from errors.
    lower = {key.lower(): value for key, value in snapshot["header_items"]}
    body = snapshot["body"]
    location = lower.get("location", "")
    variants = {snapshot["url"], urlsplit(snapshot["url"]).path, path,
                unquote(path), quote(path, safe=""), html.escape(path)} - {"", "/"}
    for variant in sorted(variants, key=len, reverse=True):
        body = body.replace(variant, "<requested-path>")
        location = location.replace(variant, "<requested-path>")
    return snapshot["status"], lower.get("content-type", ""), location, body


async def run_dir_enum(url: str, wordlist: str = "", ssh_host: str | None = None) -> dict:
    """Calibrated discovery; ambiguous catch-all responses are retained separately."""
    result = {"url": url, "source": "calibrated-curl", "found": [], "ambiguous": [],
              "errors": [], "complete": False, "tested_paths": [], "raw": ""}
    try:
        parsed = urlsplit(_http_url(url))
        if parsed.query:
            raise ValueError("Directory enumeration requires a base URL without a query")
        base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))
        paths = list(dict.fromkeys(p.strip().lstrip("/") for p in wordlist.split(",") if p.strip())) if wordlist else list(_DEFAULT_DIR_WORDLIST)
        if len(paths) > 200:
            raise ValueError("At most 200 paths per scan; split larger wordlists explicitly")
        if any(p.startswith("/") or any(c in p for c in ("?", "#", "\\")) or
               ".." in unquote(p).split("/") or "://" in p for p in paths):
            raise ValueError("Wordlist entries must be paths beneath the base URL")
    except ValueError as exc:
        return result | {"error": str(exc)}
    result["url"] = base
    semaphore = asyncio.Semaphore(4)

    async def fetch(path):
        async with semaphore:
            return await _http_snapshot(base + "/" + quote(path, safe="/@:+-._~"), ssh_host)

    # Calibrate each parent directory; nested handlers often differ from root.
    parents = sorted({p.rpartition("/")[0] for p in paths})
    baselines = {}
    for parent in parents:
        probes = [(parent + "/" if parent else "") + "scs-missing-" + uuid.uuid4().hex for _ in range(2)]
        samples = await asyncio.gather(*(fetch(p) for p in probes))
        usable = all(s["complete"] and s["body_complete"] for s in samples)
        signatures = [_normalized_response(s, p) for s, p in zip(samples, probes)]
        baselines[parent] = (usable and signatures[0] == signatures[1], signatures[0])
        for p, s in zip(probes, samples):
            if not s["complete"]:
                result["errors"].append({"path": p, "error": s["error"], "phase": "calibration"})
    snapshots = await asyncio.gather(*(fetch(p) for p in paths))
    for path, snapshot in zip(paths, snapshots):
        result["tested_paths"].append(path or "/")
        if not snapshot["complete"]:
            result["errors"].append({"path": path or "/", "error": snapshot["error"]})
            continue
        code = int(snapshot["status"])
        if code in (404, 410):
            continue
        item = {"path": path or "/", "status": code, "size": snapshot["size"],
                "verification": "unverified"}
        stable, signature = baselines[path.rpartition("/")[0]]
        if not stable or not snapshot["body_complete"]:
            item["reason"] = "unstable_or_incomplete_baseline"
        elif _normalized_response(snapshot, path) == signature:
            item["reason"] = "matches_missing_path_response"
        elif code >= 500 or code == 429:
            item["reason"] = "server_error_or_rate_limit"
        else:
            item["reason"] = "differs_from_missing_path_response"
            result["found"].append(item)
            continue
        result["ambiguous"].append(item)
    result["complete"] = not result["errors"]
    result["coverage"] = {"requested": len(paths), "tested": len(snapshots),
                          "calibration_requests": len(parents) * 2,
                          "ambiguous": len(result["ambiguous"])}
    return result
