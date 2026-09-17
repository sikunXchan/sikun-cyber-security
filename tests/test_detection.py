"""Offline detection regressions, including a loopback server and real curl."""
import asyncio
import json
import os
import re
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from unittest.mock import AsyncMock, patch

import pytest

from sikun import tools
from sikun.http_checks import inspect_http


def test_nmap_retains_hosts_cpe_and_uncertain_states():
    xml = '''<nmaprun><scaninfo type="udp" protocol="udp" numservices="2" services="53,161"/>
    <host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="udp" portid="53"><state state="open"/>
    <service name="domain" product="BIND" version="9.18" method="probed" conf="10">
    <cpe>cpe:/a:isc:bind:9.18</cpe></service></port>
    <port protocol="udp" portid="161"><state state="open|filtered"/></port></ports></host>
    <host><address addr="127.0.0.2" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="443"><state state="open"/>
    <service name="http" tunnel="ssl" method="table" conf="3"/></port></ports></host>
    <runstats><finished exit="success"/></runstats></nmaprun>'''
    result = tools._parse_nmap_xml(xml, "127.0.0.0/30")
    assert result["complete"]
    assert len(result["open_ports"]) == 2
    assert result["open_ports"][0]["cpes"] == ["cpe:/a:isc:bind:9.18"]
    assert result["open_ports"][0]["product_version"] == "9.18"
    assert result["open_ports"][1]["host"] == "127.0.0.2"
    assert result["open_ports"][1]["tunnel"] == "ssl"
    assert result["uncertain_ports"][0]["state"] == "open|filtered"
    assert result["coverage"][0]["services"] == "53,161"


@pytest.mark.parametrize("raw", ["nmap: command not found", "<nmaprun>",
                                      "<nmaprun><runstats><finished exit='error' errormsg='denied'/></runstats></nmaprun>"])
def test_nmap_failure_is_not_a_clean_scan(raw):
    result = tools._parse_nmap_xml(raw, "127.0.0.1")
    assert not result["complete"] and result["error"]


def test_nmap_parses_before_model_preview_truncation():
    ports = ''.join(f'<port protocol="tcp" portid="{p}"><state state="open"/></port>' for p in range(1, 301))
    raw = '<nmaprun><host><ports>' + ports + '</ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
    async def run():
        with patch.object(tools, "run_bash", AsyncMock(return_value=raw)) as bash:
            result = await tools.run_nmap_scan("127.0.0.1", "1-300", protocol="udp")
            assert "-sU" in bash.call_args.args[0]
            assert "-oX" in bash.call_args.args[0]
            assert len(result["open_ports"]) == 300
            assert len(result["raw"]) <= 8000
    asyncio.run(run())


@pytest.mark.parametrize("target,ports", [("--script=all", ""), ("127.0.0.1", "80;id"),
                                           ("127.0.0.1", "65536"), ("127.0.0.1", "90-80")])
def test_invalid_scan_arguments_never_execute(target, ports):
    with patch.object(tools, "run_bash", AsyncMock()) as bash:
        result = asyncio.run(tools.run_nmap_scan(target, ports))
        assert result["error"]
        bash.assert_not_called()


def check_map(url="https://example.test", headers=(), body="", complete=True):
    return {c["check"]: c for c in inspect_http(url, "200", list(headers), body, complete=complete)}


def test_headers_and_html_checks_distinguish_observation_from_exploit():
    result = check_map(headers=[("Content-Type", "text/html"),
                                ("Content-Security-Policy-Report-Only", "default-src 'self'")],
                       body='<script src="http://cdn.test/a.js"></script><form action="http://example.test/login"><input type="password"></form>')
    for name in ("hsts", "csp", "frame_protection", "mixed_content", "password_transport"):
        assert result[name]["status"] == "review"
    assert "No enforcing" in result["csp"]["evidence"]
    assert all(c["kind"] == "configuration_observation" for c in result.values())


def test_safe_configuration_and_non_html_applicability():
    result = check_map(headers=[("content-type", "text/html"),
        ("strict-transport-security", "max-age=31536000; includeSubDomains"),
        ("x-content-type-options", "nosniff"),
        ("content-security-policy", "default-src 'self'; frame-ancestors 'none'")])
    assert result["hsts"]["status"] == "pass"
    assert result["frame_protection"]["status"] == "pass"
    # A present CSP still needs a semantic review (nonce/hash/source allowlist).
    assert result["csp"]["status"] == "review"
    result = check_map(url="http://example.test", headers=[("Content-Type", "application/json")])
    for name in ("hsts", "csp", "frame_protection", "mixed_content", "password_transport"):
        assert result[name]["status"] == "not_applicable"


@pytest.mark.parametrize("policy", ["", "max-age=0", "max-age=invalid"])
def test_invalid_hsts_is_not_considered_protection(policy):
    assert check_map(headers=[("Strict-Transport-Security", policy)])["hsts"]["status"] == "review"


def test_duplicate_cookies_preserve_each_policy_without_leaking_values():
    headers = [("Set-Cookie", "sid=secret-one; Secure; HttpOnly; SameSite=Lax"),
               ("set-cookie", "sid=secret-two; Path=/admin; SameSite=None")]
    checks = inspect_http("https://example.test", "200", headers, "")
    cookies = [c for c in checks if c["check"] == "cookie"]
    assert [c["status"] for c in cookies] == ["pass", "review"]
    assert "rejected" in cookies[1]["evidence"]
    assert "secret-one" not in json.dumps(checks) and "secret-two" not in json.dumps(checks)


def test_truncated_html_never_passes_unseen_body_checks():
    checks = check_map(headers=[("Content-Type", "text/html")], complete=False)
    assert checks["mixed_content"]["status"] == "incomplete"
    assert checks["password_transport"]["status"] == "incomplete"


@pytest.fixture
def local_site(monkeypatch):
    if os.name == "nt":
        git_bin = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin"
        if (git_bin / "bash.exe").exists():
            monkeypatch.setenv("PATH", str(git_bin) + os.pathsep + os.environ["PATH"])
    if not shutil.which("bash") or not shutil.which("curl"):
        pytest.skip("Integration checks require bash and curl")
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append(self.path)
            code, headers = 200, [("Content-Type", "text/html")]
            if self.path == "/redirect":
                code, body = 302, "redirect"
                headers.append(("Location", "/outside"))
            elif self.path == "/cookies":
                body = '<title>A &amp; B</title>'
                headers += [("Set-Cookie", "first=one; Secure; HttpOnly; SameSite=Lax"),
                            ("Set-Cookie", "second=two; SameSite=None")]
            elif self.path == "/large":
                body = "x" * 7000
            elif self.path == "/oversize":
                body = "x" * 270000
            elif self.path == "/admin":
                body = "Unique admin page"
            elif self.path == "/api/real":
                body = "real endpoint"
            elif self.path.startswith("/api/"):
                body = "API route unavailable: " + self.path
            elif self.path == "/broken":
                code, body = 503, "temporarily unavailable"
            else:
                body = "Unknown route: " + self.path
            data = body.encode()
            self.send_response(code)
            for key, value in headers:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_single_request_preserves_cookies_and_title(local_site):
    url, requests = local_site
    result = asyncio.run(tools.run_http_probe(url + "/cookies"))
    assert result["complete"], result
    assert requests == ["/cookies"]
    assert result["title"] == "A & B"
    assert len([c for c in result["security_checks"] if c["check"] == "cookie"]) == 2


def test_redirect_is_returned_without_contacting_destination(local_site):
    url, requests = local_site
    result = asyncio.run(tools.run_http_probe(url + "/redirect"))
    assert result["status"] == "302"
    assert result["redirect_to"] == "/outside"
    assert requests == ["/redirect"]


def test_large_response_does_not_destroy_headers_or_look_complete(local_site):
    url, _ = local_site
    result = asyncio.run(tools.run_http_probe(url + "/large"))
    assert result["status"] == "200" and result["headers"]
    assert result["complete"] and not result["body_complete"]
    result = asyncio.run(tools.run_http_probe(url + "/oversize"))
    assert not result["complete"] and result["error"]
    assert not result["security_checks"]


def test_soft_404_and_nested_router_calibration_keep_real_paths(local_site):
    url, requests = local_site
    result = asyncio.run(tools.run_dir_enum(url, "admin,missing,api/real,api/fake,broken"))
    assert result["complete"], result
    assert {p["path"] for p in result["found"]} == {"admin", "api/real"}
    assert {p["path"] for p in result["ambiguous"]} == {"missing", "api/fake", "broken"}
    assert result["coverage"]["calibration_requests"] == 4
    assert len(requests) == 9


def snapshot(url, body, status="200", complete=True):
    return {"url": url, "body": body, "status": status, "size": len(body),
            "header_items": [("Content-Type", "text/html")],
            "complete": complete, "body_complete": complete,
            "error": "timeout" if not complete else ""}


def test_same_size_different_content_is_not_suppressed():
    async def fetch(url, *_):
        return snapshot(url, "real page" if url.endswith("/admin") else "not found")
    with patch.object(tools, "_http_snapshot", fetch):
        result = asyncio.run(tools.run_dir_enum("http://example.test", "admin"))
    assert len(result["found"]) == 1


def test_dynamic_baseline_retains_candidates_as_ambiguous():
    count = 0
    async def fetch(url, *_):
        nonlocal count
        count += 1
        return snapshot(url, f"nonce {count}")
    with patch.object(tools, "_http_snapshot", fetch):
        result = asyncio.run(tools.run_dir_enum("http://example.test", "admin"))
    assert not result["found"] and len(result["ambiguous"]) == 1


def test_network_failure_marks_incomplete_instead_of_clean():
    async def fetch(url, *_):
        return snapshot(url, "", status="?", complete=False)
    with patch.object(tools, "_http_snapshot", fetch):
        result = asyncio.run(tools.run_dir_enum("http://example.test", "admin"))
    assert not result["complete"] and len(result["errors"]) == 3


@pytest.mark.parametrize("url,wordlist", [("file:///etc/passwd", "admin"),
    ("http://example.test", "../other"), ("http://example.test", "%2e%2e/other"),
    ("http://example.test?x=1", "admin")])
def test_invalid_discovery_input_never_executes(url, wordlist):
    with patch.object(tools, "run_bash", AsyncMock()) as bash:
        assert asyncio.run(tools.run_dir_enum(url, wordlist))["error"]
        bash.assert_not_called()


@pytest.mark.parametrize("evidence", [None, "", "  \n ", 42])
def test_unverified_report_never_reaches_finding_board_or_memory(evidence, tmp_path):
    from types import SimpleNamespace
    from sikun.agent_gemini import _record_report
    from sikun.memory import TargetMemory
    app = SimpleNamespace(post_event=AsyncMock())
    memory = TargetMemory("example.test", tmp_path / "memory.json")
    result = asyncio.run(_record_report(app, memory, {"channel": "finding", "text": "claim", "evidence": evidence}))
    assert result["error"] and not memory.findings
    assert not memory.path.exists()
    assert all(c.args[0] != "finding" for c in app.post_event.call_args_list)


def test_evidenced_report_is_saved(tmp_path):
    from types import SimpleNamespace
    from sikun.agent_gemini import _record_report
    from sikun.memory import TargetMemory
    app = SimpleNamespace(post_event=AsyncMock())
    memory = TargetMemory("example.test", tmp_path / "memory.json")
    result = asyncio.run(_record_report(app, memory, {"channel": "finding", "text": "claim", "evidence": "GET / returned observed content"}))
    assert result == {"result": "ok"} and memory.path.exists()
    assert memory.findings[0]["evidence"] == "GET / returned observed content"


def test_service_memory_enriches_ports_and_preserves_distinct_hosts(tmp_path):
    from sikun.memory import TargetMemory
    memory = TargetMemory("127.0.0.1", tmp_path / "memory.json")
    memory.add_ports([{"port": "443", "protocol": "tcp", "service": "https", "method": "table"}])
    memory.add_ports([{"host": "127.0.0.1", "port": "443", "protocol": "tcp", "service": "http",
                       "version": "nginx 1.26", "method": "probed", "cpes": ["cpe:/a:nginx:nginx:1.26"]}])
    memory.add_ports([{"host": "127.0.0.2", "port": "443", "protocol": "tcp", "service": "https"}])
    memory.add_ports([{"port": "443", "protocol": "tcp", "service": "https", "method": "table"}])
    assert len(memory.ports) == 2
    assert memory.ports[0]["service"] == "http" and memory.ports[0]["cpes"]
    assert "127.0.0.2:443" in memory.summary_for_prompt()


def test_scope_checks_entire_requested_network():
    from sikun.scope import Scope
    scope = Scope(["127.0.0.1", "192.0.2.0/25", "2001:db8::/64"])
    assert not scope.contains("127.0.0.1/8")
    assert not scope.contains("192.0.2.0/24")
    assert scope.contains("192.0.2.0/26")
    assert scope.contains("2001:db8::/80")
    assert scope.contains("127.0.0.1/admin")
    assert scope.contains("127.0.0.1:8080/")
    assert Scope(["example.test"]).contains("example.test/123")


def test_nvd_errors_and_limits_remain_explicit():
    from sikun.plugins import _import_file, PluginContext
    mod = _import_file(Path(__file__).parents[1] / "plugins/cve_lookup.py")
    assert not mod._parse_nvd_ids("error: failed fetching CVE-2021-41773", 5)
    async def error_run(command):
        return "none" if "command -v" in command else "__NVD_ERROR__\n"
    ctx = PluginContext("example.test", None, Path.cwd(), error_run)
    result = asyncio.run(mod.PLUGIN.run({"product": "apache"}, ctx))
    assert result["nvd_status"] == "error" and not result["candidates"]
    async def limit_run(command):
        return "none" if "command -v" in command else '__NVD_OK__\n"totalResults": 500\nCVE-2021-41773\n'
    ctx.run = limit_run
    result = asyncio.run(mod.PLUGIN.run({"product": "apache", "max_results": 1}, ctx))
    assert result["nvd_status"] == "limited"
    assert result["candidates"][0]["verification"] == "unverified"


def test_article_framework_names_do_not_become_fingerprints():
    assert tools._guess_tech({}, "An article comparing Django, Express and Next.js") == []
    assert tools._guess_tech({"X-Powered-By": "Express"}, "") == ["Express/Node.js"]
    assert tools._guess_tech({}, '<script src="/_next/static/main.js"></script>') == ["Next.js"]


@pytest.mark.parametrize("ui", ["tui", "webapp"])
def test_boards_preserve_hosts_and_service_updates(ui):
    from sikun.tui import SikunApp
    from sikun.webapp import WebApp
    app = (SikunApp if ui == "tui" else WebApp)(target="127.0.0.1")
    app._merge_ports([{"host": "127.0.0.1", "port": "80", "protocol": "tcp", "service": "unknown"}])
    app._merge_ports([{"host": "127.0.0.1", "port": "80", "protocol": "tcp", "service": "http"},
                      {"host": "127.0.0.2", "port": "80", "protocol": "tcp", "service": "http"}])
    assert len(app.board["ports"]) == 2 and app.board["ports"][0]["service"] == "http"


def test_nvd_shell_parser_accepts_pretty_json_and_ignores_reference_ids(local_site):
    from sikun.plugins import _import_file
    import shlex
    mod = _import_file(Path(__file__).parents[1] / "plugins/cve_lookup.py")
    payload = json.dumps({"totalResults": 1, "vulnerabilities": [{"cve": {
        "id": "CVE-2021-41773", "description": "Compare CVE-1999-9999"}}]}, indent=2)
    # Simulate curl inside the same shell, keeping the real extraction pipeline.
    prefix = 'curl() { while [ "$1" != "--output" ]; do shift; done; shift; printf "%s" ' + shlex.quote(payload) + ' > "$1"; }\n'
    raw = asyncio.run(tools.run_bash(prefix + mod._nvd_id_command("apache", 5), Path.cwd()))
    assert "__NVD_OK__" in raw
    assert [c["id"] for c in mod._parse_nvd_ids(raw, 5)] == ["CVE-2021-41773"]


def test_missing_shell_returns_incomplete_results():
    with patch.object(tools, "run_bash", AsyncMock(side_effect=FileNotFoundError("bash unavailable"))):
        http = asyncio.run(tools.run_http_probe("http://example.test"))
        nmap = asyncio.run(tools.run_nmap_scan("example.test"))
    assert not http["complete"] and "bash unavailable" in http["error"]
    assert not nmap["complete"] and nmap["error"]
