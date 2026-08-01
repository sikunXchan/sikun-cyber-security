"""v1.0 foundation tests — profiles, plugins, scaffold, parsers, TUI board.

Runs two ways:
  * `python tests/test_foundation.py`  (no extra deps — uses the built-in runner below)
  * `pytest`                           (each test_* is a plain sync function)

Every test is offline: the one plugin that shells out is driven with a fake
`ctx.run`, so nothing here touches the network or an API key.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from sikun import scaffold
from sikun.plugins import PluginContext, load_plugins
from sikun.profile import PROJECT_ROOT, load_profile
from sikun.scope import Scope, ScopeGuard, extract_hosts, guard_besteffort, guard_reliable
from sikun.tools import _guess_tech, _parse_http_headers
from sikun.tui import SikunApp


def test_default_profile_loads():
    p = load_profile(None)
    assert p.name == "default"
    assert p.plugin_dirs and p.plugin_dirs[0].name == "plugins"


def test_example_plugin_loads_and_runs():
    p = load_profile(None)
    result = load_plugins(p.plugin_dirs)
    assert not result.errors, result.errors
    by_name = {pl.name: pl for pl in result.plugins}
    assert "reverse_dns" in by_name

    async def fake_run(cmd: str) -> str:
        assert "9.9.9.9" in cmd
        return "9.9.9.9 dns9.example."

    ctx = PluginContext(target="9.9.9.9", ssh_host=None, workdir=Path.home(), run=fake_run)
    out = asyncio.run(by_name["reverse_dns"].run({"ip": "9.9.9.9"}, ctx))
    assert out["ip"] == "9.9.9.9" and "dns9.example" in out["result"]


def test_plugin_loader_rejects_reserved_and_broken():
    with tempfile.TemporaryDirectory() as d:
        dir_ = Path(d)
        # reserved name -> rejected
        (dir_ / "bad_reserved.py").write_text(
            "from sikun.plugins import ToolPlugin\n"
            "async def _r(a, c): return {}\n"
            "PLUGIN = ToolPlugin(name='bash', description='x', parameters={'type':'object','properties':{}}, run=_r)\n"
        )
        # syntax error -> reported, not fatal
        (dir_ / "broken.py").write_text("def oops(:\n")
        # underscore-prefixed -> ignored entirely
        (dir_ / "_helper.py").write_text("x = 1\n")
        # one good plugin still loads alongside the bad ones
        (dir_ / "good.py").write_text(
            "from sikun.plugins import ToolPlugin\n"
            "async def _r(a, c): return {'ok': True}\n"
            "PLUGIN = ToolPlugin(name='good_tool', description='x', parameters={'type':'object','properties':{}}, run=_r)\n"
        )
        result = load_plugins([dir_])
        names = {pl.name for pl in result.plugins}
        assert names == {"good_tool"}, names
        assert any("予約名" in e for e in result.errors)
        assert any("broken.py" in e for e in result.errors)


def test_scaffold_creates_and_skips():
    name = "unittest_scaffold_tmp"
    prof = PROJECT_ROOT / "profiles" / f"{name}.toml"
    plug = PROJECT_ROOT / "plugins" / f"{name}_ping.py"
    try:
        created, skipped = scaffold.init_agent(name)
        assert prof.exists() and plug.exists()
        assert not skipped
        # second run skips existing files rather than clobbering
        created2, skipped2 = scaffold.init_agent(name)
        assert not created2 and len(skipped2) == 2
        # generated artifacts are valid
        assert load_profile(name).name == name
        assert f"{name}_ping" in {pl.name for pl in load_plugins([PROJECT_ROOT / "plugins"]).plugins}
    finally:
        prof.unlink(missing_ok=True)
        plug.unlink(missing_ok=True)


def test_http_header_parser_keeps_last_hop():
    raw = (
        "HTTP/1.1 301 Moved Permanently\r\nLocation: http://x/\r\n\r\n"
        "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: PHP/8.1\r\n\r\n"
    )
    status, headers = _parse_http_headers(raw)
    assert status == "200", status
    assert headers.get("Server") == "nginx", headers


def test_guess_tech_from_fingerprints():
    tech = _guess_tech({"Server": "nginx", "X-Powered-By": "PHP/8.1"}, "")
    assert "nginx" in tech and "PHP" in tech


def test_http_probe_surfaces_server_version():
    # http_probe must expose the version-bearing Server / X-Powered-By headers as
    # first-class fields so cve_lookup gets middleware+version, not just "Apache".
    from unittest import mock

    from sikun import tools

    raw = (
        "__SIKUN_HEADERS__\nHTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n"
        "X-Powered-By: PHP/7.4.3\r\n\r\n__SIKUN_BODY__<title>x</title>"
    )

    async def fake_bash(*a, **k):
        return raw

    with mock.patch.object(tools, "run_bash", fake_bash):
        result = asyncio.run(tools.run_http_probe("http://127.0.0.1:8080"))
    assert result["server"] == "Apache/2.4.49"
    assert result["x_powered_by"] == "PHP/7.4.3"


def test_tui_board_tracks_state():
    async def run():
        app = SikunApp(target="192.168.56.10", profile_name="default")
        async with app.run_test() as pilot:
            app.update_board(
                model="gemini-3.5-flash",
                cost=0.1234,
                ports=[
                    {"port": "22", "protocol": "tcp", "service": "ssh"},
                    {"port": "80", "protocol": "tcp", "service": "http"},
                ],
            )
            app.update_board(ports=[{"port": "22", "protocol": "tcp", "service": "ssh"}])
            await app.post_event("finding", "SQLi 認証バイパス", "high")
            await app.post_event("recon", "port 22 open")
            await pilot.pause()
            assert len(app.board["ports"]) == 2
            assert app.board["findings"]["high"] == 1
            assert app.board["phase"] == "recon"
            app._board_renderable()  # must not raise
            assert "gemini-3.5-flash" in app._status_text()

    asyncio.run(run())


def test_scope_matching():
    s = Scope(["10.20.0.0/24", "192.168.56.10", "shop.example.local"])
    assert s.enabled
    assert s.contains("10.20.0.5")
    assert s.contains("http://10.20.0.5:8080/admin")
    assert s.contains("192.168.56.10")
    assert s.contains("api.shop.example.local")  # subdomain
    assert not s.contains("10.20.1.5")           # neighbouring /24
    assert not s.contains("8.8.8.8")
    assert not s.contains("evil.example.com")


def test_scope_disabled_allows_all():
    s = Scope([])
    assert not s.enabled
    assert s.out_of_scope(["8.8.8.8", "anything"]) == []


def test_extract_hosts_from_command():
    hosts = extract_hosts("nmap -Pn 10.0.0.5 && curl http://10.0.0.9:8080/x")
    assert "10.0.0.5" in hosts and "10.0.0.9" in hosts
    # version-like dotted numbers that aren't valid IPs shouldn't crash it
    assert isinstance(extract_hosts("pip install foo==1.2.3"), list)


def test_guard_reliable_blocks_and_audits():
    import json as _json

    with tempfile.TemporaryDirectory() as d:
        audit = Path(d) / "audit.log"
        guard = ScopeGuard(Scope(["10.0.0.0/24"]), audit, "10.0.0.5")
        assert guard_reliable(guard, "nmap_scan", ["10.0.0.5"]) is None      # in scope
        err = guard_reliable(guard, "nmap_scan", ["9.9.9.9"])                # out of scope
        assert err and "9.9.9.9" in err
        lines = [ _json.loads(x) for x in audit.read_text().splitlines() ]
        assert lines[0]["decision"] == "allow" and lines[1]["decision"] == "blocked"


def test_guard_besteffort_confirms_out_of_scope():
    class _FakeApp:
        def __init__(self, choice):
            self._choice = choice
            self.posted = []

        async def post_event(self, ch, text, sev=None):
            self.posted.append(text)

        async def wait_for_choice(self, options):
            return self._choice

    with tempfile.TemporaryDirectory() as d:
        guard = ScopeGuard(Scope(["10.0.0.0/24"]), Path(d) / "a.log", "10.0.0.5")
        # in-scope: proceeds without prompting
        assert asyncio.run(guard_besteffort(_FakeApp("block"), guard, "bash", ["10.0.0.9"])) is True
        # out-of-scope + operator blocks
        assert asyncio.run(guard_besteffort(_FakeApp("block"), guard, "bash", ["9.9.9.9"])) is False
        # out-of-scope + operator overrides
        assert asyncio.run(guard_besteffort(_FakeApp("allow"), guard, "bash", ["9.9.9.9"])) is True


def test_example_plugin_declares_scope_targets():
    plugins = {p.name: p for p in load_plugins([PROJECT_ROOT / "plugins"]).plugins}
    rd = plugins["reverse_dns"]
    assert rd.scope_targets is not None
    assert rd.scope_targets({"ip": "1.2.3.4"}) == ["1.2.3.4"]


def _load_cve_plugin():
    from sikun.plugins import _import_file

    return _import_file(PROJECT_ROOT / "plugins" / "cve_lookup.py")


def test_cve_lookup_parsers_tolerate_exit_prefix():
    mod = _load_cve_plugin()
    ss_raw = "[exit=0]\n" + json.dumps(
        {"RESULTS_EXPLOIT": [{"Title": "vsftpd 2.3.4 - Backdoor", "EDB-ID": "17491", "Path": "/x/17491.rb"}]}
    )
    got = mod._parse_searchsploit_json(ss_raw, 15)
    assert got and got[0]["id"] == "17491" and got[0]["source"] == "exploit-db"

    # NVD path now extracts CVE IDs via grep on the target -> one ID per line
    nvd_raw = "[exit=0]\nCVE-2011-2523\nCVE-2021-41773\nCVE-2011-2523\n"
    got = mod._parse_nvd_ids(nvd_raw, 15)
    assert [c["id"] for c in got] == ["CVE-2011-2523", "CVE-2021-41773"]  # dedup, order kept
    assert all(c["source"] == "nvd" for c in got)


def _cve_plugin():
    return {p.name: p for p in load_plugins([PROJECT_ROOT / "plugins"]).plugins}["cve_lookup"]


def test_cve_lookup_merges_sources_when_searchsploit_present():
    plugin = _cve_plugin()
    assert plugin.scope_targets is not None and plugin.scope_targets({"product": "x"}) == []

    async def fake_run(cmd: str) -> str:
        if "command -v searchsploit" in cmd:
            return "[exit=0]\n/usr/bin/searchsploit"
        if "searchsploit --json" in cmd:
            assert "vsftpd" in cmd
            return "[exit=0]\n" + json.dumps(
                {"RESULTS_EXPLOIT": [{"Title": "vsftpd 2.3.4 - Backdoor", "EDB-ID": "17491", "Path": "/x.rb"}]}
            )
        if "nist.gov" in cmd:
            assert "grep -oE" in cmd  # NVD path extracts IDs on the target
            return "[exit=0]\nCVE-2011-2523\n"
        return "[exit=0]\n"

    ctx = PluginContext(target="10.0.0.5", ssh_host=None, workdir=Path.home(), run=fake_run)
    out = asyncio.run(plugin.run({"product": "vsftpd", "version": "2.3.4"}, ctx))
    ids = {c["id"] for c in out["candidates"]}
    assert "17491" in ids and "CVE-2011-2523" in ids
    assert out["sources_tried"] == ["searchsploit", "nvd"]


def test_cve_lookup_falls_back_when_no_searchsploit():
    plugin = _cve_plugin()

    async def fake_run(cmd: str) -> str:
        if "command -v searchsploit" in cmd:
            return "[exit=0]\nnone"
        if "nist.gov" in cmd:
            return "[exit=0]\n"  # grep found no CVE IDs
        return "[exit=0]\n"

    ctx = PluginContext(target="10.0.0.5", ssh_host=None, workdir=Path.home(), run=fake_run)
    out = asyncio.run(plugin.run({"product": "openssh"}, ctx))
    assert "searchsploit" not in out["sources_tried"]
    assert any("searchsploit" in n for n in out["notes"])


def _detection_plugin():
    return {p.name: p for p in load_plugins([PROJECT_ROOT / "plugins"]).plugins}["detection_rule"]


def test_detection_rule_builds_valid_sigma():
    plugin = _detection_plugin()
    assert plugin.scope_targets is not None and plugin.scope_targets({}) == []

    async def noop_run(cmd: str) -> str:
        return ""

    ctx = PluginContext(target="10.0.0.5", ssh_host=None, workdir=Path.home(), run=noop_run)
    out = asyncio.run(
        plugin.run(
            {
                "title": "Nmap SYN scan",
                "selection": "CommandLine|contains: -sS\nImage|endswith: /nmap",
                "logsource_category": "process_creation",
                "logsource_product": "linux",
                "level": "medium",
                "tags": "attack.t1046 attack.discovery",
                "save": False,
            },
            ctx,
        )
    )
    assert out["saved_to"] is None  # save=False
    assert out["data_source"]["watched_fields"] == ["CommandLine|contains", "Image|endswith"]
    sigma = out["sigma"]
    for needle in ("title:", "detection:", "selection:", "condition:", "level:", "process_creation", "attack.t1046"):
        assert needle in sigma, (needle, sigma)


def test_detection_rule_parse_selection_list_and_validation():
    from sikun.plugins import _import_file

    mod = _import_file(PROJECT_ROOT / "plugins" / "detection_rule.py")
    sel = mod._parse_selection("DestinationPort: 80,443,8080\nUser: root")
    assert sel["DestinationPort"] == ["80", "443", "8080"]
    assert sel["User"] == "root"
    # empty match values are skipped (a `field: ""` rule matches everything)
    sel2 = mod._parse_selection('a|contains: -sS\nb|contains:\nc|contains: ""')
    assert sel2 == {"a|contains": "-sS"}

    async def noop_run(cmd: str) -> str:
        return ""

    ctx = PluginContext(target="x", ssh_host=None, workdir=Path.home(), run=noop_run)
    # invalid level downgraded to medium with a note; empty selection -> error
    out = asyncio.run(mod.PLUGIN.run({"title": "t", "selection": "A: 1", "level": "bogus", "save": False}, ctx))
    assert out["level"] == "medium" and any("level" in n for n in out["notes"])
    err = asyncio.run(mod.PLUGIN.run({"title": "t", "selection": "", "save": False}, ctx))
    assert "error" in err


def test_detection_rule_saves_file():
    from sikun.plugins import _import_file

    mod = _import_file(PROJECT_ROOT / "plugins" / "detection_rule.py")

    async def noop_run(cmd: str) -> str:
        return ""

    ctx = PluginContext(target="x", ssh_host=None, workdir=Path.home(), run=noop_run)
    out = asyncio.run(
        mod.PLUGIN.run({"title": "unittest detrule tmp", "selection": "A: 1", "save": True}, ctx)
    )
    saved = PROJECT_ROOT / out["saved_to"]
    try:
        assert saved.exists() and saved.read_text().startswith("title:")
    finally:
        saved.unlink(missing_ok=True)


def test_remediate_resolves_class_and_maps_priority():
    from sikun.plugins import _import_file

    mod = _import_file(PROJECT_ROOT / "plugins" / "remediate.py")

    # free-form / alias / non-ascii class strings all resolve to canonical keys
    assert mod._resolve_class("SQL injection in login")[0] == "sqli"
    assert mod._resolve_class("IDOR")[0] == "broken_access_control"
    assert mod._resolve_class("機密ファイルの露出")[0] == "sensitive_data_exposure"
    assert mod._resolve_class("quantum bug")[0] is None  # unknown -> None

    async def noop_run(cmd: str) -> str:
        return ""

    ctx = PluginContext(target="x", ssh_host=None, workdir=Path.home(), run=noop_run)

    # severity -> priority is deterministic; curated fixes come through
    out = asyncio.run(
        mod.PLUGIN.run(
            {"title": "t", "vuln_class": "sqli", "severity": "critical", "save": False}, ctx
        )
    )
    assert out["priority"] == "P0" and out["cwe"] == "CWE-89" and out["fixes"]

    # unknown class still produces generic advice (never crashes) with a note
    unk = asyncio.run(mod.PLUGIN.run({"title": "t", "vuln_class": "quantum bug", "save": False}, ctx))
    assert unk["fixes"] and any("未知" in n for n in unk["notes"])

    # missing required args -> error, not exception
    assert "error" in asyncio.run(mod.PLUGIN.run({"title": "t", "vuln_class": "", "save": False}, ctx))

    # touches no host -> scope_targets empty (safe by construction)
    assert mod.PLUGIN.scope_targets({"title": "t", "vuln_class": "sqli"}) == []


def test_remediate_saves_file():
    from sikun.plugins import _import_file

    mod = _import_file(PROJECT_ROOT / "plugins" / "remediate.py")

    async def noop_run(cmd: str) -> str:
        return ""

    ctx = PluginContext(target="x", ssh_host=None, workdir=Path.home(), run=noop_run)
    out = asyncio.run(
        mod.PLUGIN.run({"title": "unittest remediation tmp", "vuln_class": "xss", "save": True}, ctx)
    )
    saved = PROJECT_ROOT / out["saved_to"]
    try:
        assert saved.exists() and saved.read_text().startswith("# 修復アドバイス:")
    finally:
        saved.unlink(missing_ok=True)


def test_study_mode_selects_learning_prompt_and_forbids_attacks():
    # /mode study (the daily-driver) must pick the study template — learning +
    # defensive analysis, explicitly no remote attacks and no executing
    # untrusted code — not the offensive or general one.
    import sikun.agent_gemini as ag

    sec = ag._build_config("x", "security").system_instruction
    study = ag._build_config("x", "study").system_instruction
    general = ag._build_config("x", "general").system_instruction

    assert study != sec and study != general
    assert "学習" in study and "解析" in study
    # the safety spine: no attacks, never run suspicious code, redirect to security
    assert "実行しない" in study and "/mode security" in study
    # unknown mode still falls back to the general assistant (no crash)
    assert ag._build_config("x", "banana").system_instruction == general


def test_coverage_gate_fires_once_after_work_in_security_mode():
    # The coverage gate forces one breadth audit before the agent may conclude,
    # but only when it actually did attack work this segment, only in security
    # mode, and never twice for the same segment (no loop, no Q&A false-fire).
    import sikun.agent_gemini as ag

    assert ag._should_audit_coverage("security", True, False) is True  # worked, not yet audited
    assert ag._should_audit_coverage("security", True, True) is False  # already audited -> no re-fire
    assert ag._should_audit_coverage("security", False, False) is False  # no work -> pure Q&A, skip
    assert ag._should_audit_coverage("general", True, False) is False  # not an attack engagement
    # the nudge is breadth-oriented and explicitly permits 保留 (no runaway)
    assert "網羅" in ag.COVERAGE_NUDGE and "保留" in ag.COVERAGE_NUDGE


def test_report_tool_has_evidence_field():
    # finding verification loop: the report tool must accept an `evidence` arg
    import sikun.agent_gemini as ag

    params = ag.REPORT_DECLARATION.parameters
    props = params["properties"] if isinstance(params, dict) else params.properties
    assert "evidence" in props


def test_turn_productivity_detection_drives_self_correction():
    # The stall detector that triggers a re-plan turn: progress resets the
    # streak, a flailing (empty/error) tool turn counts as unproductive.
    from types import SimpleNamespace

    from sikun.agent_gemini import _turn_was_productive

    def call(name, **args):
        return SimpleNamespace(function_call=SimpleNamespace(name=name, args=args), function_response=None)

    def resp(name, response):
        return SimpleNamespace(function_call=None, function_response=SimpleNamespace(name=name, response=response))

    # productive signals
    assert _turn_was_productive([call("report", channel="finding")], [])
    assert _turn_was_productive([], [resp("nmap_scan", {"open_ports": [{"port": 22}]})])
    assert _turn_was_productive([], [resp("dir_enum", {"found": [{"path": "/admin"}]})])
    assert _turn_was_productive([], [resp("http_probe", {"status": "200"})])
    assert _turn_was_productive([], [resp("bash", {"output": "x" * 60})])
    # unproductive: no new ports, a 404, a short/errored shell
    assert not _turn_was_productive(
        [],
        [
            resp("nmap_scan", {"open_ports": []}),
            resp("http_probe", {"status": "404"}),
            resp("bash", {"output": "", "error": "connection refused"}),
        ],
    )
    # long BUT failing shell output is a flail, not progress
    assert not _turn_was_productive(
        [], [resp("bash", {"output": "curl: (7) Failed to connect to host: Connection refused\n" * 2})]
    )


def test_privesc_enum_parses_and_flags_notable():
    from sikun.plugins import _import_file

    mod = _import_file(PROJECT_ROOT / "plugins" / "privesc_enum.py")
    raw = "\n".join(
        [
            "[exit=0]",
            "###ID###",
            "uid=1000(user) gid=1000(user) groups=1000(user)",
            "###SUDO###",
            "User user may run the following commands:",
            "    (root) NOPASSWD: /usr/bin/find",
            "###SUID###",
            "/usr/bin/find",
            "/usr/bin/passwd",
            "/usr/bin/sudo",
            "###KERNEL###",
            "Linux box 5.4.0-42-generic x86_64",
            "###CAPS###",
            "/usr/bin/python3.8 = cap_setuid+ep",
            "###PASSWD###",
            "-rw-r--r-- 1 root root 2000 /etc/passwd",
            "-rw-r----- 1 root shadow 1000 /etc/shadow",
            "###WORLD_WRITABLE###",
            "###DONE###",
        ]
    )
    sections = mod._parse_sections(raw)
    assert "uid=1000" in sections["ID"]
    notable = mod._analyze(sections)
    joined = " ".join(notable)
    assert "NOPASSWD" in joined
    assert "find" in joined  # GTFOBins SUID hit
    assert "cap_setuid" in joined


def test_privesc_enum_run_and_scope():
    plugin = {p.name: p for p in load_plugins([PROJECT_ROOT / "plugins"]).plugins}["privesc_enum"]
    assert plugin.scope_targets is not None and plugin.scope_targets({}) == []

    async def fake_run(cmd: str) -> str:
        assert "###ID###" in cmd  # runs the combined enumeration script
        return "[exit=0]\n###ID###\nuid=0(root)\n###SUID###\n/bin/bash\n###DONE###"

    ctx = PluginContext(target="10.0.0.5", ssh_host=None, workdir=Path.home(), run=fake_run)
    out = asyncio.run(plugin.run({}, ctx))
    assert "uid=0(root)" in out["host_user"]
    assert any("bash" in n for n in out["notable"])  # /bin/bash SUID flagged


def test_system_prompt_has_persistence_and_efficiency_guidance():
    from sikun.prompts import SYSTEM_PROMPT_TEMPLATE

    # field-test-driven guidance: adapt-then-honestly-stop + no huge-bundle fetches
    assert "成功を偽らず" in SYSTEM_PROMPT_TEMPLATE
    assert "バンドルを丸ごと取得しない" in SYSTEM_PROMPT_TEMPLATE


def test_dir_enum_wordlist_expanded_for_discovery():
    from sikun.tools import _DEFAULT_DIR_WORDLIST

    for path in ("main.js.map", "metrics", "api-docs", ".git/HEAD"):
        assert path in _DEFAULT_DIR_WORDLIST, path


def test_builtin_tools_match_prompt_advertised_tools():
    """SYSTEM_PROMPT_TEMPLATE tells the model to prefer nmap_scan/http_probe/
    dir_enum over raw bash and to feed cve_lookup from them. That's a lie if the
    backend doesn't actually register those tools — a gap that shipped once. Pin
    the built-in tool names so the prompt and the registered tools can't drift."""
    from sikun import agent_gemini

    names = {d.name for d in agent_gemini.TOOLS.function_declarations}
    for advertised in ("bash", "report", "nmap_scan", "http_probe", "dir_enum", "propose_plan"):
        assert advertised in names, (advertised, names)


def test_model_tier_defaults_to_lite():
    from sikun.agent_gemini import _resolve_tier

    class _FakeApp:
        def __init__(self, state: dict) -> None:
            self.session_state = state

    assert _resolve_tier(_FakeApp({})) == "lite"
    assert _resolve_tier(_FakeApp({"model": "full"})) == "full"
    assert _resolve_tier(_FakeApp({"model": "lite"})) == "lite"


def test_target_memory_persists_and_summarizes():
    import sikun.memory as mem

    with tempfile.TemporaryDirectory() as d:
        # redirect memory dir to a temp location for the test
        orig = mem.MEMORY_DIR
        mem.MEMORY_DIR = Path(d)
        try:
            m = mem.TargetMemory.load("10.9.9.9")
            assert not m.has_history()
            m.add_ports([{"port": "21", "protocol": "tcp", "service": "ftp", "version": "vsftpd 2.3.4"}])
            m.add_ports([{"port": "21", "protocol": "tcp", "service": "ftp"}])  # dup
            m.add_finding("critical", "vsftpd backdoor RCE", "uid=0(root) via 6200")
            m.add_finding("critical", "vsftpd backdoor RCE", "x")  # dup by (sev,text)
            m.save()
            assert len(m.ports) == 1 and len(m.findings) == 1

            # reload from disk -> cross-session recall
            m2 = mem.TargetMemory.load("10.9.9.9")
            assert m2.has_history()
            s = m2.summary_for_prompt()
            assert "vsftpd 2.3.4" in s and "backdoor RCE" in s and "uid=0(root)" in s
        finally:
            mem.MEMORY_DIR = orig


def test_target_memory_no_history_empty_summary():
    import sikun.memory as mem

    with tempfile.TemporaryDirectory() as d:
        orig = mem.MEMORY_DIR
        mem.MEMORY_DIR = Path(d)
        try:
            assert mem.TargetMemory.load("fresh.host").summary_for_prompt() == ""
        finally:
            mem.MEMORY_DIR = orig


def _main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
