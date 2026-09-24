"""Regressions for best-effort scope checks on raw commands containing URLs."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from sikun.scope import Scope, ScopeGuard, extract_hosts, guard_besteffort


class ScopeUrlTests(unittest.TestCase):
    def test_userinfo_and_port_do_not_hide_the_destination(self) -> None:
        hosts = extract_hosts("curl 'HTTPS://allowed.example:443@outside.example.test/path'")
        self.assertEqual(hosts, ["outside.example.test"])
        self.assertEqual(Scope(["allowed.example"]).out_of_scope(hosts), hosts)
        allowed = extract_hosts('curl "https://user:password@allowed.example:8443/path"')
        self.assertEqual(allowed, ["allowed.example"])
        self.assertEqual(Scope(["allowed.example"]).out_of_scope(allowed), [])

    def test_bracketed_ipv6_url_is_checked(self) -> None:
        hosts = extract_hosts("curl https://[2001:db8::5]:8443/status")
        self.assertEqual(hosts, ["2001:db8::5"])
        self.assertEqual(extract_hosts("curl https://[2001:db8::5]"), hosts)
        self.assertEqual(Scope(["2001:db8::/32"]).out_of_scope(hosts), [])
        self.assertEqual(Scope(["2001:db9::/32"]).out_of_scope(hosts), hosts)

    def test_out_of_scope_url_requires_operator_choice_and_is_audited(self) -> None:
        class App:
            def __init__(self) -> None:
                self.messages: list[str] = []

            async def post_event(self, _channel: str, message: str) -> None:
                self.messages.append(message)

            async def wait_for_choice(self, _options: list[tuple[str, str]]) -> str:
                return "block"

        with tempfile.TemporaryDirectory() as directory:
            audit = Path(directory) / "audit.jsonl"
            guard = ScopeGuard(Scope(["allowed.example"]), audit, "allowed.example")
            app = App()
            hosts = extract_hosts("curl https://allowed.example:443@outside.example.test/")
            self.assertFalse(asyncio.run(guard_besteffort(app, guard, "bash", hosts)))
            self.assertIn("outside.example.test", app.messages[0])
            self.assertEqual(json.loads(audit.read_text(encoding="utf-8"))["decision"], "operator-block")


if __name__ == "__main__":
    unittest.main()
