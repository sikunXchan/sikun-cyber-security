"""The Codex adapter must only hand scope-checked actions to SCS."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from google.genai import types
from unittest.mock import AsyncMock

from sikun import agent_codex
from sikun import agent_gemini
from sikun.engine import resolve_engine
from sikun.profile import Profile
from sikun import tui


class FakeThread:
    def __init__(self, payload: dict):
        self.payload = payload
        self.prompts: list[str] = []

    async def run(self, prompt: str, **_kwargs):
        self.prompts.append(prompt)
        return SimpleNamespace(final_response=json.dumps(self.payload))


class FakeCodex:
    thread: FakeThread

    def __init__(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def thread_start(self, **kwargs):
        assert kwargs["sandbox"] == agent_codex.Sandbox.read_only
        assert kwargs["approval_mode"] == agent_codex.ApprovalMode.deny_all
        assert kwargs["config"]["web_search"] == "disabled"
        return self.thread


def config() -> types.GenerateContentConfig:
    declarations = [types.FunctionDeclaration(name=name, description=name,
                    parameters={"type": "object", "properties": {}})
                    for name in ("bash", "http_probe", "report")]
    return types.GenerateContentConfig(tools=[types.Tool(function_declarations=declarations)],
                                       system_instruction="Only authorized targets")


def test_codex_security_mode_uses_structured_scope_checked_action(monkeypatch, tmp_path: Path):
    FakeCodex.thread = FakeThread({"kind": "tool", "name": "http_probe",
                                   "args_json": '{"url":"http://127.0.0.1/"}', "text": ""})
    monkeypatch.setattr(agent_codex, "AsyncCodex", FakeCodex)

    async def exercise():
        adapter = agent_codex.CodexModelAdapter(tmp_path, "security")
        adapter.scope_enabled = True
        response = await adapter.generate_content(
            model="gpt-6-sol", config=config(),
            contents=[types.Content(role="user", parts=[types.Part(text="Check the local lab")])],
        )
        await adapter.close()
        return response

    response = asyncio.run(exercise())
    call = response.candidates[0].content.parts[0].function_call
    assert call.name == "http_probe"
    assert call.args["url"] == "http://127.0.0.1/"
    assert '"name": "bash"' not in FakeCodex.thread.prompts[0]
    assert '"name": "http_probe"' in FakeCodex.thread.prompts[0]


@pytest.mark.parametrize("mode,scope", [("study", False), ("general", True), ("security", False)])
def test_codex_without_security_scope_never_offers_network_actions(monkeypatch, tmp_path: Path, mode, scope):
    FakeCodex.thread = FakeThread({"kind": "tool", "name": "http_probe",
                                   "args_json": '{"url":"http://outside.test/"}', "text": ""})
    monkeypatch.setattr(agent_codex, "AsyncCodex", FakeCodex)

    async def exercise():
        adapter = agent_codex.CodexModelAdapter(tmp_path, mode)
        adapter.scope_enabled = scope
        try:
            await adapter.generate_content(model="gpt-6-sol", config=config(),
                contents=[types.Content(role="user", parts=[types.Part(text="Test")])])
        finally:
            await adapter.close()

    with pytest.raises(ValueError, match="unavailable action"):
        asyncio.run(exercise())
    assert '"name": "http_probe"' not in FakeCodex.thread.prompts[0]


def test_auto_engine_prefers_codex_without_gemini_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert resolve_engine("auto") == "codex"


def test_codex_tui_does_not_show_gemini_cost(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(tui, "LOG_DIR", tmp_path)
    app = tui.SikunApp(target="127.0.0.1")
    try:
        app.board.update(provider="codex", cost=42.0, model="gpt-6-sol")
        assert "$42" not in app._status_text()
        assert "COST" not in app._board_renderable().plain
    finally:
        app._log_file.close()


def test_codex_runtime_blocks_out_of_scope_probe_before_network(monkeypatch, tmp_path: Path):
    class Stop(Exception):
        pass

    class App:
        def __init__(self):
            self.session_state = {"mode": "security"}
            self.events = []

        async def post_event(self, _channel, message, *_args):
            self.events.append(message)

        async def run_interruptible(self, coro):
            return await coro

        async def wait_for_instruction(self):
            raise Stop()

        def update_board(self, **_kwargs):
            pass

    class Shell:
        def __init__(self, **_kwargs):
            pass

        async def start(self):
            pass

        async def stop(self):
            pass

        async def run(self, _command):
            raise AssertionError("Codex cannot request raw shell actions")

    class Adapter:
        is_codex = True

        def __init__(self, *_args):
            self.aio = SimpleNamespace(models=self)
            self.calls = 0

        async def generate_content(self, **_kwargs):
            self.calls += 1
            part = (types.Part(function_call=types.FunctionCall(
                name="http_probe", args={"url": "http://outside.test/"}))
                if self.calls == 1 else types.Part(text="No scoped network action was run."))
            return types.GenerateContentResponse(candidates=[types.Candidate(
                content=types.Content(role="model", parts=[part]),
                finish_reason=types.FinishReason.STOP,
            )])

        async def close(self):
            pass

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(agent_codex, "CodexModelAdapter", Adapter)
    monkeypatch.setattr(agent_gemini, "PersistentShell", Shell)
    monkeypatch.setattr(agent_gemini, "LOG_DIR", tmp_path)
    probe = AsyncMock()
    monkeypatch.setattr(agent_gemini, "run_http_probe", probe)
    app = App()
    with pytest.raises(Stop):
        asyncio.run(agent_gemini.run_agent(app, target="allowed.test",
            initial_instruction="Probe only the allowed host", profile=Profile(scope=["allowed.test"]),
            engine="codex"))
    probe.assert_not_awaited()
    assert any("outside.test" in event for event in app.events)
    assert '"decision": "blocked"' in (tmp_path / "audit.log").read_text(encoding="utf-8")
