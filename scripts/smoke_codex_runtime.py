"""Live Codex/SCS smoke test against a local HTTP server only."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sikun.agent_gemini import run_agent
from sikun.profile import Profile
from sikun.tui import LOG_DIR


class Finished(Exception):
    pass


class LabApp:
    def __init__(self) -> None:
        self.session_state = {"mode": "security", "model": "full"}
        self.events: list[str] = []
        self.board: dict = {}

    async def post_event(self, _channel: str, message: str, *_args) -> None:
        self.events.append(message)
        print(message[:300].encode("ascii", "backslashreplace").decode("ascii"), flush=True)

    async def run_interruptible(self, coro):
        return await coro

    async def wait_for_instruction(self) -> str:
        raise Finished()

    async def wait_for_choice(self, _options) -> str:
        return "approve"

    def update_board(self, **kwargs) -> None:
        self.board.update(kwargs)

    def set_activity(self, _label: str) -> None:
        pass

    def clear_activity(self) -> None:
        pass


def main() -> None:
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

        def do_GET(self) -> None:
            requests.append(self.path)
            body = b"<html><title>SCS local lab</title><p>Lab only</p></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/"
    app = LabApp()
    original_key = os.environ.pop("GEMINI_API_KEY", None)

    async def exercise() -> None:
        try:
            await asyncio.wait_for(run_agent(
                app, target=url, workdir=Path.cwd(),
                initial_instruction=f"Use the SCS http_probe action on {url} exactly once. Then report only the observed HTTP status and page title. Do not run any other tool or contact another host.",
                profile=Profile(name="local-lab", model="gpt-6-luna", scope=["127.0.0.1"]),
                engine="codex",
            ), timeout=180)
        except Finished:
            pass

    try:
        asyncio.run(exercise())
        assert requests == ["/"], f"Unexpected local requests: {requests}"
        assert app.board.get("provider") == "codex"
        assert any("http_probe" in event for event in app.events)
        audit = LOG_DIR / "audit.log"
        records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        assert any(record["tool"] == "http_probe" and record["decision"] == "allow"
                   and record["session_target"] == url for record in records)
        print(json.dumps({"result": "passed", "url": url, "requests": requests,
                          "model": app.board.get("model"), "provider": app.board.get("provider")}))
    finally:
        server.shutdown()
        server.server_close()
        if original_key is not None:
            os.environ["GEMINI_API_KEY"] = original_key


if __name__ == "__main__":
    main()
