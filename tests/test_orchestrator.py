"""Orchestrator-worker core tests — DAG layering, dispatch, scope, merge.

Runs two ways (same as test_foundation.py):
  * `python tests/test_orchestrator.py`  (built-in runner below)
  * `pytest`                             (each test_* is a plain sync function)

Fully offline: workers are in-test stubs, no network, no API key, no SDK
subprocess. The Claude Agent SDK worker (sikun.agent_claude) is intentionally
NOT exercised here — it requires an authorized target and an API key.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

# Allow `python tests/test_orchestrator.py` from the repo root (pytest already
# puts the root on the path).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sikun.orchestrator import (
    SubTask,
    WorkerResult,
    build_layers,
    orchestrate,
    synthesize,
)
from sikun.permission import new_guard, screen_targets


class _Stub:
    """Minimal Worker: returns canned findings and echoes upstream hints so
    dependency wiring is observable."""

    def __init__(self, category, findings=None, hints=None, boom=False):
        self.category = category
        self.findings = findings or []
        self.hints = hints or []
        self.boom = boom
        self.seen_upstream: dict = {}

    async def run(self, task: SubTask, upstream: dict[str, WorkerResult]) -> WorkerResult:
        if self.boom:
            raise RuntimeError("worker exploded")
        self.seen_upstream = dict(upstream)
        return WorkerResult(category=self.category, status="done",
                            findings=list(self.findings), next_hints=list(self.hints))


# ── build_layers ────────────────────────────────────────────────────────────

def test_layers_independent_tasks_one_layer():
    tasks = [SubTask("a", "recon", "g"), SubTask("b", "web", "g"), SubTask("c", "crypto", "g")]
    layers = build_layers(tasks)
    assert len(layers) == 1
    assert {t.id for t in layers[0]} == {"a", "b", "c"}


def test_layers_chain_is_ordered():
    tasks = [
        SubTask("recon", "recon", "g"),
        SubTask("web", "web", "g", depends_on=["recon"]),
        SubTask("exploit", "web", "g", depends_on=["web"]),
    ]
    layers = build_layers(tasks)
    assert [[t.id for t in layer] for layer in layers] == [["recon"], ["web"], ["exploit"]]


def test_layers_diamond():
    # a -> b, a -> c, (b,c) -> d
    tasks = [
        SubTask("a", "recon", "g"),
        SubTask("b", "web", "g", depends_on=["a"]),
        SubTask("c", "mobile", "g", depends_on=["a"]),
        SubTask("d", "web", "g", depends_on=["b", "c"]),
    ]
    layers = build_layers(tasks)
    assert [t.id for t in layers[0]] == ["a"]
    assert {t.id for t in layers[1]} == {"b", "c"}
    assert [t.id for t in layers[2]] == ["d"]


def test_layers_unknown_dependency_raises():
    tasks = [SubTask("a", "recon", "g", depends_on=["ghost"])]
    try:
        build_layers(tasks)
        assert False, "expected ValueError"
    except ValueError as e:
        assert "ghost" in str(e)


def test_layers_cycle_raises():
    tasks = [
        SubTask("a", "recon", "g", depends_on=["b"]),
        SubTask("b", "web", "g", depends_on=["a"]),
    ]
    try:
        build_layers(tasks)
        assert False, "expected ValueError"
    except ValueError as e:
        assert "循環" in str(e)


def test_layers_duplicate_id_raises():
    tasks = [SubTask("a", "recon", "g"), SubTask("a", "web", "g")]
    try:
        build_layers(tasks)
        assert False, "expected ValueError"
    except ValueError as e:
        assert "重複" in str(e)


# ── orchestrate ───────────────────────────────────────────────────────────────

def test_orchestrate_passes_upstream_to_dependents():
    recon = _Stub("recon", findings=[{"type": "open_port", "detail": "8080"}],
                  hints=["look at 8080"])
    web = _Stub("web")
    router = {"recon": recon, "web": web}
    tasks = [SubTask("r", "recon", "g"),
             SubTask("w", "web", "g", depends_on=["r"])]
    results = asyncio.run(orchestrate(tasks, router))
    assert results["r"].status == "done" and results["w"].status == "done"
    # web saw recon's result as upstream
    assert "r" in web.seen_upstream
    assert web.seen_upstream["r"].next_hints == ["look at 8080"]


def test_orchestrate_unknown_category_is_error_not_crash():
    router = {"recon": _Stub("recon")}
    tasks = [SubTask("x", "no_such_category", "g")]
    results = asyncio.run(orchestrate(tasks, router))
    assert results["x"].status == "error"
    assert results["x"].findings[0]["type"] == "no_worker"


def test_orchestrate_worker_exception_contained():
    router = {"recon": _Stub("recon", boom=True)}
    tasks = [SubTask("x", "recon", "g")]
    results = asyncio.run(orchestrate(tasks, router))
    assert results["x"].status == "error"
    assert results["x"].findings[0]["type"] == "exception"


def test_orchestrate_should_stop_halts_further_layers():
    router = {"recon": _Stub("recon"), "web": _Stub("web")}
    tasks = [SubTask("r", "recon", "g"),
             SubTask("w", "web", "g", depends_on=["r"])]
    # stop as soon as layer 0 produced any result
    results = asyncio.run(orchestrate(tasks, router, should_stop=lambda res: "r" in res))
    assert "r" in results and "w" not in results


# ── synthesize ────────────────────────────────────────────────────────────────

def test_synthesize_merges_and_counts():
    results = {
        "a": WorkerResult("recon", "done",
                          findings=[{"type": "open_port", "detail": "8080"}],
                          next_hints=["h1"], scope_touched=["10.0.0.1"]),
        "b": WorkerResult("web", "blocked",
                          findings=[{"type": "scope_block", "detail": "x"}],
                          scope_touched=["10.0.0.1"]),
        "c": WorkerResult("crypto", "error", findings=[{"type": "exception", "detail": "y"}]),
    }
    report = synthesize(results)
    assert report["summary"] == {"tasks": 3, "findings": 3, "blocked": 1, "errors": 1}
    assert report["next_hints"] == ["h1"]
    assert report["scope_touched"] == ["10.0.0.1"]
    # findings are tagged with their source task
    assert all("source" in f and "category" in f for f in report["findings"])


# ── scope enforcement (reused ScopeGuard) ─────────────────────────────────────

def test_scope_blocks_out_of_scope_and_audits():
    with tempfile.TemporaryDirectory() as d:
        audit = Path(d) / "audit.log"
        guard = new_guard(["10.13.37.0/24"], audit, session_target="10.13.37.10")
        assert screen_targets(guard, "recon", ["10.13.37.42"]) is None   # in range
        err = screen_targets(guard, "recon", ["8.8.8.8"])                # out of range
        assert err is not None and "8.8.8.8" in err
        log = audit.read_text(encoding="utf-8")
        assert "blocked" in log and "allow" in log


def test_scope_disabled_allows_all():
    with tempfile.TemporaryDirectory() as d:
        guard = new_guard([], Path(d) / "a.log", session_target="")
        assert screen_targets(guard, "recon", ["8.8.8.8"]) is None       # no enforcement


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
