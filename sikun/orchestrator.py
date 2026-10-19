"""Orchestrator-worker core — model-agnostic task decomposition and dispatch.

The parent ("orchestrator") turns a user instruction into a DAG of `SubTask`s,
runs the DAG layer by layer (independent tasks in a layer run in parallel,
dependent tasks wait for their upstream layer), and merges the structured
results back. Nothing in this module depends on any LLM provider: a `Worker`
is just an async callable, so the same orchestration drives a Claude Agent SDK
worker (``sikun.agent_claude``), a mock worker (``experiments/``), or anything
else. That keeps the decomposition logic unit-testable without launching an
agent.

Design rationale (see also docs, now removed, and the PR description):

- **Independent subtasks parallelize; chained steps do not.** A subtask whose
  intermediate output another subtask needs *right away* must either be the
  same subtask or be joined by a ``depends_on`` edge — never split so the
  orchestrator has to shuttle half-results between them. ``build_layers``
  enforces exactly this: it groups tasks by dependency depth.
- **Workers return structured results, not free text**, so merging is
  deterministic (`synthesize`).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Protocol


@dataclass
class SubTask:
    """One unit of work the orchestrator hands to a worker.

    ``depends_on`` lists the ids of subtasks whose results must be available
    before this one runs — the edges of the DAG. ``tools`` and ``scope`` are
    the subset of tools and the authorized targets this worker is allowed to
    use, so a child can be least-privileged (e.g. the web worker only reaches
    the admin-panel host).
    """

    id: str
    category: str
    goal: str
    depends_on: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)


@dataclass
class WorkerResult:
    """What a worker returns to the orchestrator. Structured on purpose: free
    text makes cross-worker merging ambiguous. ``next_hints`` is how a worker
    passes a lead to a later layer (the orchestrator forwards upstream results
    to dependents)."""

    category: str
    status: str                                   # "done" | "blocked" | "error"
    findings: list[dict[str, Any]] = field(default_factory=list)
    next_hints: list[str] = field(default_factory=list)
    scope_touched: list[str] = field(default_factory=list)
    raw: Any = None                               # worker-specific extra payload


class Worker(Protocol):
    """A category worker. Given its task and the results of everything it
    depended on, it produces one ``WorkerResult``. Async so a layer's workers
    can run concurrently."""

    async def run(self, task: SubTask, upstream: dict[str, WorkerResult]) -> WorkerResult:
        ...


# A router maps a task's category to the worker that handles it.
Router = dict[str, Worker]
# Optional early-stop predicate, evaluated after each completed layer (e.g.
# "a flag was found, stop scheduling further layers").
StopPredicate = Callable[[dict[str, WorkerResult]], bool]


def build_layers(tasks: list[SubTask]) -> list[list[SubTask]]:
    """Topologically sort ``tasks`` into layers by dependency depth.

    Tasks in the same returned list are mutually independent and may run in
    parallel; each list only runs once every earlier list has finished. This
    is Kahn's algorithm grouped by level.

    Raises ``ValueError`` on an unknown dependency id or a dependency cycle —
    both are decomposition bugs the orchestrator should surface loudly rather
    than silently drop a task.

    Example::

        recon-1  depends_on []            ─┐ layer 0 (parallel)
        app-1    depends_on []            ─┤
        fw-1     depends_on []            ─┘
        web-1    depends_on [recon-1]      ─ layer 1 (needs recon-1)
    """
    by_id: dict[str, SubTask] = {}
    for t in tasks:
        if t.id in by_id:
            raise ValueError(f"重複した SubTask id: {t.id}")
        by_id[t.id] = t

    # Validate edges up front so the error names the offending task.
    for t in tasks:
        for dep in t.depends_on:
            if dep not in by_id:
                raise ValueError(f"SubTask {t.id} の depends_on に未知の id: {dep}")

    remaining = {t.id: set(t.depends_on) for t in tasks}
    layers: list[list[SubTask]] = []
    done: set[str] = set()

    while remaining:
        # Ready = every dependency already satisfied in an earlier layer.
        ready = [tid for tid, deps in remaining.items() if deps <= done]
        if not ready:
            cyc = ", ".join(sorted(remaining))
            raise ValueError(f"依存の循環を検出(解決不能な SubTask): {cyc}")
        # Stable order within a layer: keep the caller's task order.
        ready_sorted = [t.id for t in tasks if t.id in ready]
        layers.append([by_id[tid] for tid in ready_sorted])
        done.update(ready)
        for tid in ready:
            del remaining[tid]

    return layers


async def orchestrate(
    tasks: list[SubTask],
    router: Router,
    *,
    should_stop: StopPredicate | None = None,
    on_event: Callable[[str, str], Awaitable[None] | None] | None = None,
) -> dict[str, WorkerResult]:
    """Run the DAG: for each layer, dispatch all its tasks concurrently, then
    move to the next. Returns ``{task_id: WorkerResult}`` for every task that
    ran (tasks after an early stop are simply not scheduled).

    ``router`` picks the worker per ``task.category``; a category with no
    worker yields a ``status="error"`` result rather than crashing the run.
    ``on_event`` (optional) is a UI sink — called with ``(channel, text)`` so a
    TUI/GUI can show progress; it may be sync or async.
    """

    async def emit(channel: str, text: str) -> None:
        if on_event is None:
            return
        res = on_event(channel, text)
        if asyncio.iscoroutine(res):
            await res

    results: dict[str, WorkerResult] = {}
    layers = build_layers(tasks)

    for depth, layer in enumerate(layers):
        await emit(
            "system",
            f"層 {depth}: {len(layer)} タスクを並列実行 "
            f"({', '.join(t.id for t in layer)})",
        )

        async def run_one(task: SubTask) -> tuple[str, WorkerResult]:
            upstream = {dep: results[dep] for dep in task.depends_on if dep in results}
            worker = router.get(task.category)
            if worker is None:
                return task.id, WorkerResult(
                    category=task.category,
                    status="error",
                    findings=[{"type": "no_worker",
                               "detail": f"category '{task.category}' に対応する worker が未登録"}],
                )
            await emit("tool", f"▶ {task.id} ({task.category}): {task.goal}")
            try:
                res = await worker.run(task, upstream)
            except Exception as exc:  # a worker crash shouldn't kill the whole DAG
                res = WorkerResult(
                    category=task.category,
                    status="error",
                    findings=[{"type": "exception", "detail": repr(exc)}],
                )
            await emit("tool", f"◀ {task.id}: {res.status} (findings={len(res.findings)})")
            return task.id, res

        layer_results = await asyncio.gather(*(run_one(t) for t in layer))
        results.update(dict(layer_results))

        if should_stop is not None and should_stop(results):
            await emit("system", f"早期終了条件が成立 — 層 {depth} で停止")
            break

    return results


def synthesize(results: dict[str, WorkerResult]) -> dict[str, Any]:
    """Merge all worker results into one report the parent presents.

    Deliberately simple and deterministic: concatenate findings (tagged with
    their source task), collect the leads, and union the touched targets. The
    orchestrator — or a final LLM pass — decides the next move from this, but
    the merge itself does no model work so it is reproducible and testable.
    """
    findings: list[dict[str, Any]] = []
    hints: list[str] = []
    touched: set[str] = set()
    statuses: dict[str, str] = {}

    for task_id, res in results.items():
        statuses[task_id] = res.status
        for f in res.findings:
            findings.append({"source": task_id, "category": res.category, **f})
        hints.extend(res.next_hints)
        touched.update(res.scope_touched)

    return {
        "statuses": statuses,
        "findings": findings,
        "next_hints": hints,
        "scope_touched": sorted(touched),
        "summary": {
            "tasks": len(results),
            "findings": len(findings),
            "blocked": sum(1 for s in statuses.values() if s == "blocked"),
            "errors": sum(1 for s in statuses.values() if s == "error"),
        },
    }
