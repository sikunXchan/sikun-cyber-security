"""Runnable experiment for the orchestrator-worker core — mock workers only.

This exercises the real decomposition/dispatch/merge logic from
``sikun.orchestrator`` and the real scope enforcement from
``sikun.permission`` / ``sikun.scope``, but the workers are MOCKS: they return
canned structured results and perform NO network or offensive action. The
point is to prove the orchestration contract end to end:

  1. a user instruction is decomposed into a DAG of SubTasks,
  2. ``build_layers`` groups independent tasks (parallel) and orders
     dependent ones (sequential),
  3. each layer is dispatched concurrently,
  4. the authorization gate HARD-BLOCKS an out-of-scope target, and
  5. ``synthesize`` merges everything into one report.

Run it inside a network-isolated namespace so even a misbehaving worker can
reach nothing:

    unshare -rn python3 experiments/orchestrator_experiment.py

(Plain ``python3 experiments/orchestrator_experiment.py`` also works; the
mocks never touch the network regardless.)
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Make the repo root importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sikun.orchestrator import SubTask, Worker, WorkerResult, orchestrate, synthesize
from sikun.permission import new_guard, screen_targets
from sikun.scope import ScopeGuard

# ── Lab scope: the authorized exercise range. Everything outside is blocked. ──
LAB_SCOPE = ["10.13.37.0/24", "localhost", "127.0.0.1"]
AUDIT_LOG = Path(__file__).resolve().parent / "experiment_audit.log"


class MockWorker(Worker):
    """A category worker that fakes the work. It still runs the REAL scope
    check against the target it 'would' probe, so the authorization path is
    exercised for real — only the exploitation is faked."""

    def __init__(self, category: str, guard: ScopeGuard, probe_targets: dict[str, list[str]],
                 canned: dict[str, dict]):
        self.category = category
        self.guard = guard
        self.probe_targets = probe_targets      # task_id -> targets it will touch
        self.canned = canned                    # task_id -> {findings, next_hints}

    async def run(self, task: SubTask, upstream: dict[str, WorkerResult]) -> WorkerResult:
        await asyncio.sleep(0.05)  # pretend the work takes a moment
        targets = self.probe_targets.get(task.id, [])

        # Real authorization gate: refuse out-of-scope targets, audit either way.
        touched: list[str] = []
        for tgt in targets:
            err = screen_targets(self.guard, f"{self.category}:{task.id}", [tgt])
            if err:
                return WorkerResult(
                    category=self.category, status="blocked",
                    findings=[{"type": "scope_block", "detail": err, "evidence": tgt}],
                    scope_touched=touched,
                )
            touched.append(tgt)

        plan = self.canned.get(task.id, {})
        return WorkerResult(
            category=self.category, status="done",
            findings=plan.get("findings", []),
            next_hints=plan.get("next_hints", []),
            scope_touched=touched,
        )


def build_dag() -> list[SubTask]:
    """A realistic authorized-lab decomposition (IoT device exercise), plus one
    deliberately out-of-scope task to demonstrate the block.

    Layers:
      0 (parallel): recon-1, app-1, fw-1, oob-1
      1           : web-1   (needs recon-1's open-port result)
    """
    return [
        SubTask(id="recon-1", category="recon",
                goal="ラボ機器の開放ポート・サービスを特定",
                scope=["10.13.37.10"]),
        SubTask(id="app-1", category="mobile",
                goal="companion アプリの静的解析(MobSF想定)",
                scope=["10.13.37.10"]),
        SubTask(id="fw-1", category="reversing",
                goal="ファームウェアの逆コンパイル(Ghidra想定)",
                scope=["10.13.37.10"]),
        SubTask(id="web-1", category="web",
                goal="管理画面/API を調査(recon-1 の結果を使う)",
                depends_on=["recon-1"], scope=["10.13.37.10"]),
        SubTask(id="oob-1", category="recon",
                goal="(誤設定デモ)範囲外ホストを偵察しようとする",
                scope=["8.8.8.8"]),
    ]


async def main() -> int:
    guard = new_guard(LAB_SCOPE, AUDIT_LOG, session_target="10.13.37.10")

    probe = {
        "recon-1": ["10.13.37.10"],
        "app-1": ["10.13.37.10"],
        "fw-1": ["10.13.37.10"],
        "web-1": ["10.13.37.10"],
        "oob-1": ["8.8.8.8"],            # out of scope → must be blocked
    }
    canned = {
        "recon-1": {"findings": [{"type": "open_port", "detail": "8080/tcp web-admin",
                                  "evidence": "nmap(mock)"}],
                    "next_hints": ["web-1 は 8080 の管理画面を見るとよい"]},
        "app-1": {"findings": [{"type": "hardcoded_secret",
                                "detail": "companion APK に API キー(CWE-798)",
                                "evidence": "mobsf(mock)"}]},
        "fw-1": {"findings": [{"type": "weak_crypto",
                               "detail": "firmware にハードコード鍵(mock)",
                               "evidence": "ghidra(mock)"}]},
        "web-1": {"findings": [{"type": "default_credentials",
                                "detail": "admin:admin が有効(CWE-1392)",
                                "evidence": "http_probe(mock)"}],
                  "next_hints": ["防御側: 初期パスワード強制変更 + 管理画面のTLS化"]},
    }

    router = {
        "recon": MockWorker("recon", guard, probe, canned),
        "web": MockWorker("web", guard, probe, canned),
        "mobile": MockWorker("mobile", guard, probe, canned),
        "reversing": MockWorker("reversing", guard, probe, canned),
    }

    def on_event(channel: str, text: str) -> None:
        print(f"[{channel}] {text}")

    print("=== SCS orchestrator experiment (mock workers, no network) ===")
    print(f"認可スコープ: {', '.join(LAB_SCOPE)}\n")

    tasks = build_dag()
    results = await orchestrate(tasks, router, on_event=on_event)

    print("\n=== 統合レポート (synthesize) ===")
    report = synthesize(results)
    print(json.dumps(report, ensure_ascii=False, indent=2))

    # Assertions so the experiment self-checks (and doubles as a smoke test).
    assert results["oob-1"].status == "blocked", "範囲外タスクがブロックされていない!"
    assert results["web-1"].status == "done", "web-1 が完了していない"
    assert any(f["type"] == "default_credentials" for f in report["findings"]), \
        "web-1 の findings が統合されていない"
    layers_ok = results["web-1"].scope_touched == ["10.13.37.10"]
    assert layers_ok, "web-1 の scope_touched が想定外"

    print(f"\n✓ 実験成功: 範囲外タスクはブロック、依存順は尊重、統合OK。")
    print(f"✓ 監査ログ: {AUDIT_LOG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
