"""Per-target persistent memory — survives across sessions.

Fixes two gaps at once:
- (問題B) findings/recon evaporate when the process ends — every run_agent()
  used to start from zero.
- (問題A) even within a run, nothing guaranteed earlier findings stayed
  salient as history grew and old tool output got compacted.

A compact, structured record per target (accumulated ports + confirmed
findings with evidence) is loaded at startup, injected into the system prompt
("what we already know about this target"), and updated live as the agent
scans and confirms things. This gives cross-session continuity and enables
differential re-scans ("what changed since last time").

Deliberately NOT the raw session log (that stays a human-readable record, see
tui.py) — this is a machine-oriented summary: small, structured, re-injected.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MEMORY_DIR = PROJECT_ROOT / "memory"

_MAX_FINDINGS_IN_SUMMARY = 12
_MAX_PORTS_IN_SUMMARY = 25


def _safe_name(target: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[:60] or "target"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class TargetMemory:
    target: str
    path: Path
    first_seen: str = ""
    last_seen: str = ""
    ports: list = field(default_factory=list)  # [{port, protocol, service, version}]
    findings: list = field(default_factory=list)  # [{severity, text, evidence, ts}]

    @classmethod
    def load(cls, target: str) -> "TargetMemory":
        path = MEMORY_DIR / f"{_safe_name(target)}.json"
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return cls(
                    target=target,
                    path=path,
                    first_seen=data.get("first_seen", ""),
                    last_seen=data.get("last_seen", ""),
                    ports=data.get("ports", []) or [],
                    findings=data.get("findings", []) or [],
                )
            except (OSError, json.JSONDecodeError):
                pass
        return cls(target=target, path=path, first_seen=_now(), last_seen=_now())

    def has_history(self) -> bool:
        return bool(self.ports or self.findings)

    def add_ports(self, ports: list) -> None:
        seen = {(p.get("port"), p.get("protocol")) for p in self.ports}
        for p in ports:
            key = (p.get("port"), p.get("protocol"))
            if key not in seen:
                self.ports.append({k: p.get(k) for k in ("port", "protocol", "service", "version")})
                seen.add(key)

    def add_finding(self, severity: str | None, text: str, evidence: str = "") -> None:
        for existing in self.findings:  # dedup by (severity, text)
            if existing.get("text") == text and existing.get("severity") == (severity or "info"):
                return
        self.findings.append(
            {
                "severity": severity or "info",
                "text": text,
                "evidence": (evidence or "")[:500],
                "ts": _now(),
            }
        )

    def save(self) -> None:
        self.last_seen = _now()
        try:
            MEMORY_DIR.mkdir(exist_ok=True)
            self.path.write_text(
                json.dumps(
                    {
                        "target": self.target,
                        "first_seen": self.first_seen,
                        "last_seen": self.last_seen,
                        "ports": self.ports,
                        "findings": self.findings,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError:
            pass

    def summary_for_prompt(self) -> str:
        """Compact markdown injected into the system prompt. Empty when there's
        nothing remembered yet (a first-ever visit adds no noise)."""
        if not self.has_history():
            return ""
        lines = [f"# 前回までの記憶(このターゲットの蓄積 / 最終調査: {self.last_seen})"]
        if self.ports:
            shown = self.ports[:_MAX_PORTS_IN_SUMMARY]
            portstr = ", ".join(
                f"{p.get('port')}/{p.get('protocol', '')} {p.get('service', '')} {p.get('version', '')}".strip()
                for p in shown
            )
            extra = f" (+{len(self.ports) - len(shown)})" if len(self.ports) > len(shown) else ""
            lines.append(f"既知の開放ポート({len(self.ports)}): {portstr}{extra}")
        if self.findings:
            lines.append("確定済みfinding:")
            for f in self.findings[:_MAX_FINDINGS_IN_SUMMARY]:
                ev = f" — 根拠: {f['evidence'][:120]}" if f.get("evidence") else ""
                lines.append(f"- [{f.get('severity')}] {f.get('text')}{ev}")
        lines.append(
            "※ 前回からの差分に注意。新規/変化したサービスや未検証の項目を優先的に調べること。"
            "既に確定済みの finding は再報告不要(証拠が変わった場合のみ更新)。"
        )
        return "\n".join(lines)
