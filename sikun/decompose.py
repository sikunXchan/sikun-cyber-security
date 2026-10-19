"""Decompose a user instruction into a DAG of SubTasks for the orchestrator.

This is the parent's "split the instruction and hand pieces to the workers"
step. The default is RULE-BASED and deterministic (so it is unit-testable
offline and does not burn a model call just to plan): detect which CTF
categories the instruction touches by keyword, then emit one SubTask per
detected category with the right dependency edges.

Dependency rule (matches the design's granularity principle): recon is the
anchor (layer 0); ``web`` depends on recon because it needs recon's open-port
result; the other categories are independent and run in parallel with recon.
When nothing specific is detected, a single recon task carries the whole
instruction rather than inventing work.

An LLM-driven refinement (ask the worker model to produce the DAG as
structured output) can layer on top later; the rule-based skeleton keeps the
autonomous path predictable and cheap.
"""

from __future__ import annotations

from sikun.orchestrator import SubTask

# Categories the engine has a worker for. recon is always available as the
# anchor; the rest are opt-in by keyword.
CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "web": ["web", "http", "url", "サイト", "管理画面", "api", "sql", "sqli", "xss",
            "csrf", "cookie", "login", "ログイン", "jwt", "セッション"],
    "crypto": ["crypto", "暗号", "rsa", "aes", "hash", "ハッシュ", "証明書", "tls",
               "ssl", "鍵", "key", "xor", "base64"],
    "reversing": ["revers", "逆コンパイル", "バイナリ", "binary", "ghidra", "firmware",
                  "ファームウェア", "elf", "disassemb", "難読化"],
    "forensics": ["forensic", "フォレンジック", "pcap", "パケット", "ログ", "log",
                  "メモリ", "memory", "dump", "ダンプ", "stego", "ステガノ", "画像解析"],
    "pwn": ["pwn", "buffer", "overflow", "オーバーフロー", "exploit", "rop",
            "shellcode", "権限昇格", "privesc", "use-after-free", "uaf"],
    "mobile": ["android", "apk", "ios", "モバイル", "アプリ", "companion", "mobsf"],
}

# The full set of worker categories (recon + keyword-driven + a misc fallback).
WORKER_CATEGORIES: list[str] = ["recon", *CATEGORY_KEYWORDS.keys(), "misc"]


def detect_categories(instruction: str, allowed: set[str] | None = None) -> list[str]:
    """Return the non-recon categories whose keywords appear in the
    instruction, preserving ``CATEGORY_KEYWORDS`` order. ``allowed`` restricts
    to categories the engine actually has workers for."""
    text = instruction.lower()
    hits = [cat for cat, kws in CATEGORY_KEYWORDS.items()
            if any(kw.lower() in text for kw in kws)]
    if allowed is not None:
        hits = [c for c in hits if c in allowed]
    return hits


def decompose(
    instruction: str,
    *,
    scope: list[str] | None = None,
    target: str = "",
    categories: list[str] | None = None,
    conservative: bool = True,
) -> list[SubTask]:
    """Turn ``instruction`` into a SubTask DAG.

    ``scope`` is the authorized target set each child inherits (falls back to
    ``[target]``). ``categories`` restricts which worker categories may be
    produced (defaults to ``WORKER_CATEGORIES``).

    ``conservative`` (default True): when the instruction touches exactly ONE
    category (e.g. a pure-web target like Juice Shop), do NOT split it into a
    recon worker + a category worker. Splitting there hands recon's findings to
    a second agent only as text ``next_hints`` — the category agent loses
    recon's raw shell state and context, which hurts tightly-chained one-track
    problems. Instead emit a single worker that owns recon→exploit end to end
    (it has the recon tools itself). Only genuinely independent multi-category
    work (>= 2 categories) is split, where parallelism actually helps.
    """
    allowed = set(categories) if categories is not None else set(WORKER_CATEGORIES)
    scope_list = list(scope) if scope else ([target] if target else [])
    detected = detect_categories(instruction, allowed)

    # One-track problem: a single worker does the whole thing (recon included).
    if conservative and len(detected) == 1:
        cat = detected[0]
        return [SubTask(
            id=f"{cat}-1", category=cat,
            goal=f"偵察から実証まで一括で対応: {instruction}",
            scope=scope_list, tools=["nmap_scan", "http_probe", "dir_enum"])]

    # 0 categories -> a single recon worker; >= 2 -> recon anchor + parallel
    # category workers (web waits on recon's open-port result).
    tasks: list[SubTask] = [
        SubTask(id="recon-1", category="recon",
                goal=f"偵察: {instruction}", scope=scope_list,
                tools=["nmap_scan", "http_probe"]),
    ]
    for cat in detected:
        deps = ["recon-1"] if cat == "web" else []
        tasks.append(SubTask(
            id=f"{cat}-1", category=cat,
            goal=f"{cat} 観点で対応: {instruction}",
            depends_on=deps, scope=scope_list))
    return tasks
