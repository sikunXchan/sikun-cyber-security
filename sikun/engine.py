"""Select the interactive agent runtime without reading credentials."""

from __future__ import annotations

import importlib.util
import os


def resolve_engine(requested: str) -> str:
    if requested not in {"auto", "codex", "gemini"}:
        raise ValueError(f"Unknown engine: {requested}")
    if requested == "auto":
        if importlib.util.find_spec("openai_codex") is not None:
            return "codex"
        if os.environ.get("GEMINI_API_KEY"):
            return "gemini"
        raise ValueError("Codex SDK or GEMINI_API_KEY is required")
    if requested == "codex" and importlib.util.find_spec("openai_codex") is None:
        raise ValueError("Codex SDK is missing: pip install openai-codex")
    return requested
