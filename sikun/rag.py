"""Real RAG over knowledge_base/: chunk + embed + cosine-similarity retrieval.

Replaces "load every file into the system prompt every turn" so the knowledge
base can grow past a handful of files without inflating cost/context. Chunks
are split on markdown "## " headings (matches the existing knowledge_base/*.md
style). Embeddings are cached to disk keyed by a content hash, so re-running
doesn't re-embed unchanged chunks — only new/edited sections cost anything.

Stdlib-only (hashlib/json/math/re) — no numpy/vector-db dependency, since the
knowledge base is small enough that a linear cosine-similarity scan is fine.
Revisit if it grows into the thousands of chunks.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from google import genai

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE_BASE_DIR = PROJECT_ROOT / "knowledge_base"
CACHE_PATH = KNOWLEDGE_BASE_DIR / ".embeddings_cache.json"
EMBED_MODEL = "gemini-embedding-001"


@dataclass(frozen=True)
class Chunk:
    source: str
    heading: str
    text: str

    @property
    def key(self) -> str:
        return hashlib.sha256(self.text.encode()).hexdigest()


def _split_into_chunks(kb_dir: Path | None = None) -> list[Chunk]:
    """Split each knowledge_base file on '## ' headings; one chunk per section.

    `kb_dir` lets a profile point RAG at its own (possibly personal) knowledge
    base instead of the shipped one; defaults to the project's knowledge_base/."""
    base = kb_dir or KNOWLEDGE_BASE_DIR
    chunks: list[Chunk] = []
    if not base.exists():
        return chunks
    for path in sorted(base.glob("**/*")):
        if path.suffix.lower() not in (".md", ".txt"):
            continue
        try:
            text = path.read_text()
        except OSError:
            continue

        parts = re.split(r"(?m)^(## .+)$", text)
        if len(parts) <= 1:
            # no "## " headings found — treat the whole file as one chunk
            if text.strip():
                chunks.append(Chunk(source=path.name, heading=path.stem, text=text.strip()))
            continue

        preamble = parts[0].strip()
        if preamble:
            chunks.append(Chunk(source=path.name, heading="(概要)", text=preamble))
        for i in range(1, len(parts), 2):
            heading = parts[i].lstrip("#").strip()
            body = parts[i + 1].strip() if i + 1 < len(parts) else ""
            chunks.append(Chunk(source=path.name, heading=heading, text=f"{parts[i]}\n{body}"))
    return chunks


def _cache_path(kb_dir: Path | None = None) -> Path:
    """Embeddings cache lives inside whichever knowledge base it describes, so
    a personal KB gets its own cache instead of sharing the default one."""
    return (kb_dir or KNOWLEDGE_BASE_DIR) / ".embeddings_cache.json"


def _load_cache(cache_path: Path) -> dict[str, list[float]]:
    if not cache_path.exists():
        return {}
    try:
        return json.loads(cache_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache_path: Path, cache: dict[str, list[float]]) -> None:
    try:
        cache_path.write_text(json.dumps(cache))
    except OSError:
        pass


def _embed_batch(client: genai.Client, texts: list[str]) -> list[list[float]]:
    resp = client.models.embed_content(model=EMBED_MODEL, contents=texts)
    return [e.values for e in resp.embeddings]


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def retrieve(client: genai.Client, query: str, top_k: int = 4, kb_dir: Path | None = None) -> str:
    """Embed `query`, return the top_k most relevant knowledge_base chunks as
    markdown text (empty string if the knowledge base is empty/missing).

    `kb_dir` selects which knowledge base to search (a profile's personal one,
    or the shipped default when None)."""
    chunks = _split_into_chunks(kb_dir)
    if not chunks:
        return ""

    cache_path = _cache_path(kb_dir)
    cache = _load_cache(cache_path)
    missing = [c for c in chunks if c.key not in cache]
    if missing:
        vectors = _embed_batch(client, [c.text for c in missing])
        for c, v in zip(missing, vectors):
            cache[c.key] = v
        _save_cache(cache_path, cache)

    query_vec = _embed_batch(client, [query])[0]
    scored = sorted(chunks, key=lambda c: _cosine(query_vec, cache[c.key]), reverse=True)
    top = scored[:top_k]
    return "\n\n".join(f"### [{c.source}] {c.heading}\n{c.text}" for c in top)
