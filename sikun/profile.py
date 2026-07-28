"""Agent profiles — a student's personal agent, described by one TOML file.

``--profile mine`` loads ``profiles/mine.toml`` (or a direct path to any
``.toml``). Every key is optional and falls back to the defaults below, so a
bare ``--profile`` and the shipped ``default`` profile both Just Work. A
profile chooses the model, injects a persona into the system prompt, and lists
directories to auto-load tool plugins from. This is what lets each student
build their own
agent without editing any core code — they write a profile and drop in
plugins.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROFILES_DIR = PROJECT_ROOT / "profiles"
DEFAULT_PLUGINS = PROJECT_ROOT / "plugins"


@dataclass
class Profile:
    name: str = "default"
    model: str | None = None
    persona: str = ""
    plugin_dirs: list[Path] = field(default_factory=lambda: [DEFAULT_PLUGINS])
    # Authorized target scope (IPs / CIDRs / hostnames). Empty == no enforcement.
    # Set this in the distributed build so an accidental out-of-scope command is
    # blocked. See sikun.scope.
    scope: list[str] = field(default_factory=list)


def _resolve(path_like: str) -> Path:
    """Profile paths are relative to the project root unless absolute, so a
    profile reads the same no matter what directory the tool is launched from."""
    p = Path(path_like).expanduser()
    return p if p.is_absolute() else (PROJECT_ROOT / p)


def resolve_profile_path(name_or_path: str) -> Path | None:
    """Accept either a bare profile name (``mine`` -> ``profiles/mine.toml``)
    or a direct path to a ``.toml`` file. Returns None if nothing matches."""
    if not name_or_path:
        return None
    p = Path(name_or_path).expanduser()
    if p.suffix == ".toml" and p.exists():
        return p
    candidate = PROFILES_DIR / f"{name_or_path}.toml"
    return candidate if candidate.exists() else None


def load_profile(name_or_path: str | None) -> Profile:
    """Load a profile by name/path. With no argument, use ``profiles/default.toml``
    if it exists, else the built-in defaults (so the tool runs even with no
    profiles authored yet)."""
    if not name_or_path:
        default = PROFILES_DIR / "default.toml"
        return _from_file(default) if default.exists() else Profile()
    path = resolve_profile_path(name_or_path)
    if path is None:
        raise FileNotFoundError(
            f"プロファイルが見つかりません: {name_or_path} "
            f"(profiles/ に <名前>.toml を置くか、パスを直接指定してください)"
        )
    return _from_file(path)


def _from_file(path: Path) -> Profile:
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    plugin_dirs = data.get("plugins")
    model = data.get("model")
    scope = data.get("scope") or []
    if not isinstance(scope, list):
        raise ValueError(f"{path.name}: scope はリスト(例: [\"10.0.0.0/24\"])にしてください")

    return Profile(
        name=str(data.get("name", path.stem)),
        model=str(model) if model else None,
        persona=str(data.get("persona", "")),
        plugin_dirs=[_resolve(d) for d in plugin_dirs] if plugin_dirs else [DEFAULT_PLUGINS],
        scope=[str(x) for x in scope],
    )
