"""Plugin tool system — let students add their own agent tools without
touching the core loop.

Drop a ``*.py`` file into a plugins directory (each profile lists its own via
``plugins = [...]``; the shipped default is ``plugins/``) that defines a
module-level ``PLUGIN`` (one :class:`ToolPlugin`) or ``PLUGINS`` (a list of
them). At startup the active profile's plugin dirs are scanned, every such
file imported, and each ToolPlugin handed to the model as a callable tool —
schema advertising, dispatch, and result routing are all done by the existing
agent loop. No edits to ``agent.py`` / ``agent_gemini.py`` / ``tools.py`` are
required to add a tool; that is the whole point.

A plugin's ``run(args, ctx)`` gets the model-supplied arguments plus a
:class:`PluginContext`, whose ``run`` executes a shell command against the
same local-or-SSH target the rest of the agent uses (the persistent Gemini
shell, or Claude's per-call subprocess — the plugin doesn't care which).
"""

from __future__ import annotations

import importlib.util
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

# Names owned by the core loop — a plugin may not shadow these.
RESERVED_NAMES = {"bash", "report", "propose_plan", "nmap_scan", "http_probe", "dir_enum"}


@dataclass
class PluginContext:
    """Handed to a plugin's ``run()`` so it can actually do work.

    ``run`` is bound by the backend to its shell (the persistent Gemini shell
    or Claude's per-call subprocess), so a plugin just ``await ctx.run("...")``
    and stays provider-agnostic. ``target``/``ssh_host``/``workdir`` are the
    same values the rest of the agent operates against.
    """

    target: str
    ssh_host: str | None
    workdir: Path
    run: Callable[[str], Awaitable[str]]


@dataclass
class ToolPlugin:
    """One tool a plugin file exposes to the model.

    ``parameters`` is a JSON-Schema object (``{"type": "object", "properties":
    {...}, "required": [...]}``) — the same shape works for both the Anthropic
    (``input_schema``) and Gemini (``FunctionDeclaration.parameters``) tool
    APIs, so a plugin is written once and runs on either provider.

    ``run`` must return something JSON-serializable (a dict is ideal — it goes
    straight back to the model as the tool result). ``summary`` is optional and
    only affects the one-line preview shown live in the TUI.
    """

    name: str
    description: str
    parameters: dict[str, Any]
    run: Callable[[dict, PluginContext], Awaitable[Any]]
    summary: Callable[[Any], str] | None = None

    def summarize(self, result: Any) -> str:
        if self.summary is not None:
            try:
                return self.summary(result)
            except Exception:
                pass
        return str(result)[:300]


@dataclass
class LoadResult:
    plugins: list[ToolPlugin]
    errors: list[str]


def _import_file(path: Path):
    # Unique module name per path so two plugin files can't clobber each other
    # in sys.modules, and a reload picks up edits.
    mod_name = f"sikun_plugin_{path.stem}_{abs(hash(str(path))) & 0xFFFFFF:x}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot create import spec for {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def load_plugins(dirs: list[Path]) -> LoadResult:
    """Import every ``*.py`` (excluding ``_``-prefixed helpers) under each dir
    and collect the ToolPlugins they declare. Returns the plugins plus a list
    of human-readable errors — a broken plugin never takes down the whole
    session; it's skipped and reported so the operator sees why."""
    found: dict[str, ToolPlugin] = {}
    errors: list[str] = []
    for directory in dirs:
        if not directory.exists() or not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                mod = _import_file(path)
            except Exception:
                errors.append(f"{path.name}: 読み込み失敗\n{traceback.format_exc(limit=2)}")
                continue

            items: list[Any] = []
            if hasattr(mod, "PLUGINS"):
                collection = getattr(mod, "PLUGINS")
                if isinstance(collection, (list, tuple)):
                    items.extend(collection)
                else:
                    errors.append(f"{path.name}: PLUGINS はリストである必要があります")
            if hasattr(mod, "PLUGIN"):
                items.append(getattr(mod, "PLUGIN"))
            if not items:
                errors.append(f"{path.name}: PLUGIN も PLUGINS も定義されていません")
                continue

            for plugin in items:
                if not isinstance(plugin, ToolPlugin):
                    errors.append(f"{path.name}: ToolPlugin ではない値が登録されています ({plugin!r})")
                    continue
                if plugin.name in RESERVED_NAMES:
                    errors.append(f"{path.name}: 予約名 '{plugin.name}' は使用できません")
                    continue
                if plugin.name in found:
                    errors.append(f"{path.name}: ツール名 '{plugin.name}' が重複(後勝ちで上書き)")
                found[plugin.name] = plugin
    return LoadResult(plugins=list(found.values()), errors=errors)
