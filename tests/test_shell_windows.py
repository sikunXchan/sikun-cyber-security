"""The Windows shell runner must use the installed Git Bash, not the WSL launcher."""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path

import pytest

from sikun.tools import PersistentShell, _bash_executable, run_bash


def test_bash_runner_and_persistent_session() -> None:
    if os.name == "nt":
        git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git" / "bin" / "bash.exe"
        if not git_bash.is_file():
            pytest.skip("Git Bash is required for the Windows shell integration test")
        assert Path(_bash_executable()).samefile(git_bash)
    elif not shutil.which("bash"):
        pytest.skip("bash is not installed")

    async def run() -> None:
        outputs = await asyncio.gather(*(run_bash("printf 'ok'", Path.cwd()) for _ in range(4)))
        assert outputs == ["ok"] * 4

        shell = PersistentShell(cwd=Path.cwd())
        await shell.start()
        try:
            first = await shell.run("export SIKUN_SHELL_CHECK=ready; printf 'first'")
            second = await shell.run("printf '%s' \"$SIKUN_SHELL_CHECK\"")
            assert "first" in first and "[exit=0]" in first
            assert "ready" in second and "[exit=0]" in second
        finally:
            await shell.stop()

    asyncio.run(run())
