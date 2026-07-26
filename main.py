#!/usr/bin/env python3
"""Entry point for Sikun Cyber Security."""

from __future__ import annotations

import argparse
import datetime
import functools
import os
import sys

from dotenv import load_dotenv

from sikun.banner import print_banner
from sikun.profile import load_profile
from sikun.scaffold import init_agent
from sikun.tui import LOG_DIR, SikunApp

PROVIDERS = {"claude", "gemini"}


def _load_run_agent(provider: str):
    """Import lazily so picking one provider doesn't require the other's SDK/key."""
    if provider == "gemini":
        from sikun.agent_gemini import run_agent
    else:
        from sikun.agent import run_agent
    return run_agent


def _handle_logs_flag(value: str) -> None:
    """`--logs` with no value lists past sessions (newest first); `--logs N`
    prints session #N's full log. Every session auto-writes to logs/ already
    (see SikunApp), this is just a CLI-side way to browse them without
    hunting through the directory by hand."""
    logs = sorted(LOG_DIR.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not logs:
        print("セッションログはまだありません。")
        return

    if value == "__list__":
        print(f"{'#':>3}  {'日時':<20} {'対象':<35} {'サイズ'}")
        for i, path in enumerate(logs, 1):
            stat = path.stat()
            mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            # filename: <timestamp>_<sanitized-target>.log
            name_parts = path.stem.split("_", 2)
            target_part = name_parts[2] if len(name_parts) > 2 else path.stem
            print(f"{i:>3}  {mtime:<20} {target_part:<35} {stat.st_size / 1024:.1f}KB")
        print("\n内容を見るには: sikun-cybersecurity --logs <番号>")
        return

    try:
        path = logs[int(value) - 1]
    except (ValueError, IndexError):
        print(f"番号が不正です: {value}(--logs だけで一覧表示できます)")
        return
    print(path.read_text(encoding="utf-8"))


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description="Sikun Cyber Security — attack-exercise agent")
    parser.add_argument("target", nargs="?", help="演習で許可された対象 (IP/ホスト名)")
    parser.add_argument(
        "--provider",
        choices=sorted(PROVIDERS),
        default=None,
        help="使用するモデルプロバイダ (claude または gemini)。省略時はプロファイルの設定に従う",
    )
    parser.add_argument(
        "--profile",
        default=os.environ.get("SIKUN_PROFILE"),
        help="使用するエージェント・プロファイル名(profiles/<名前>.toml)またはtomlへのパス。省略時は default",
    )
    parser.add_argument(
        "--init",
        dest="init_name",
        metavar="NAME",
        default=None,
        help="新しいエージェントの雛形(プロファイル+サンプルプラグイン)を生成して終了",
    )
    parser.add_argument(
        "--ssh",
        dest="ssh_host",
        default=os.environ.get("SIKUN_SSH_TARGET"),
        help="bashツールをこのホストでSSH実行する (例: user@192.168.11.37)。省略時はSIKUN_SSH_TARGET環境変数を使う",
    )
    parser.add_argument("--task", dest="initial_instruction", help="初期指示文を直接指定(省略時は対話プロンプト)")
    parser.add_argument(
        "--logs",
        nargs="?",
        const="__list__",
        default=None,
        metavar="N",
        help="値なしでセッションログの一覧を表示、番号(1が最新)を指定すると内容を表示して終了",
    )
    args = parser.parse_args()

    if args.init_name is not None:
        _handle_init(args.init_name)
        return

    if args.logs is not None:
        _handle_logs_flag(args.logs)
        return

    try:
        profile = load_profile(args.profile)
    except (FileNotFoundError, ValueError) as exc:
        print(f"プロファイル読み込みエラー: {exc}")
        sys.exit(1)

    # Provider precedence: explicit --provider > profile > default.
    provider = args.provider or profile.provider
    run_agent = _load_run_agent(provider)

    target = args.target
    if not target:
        print_banner()
        target = input("\n対象ホスト(演習で許可された環境のみ): ").strip()
        if not target:
            print("対象が指定されていません。終了します。")
            sys.exit(1)

    app = SikunApp(
        target=target,
        agent_factory=functools.partial(
            run_agent,
            target=target,
            ssh_host=args.ssh_host,
            initial_instruction=args.initial_instruction,
            profile=profile,
        ),
        profile_name=profile.name,
    )
    app.run()


def _handle_init(name: str) -> None:
    """`--init NAME`: scaffold a new profile + starter plugin, then print next steps."""
    try:
        created, skipped = init_agent(name)
    except ValueError as exc:
        print(f"エラー: {exc}")
        sys.exit(1)
    for path in created:
        print(f"作成: {path}")
    for path in skipped:
        print(f"スキップ(既に存在): {path}")
    if created:
        print(f"\n次のステップ:")
        print(f"  1. profiles/{name}.toml を編集(provider / persona など)")
        print(f"  2. plugins/{name}_ping.py を編集して自作ツールを追加")
        print(f"  3. python main.py <対象> --profile {name} で起動")


if __name__ == "__main__":
    main()
