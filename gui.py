#!/usr/bin/env python3
"""Native desktop entry point for Sikun Cyber Security (pywebview UI).

Same agent core as main.py (sikun.agent_gemini.run_agent) — only the
frontend differs: a dashboard/reports/settings window instead of the
Textual TUI. See sikun/webapp.py.
"""

from __future__ import annotations

import argparse
import functools
import os
import sys

from dotenv import load_dotenv

from sikun.agent_gemini import run_agent
from sikun.profile import load_profile
from sikun.webapp import WebApp


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description="Sikun Cyber Security - ネイティブデスクトップUI")
    parser.add_argument("target", nargs="?", help="認可された対象 (IP/ホスト名/URL)")
    parser.add_argument(
        "--profile",
        default=os.environ.get("SIKUN_PROFILE"),
        help="使用するエージェント・プロファイル名(profiles/<名前>.toml)またはtomlへのパス。省略時は default",
    )
    parser.add_argument(
        "--ssh",
        dest="ssh_host",
        default=os.environ.get("SIKUN_SSH_TARGET"),
        help="bashツールをこのホストでSSH実行する (例: user@192.168.11.37)。省略時はSIKUN_SSH_TARGET環境変数を使う",
    )
    parser.add_argument("--task", dest="initial_instruction", help="初期指示文を直接指定(省略時は対話プロンプト)")
    parser.add_argument(
        "--study",
        action="store_true",
        help="学習・解析モードで起動(攻撃せず、CVE/手法の学習や成果物の防御的解析に使う)。対象ホスト不要",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="起動時に自機のローカル体制点検(開放ポート/更新/失敗ログイン等)を実行して表示。対象ホスト不要",
    )
    args = parser.parse_args()

    try:
        profile = load_profile(args.profile)
    except (FileNotFoundError, ValueError) as exc:
        print(f"プロファイル読み込みエラー: {exc}")
        sys.exit(1)

    start_mode = "study" if args.study else "security"

    target = args.target
    if not target:
        if start_mode == "study":
            target = "(学習/解析モード)"
        elif args.status:
            target = "localhost"
        else:
            target = input("対象ホスト(認可された対象のみ): ").strip()
            if not target:
                print("対象が指定されていません。終了します。")
                sys.exit(1)

    app = WebApp(target=target, profile_name=profile.name, start_mode=start_mode)
    app.run(
        agent_factory=functools.partial(
            run_agent,
            target=target,
            ssh_host=args.ssh_host,
            initial_instruction=args.initial_instruction,
            profile=profile,
            startup_status=args.status,
        )
    )


if __name__ == "__main__":
    main()
