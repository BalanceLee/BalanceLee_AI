#!/usr/bin/env python3
"""Single entry point for HexStrike AI.

Examples:
  python run.py --build-ui
  python run.py
  python run.py --host 0.0.0.0 --port 5000
  python run.py --headless --server-url http://192.168.56.10:8888

Production Web mode serves React, HTTP APIs and Socket.IO from one port. Vite
is only needed while actively developing the frontend.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "UI" / "frontend"
FRONTEND_DIST = FRONTEND / "dist"
BACKEND = ROOT / "UI" / "backend"


def managed_node_candidates() -> list[Path]:
    return [
        Path("/Users/balancelee/.workbuddy/binaries/node/versions/22.22.2/bin/npm"),
        Path("npm"),
    ]


def find_npm() -> str:
    import shutil

    env_npm = os.environ.get("NPM_BIN")
    if env_npm and Path(env_npm).exists():
        return env_npm
    for candidate in managed_node_candidates():
        if candidate.is_absolute() and candidate.exists():
            return str(candidate)
        found = shutil.which(str(candidate))
        if found:
            return found
    raise RuntimeError("npm not found. Install Node 18-22 or set NPM_BIN.")


def build_frontend(install: bool = False) -> None:
    npm = find_npm()
    env = os.environ.copy()
    npm_dir = str(Path(npm).parent)
    env["PATH"] = npm_dir + os.pathsep + env.get("PATH", "")

    if install or not (FRONTEND / "node_modules").exists():
        command = [npm, "ci"] if (FRONTEND / "package-lock.json").exists() else [npm, "install"]
        print(f"[UI] Installing dependencies: {' '.join(command)}")
        subprocess.run(command, cwd=FRONTEND, env=env, check=True)

    print("[UI] Building React application")
    subprocess.run([npm, "run", "build"], cwd=FRONTEND, env=env, check=True)
    if not (FRONTEND_DIST / "index.html").exists():
        raise RuntimeError(f"Frontend build did not produce {FRONTEND_DIST / 'index.html'}")
    print(f"[UI] Build ready: {FRONTEND_DIST}")


def run_headless(args: argparse.Namespace) -> None:
    from user_server.orchestrator_demo import interactive_loop

    # Reuse the existing CLI adapter, but it is now optional rather than a Web prerequisite.
    cli_args = argparse.Namespace(
        server_url=args.server_url,
        target=args.target or "",
        timeout=args.timeout,
        enable_graphrag=args.enable_graphrag,
        enable_phase_aware=args.enable_phase_aware,
        max_autonomous_rounds=args.max_rounds,
    )
    interactive_loop(cli_args)


def run_web(args: argparse.Namespace) -> None:
    if args.build_ui or not (FRONTEND_DIST / "index.html").exists():
        build_frontend(install=args.install_ui)

    os.environ["HEXSTRIKE_SERVER_URL"] = args.server_url
    os.environ["HEXSTRIKE_WEB_HOST"] = args.host
    os.environ["HEXSTRIKE_WEB_PORT"] = str(args.port)
    # Legacy app.py auto-start is intentionally disabled; MCP is managed on demand.
    os.environ["HEXSTRIKE_MCP_AUTOSTART"] = "0"

    sys.path.insert(0, str(BACKEND))
    from app import app, socketio

    print("=" * 72)
    print("HexStrike AI Unified Web App")
    print(f"Web UI:     http://{args.host}:{args.port}")
    print(f"Kali tools: {args.server_url}")
    print(f"Frontend:   {FRONTEND_DIST}")
    print("CLI is not required. Use --headless only when you explicitly want terminal mode.")
    print("=" * 72)
    socketio.run(
        app,
        host=args.host,
        port=args.port,
        debug=args.debug,
        allow_unsafe_werkzeug=True,
    )


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=os.environ.get("HEXSTRIKE_WEB_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("HEXSTRIKE_WEB_PORT", "5000")))
    p.add_argument("--server-url", default=os.environ.get("HEXSTRIKE_SERVER_URL", "http://127.0.0.1:8888"))
    p.add_argument("--build-ui", action="store_true", help="Build React before starting")
    p.add_argument("--install-ui", action="store_true", help="Run npm ci/install before building")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--headless", action="store_true", help="Run the optional terminal adapter instead of Web UI")
    p.add_argument("--target", default="")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--max-rounds", type=int, default=50)
    p.add_argument("--enable-graphrag", action="store_true")
    p.add_argument("--enable-phase-aware", action="store_true")
    return p


def main() -> int:
    args = parser().parse_args()
    if args.headless:
        run_headless(args)
    else:
        run_web(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
