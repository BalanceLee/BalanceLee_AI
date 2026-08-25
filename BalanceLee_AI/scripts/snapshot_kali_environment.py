#!/usr/bin/env python3
"""Create a reproducible JSON snapshot of Kali Python packages and tool binaries.

The script does not run security tools. It records command paths, file hashes,
APT ownership (when dpkg-query is available), and relevant Python package
versions so an upgrade can be reviewed or rolled back deliberately.

Examples:
  python3 scripts/snapshot_kali_environment.py
  python3 scripts/snapshot_kali_environment.py --profiles all
  python3 scripts/snapshot_kali_environment.py --output kali-environment.lock.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "kali-tools.json"
PYTHON_PACKAGES = [
    "Flask",
    "requests",
    "aiohttp",
    "psutil",
    "beautifulsoup4",
    "selenium",
    "mitmproxy",
    "langgraph",
    "numpy",
    "playwright",
    "pwntools",
    "angr",
]
ALIASES = {
    "ROPgadget": ["ROPgadget", "ropgadget"],
    "analyzeHeadless": ["analyzeHeadless", "ghidra"],
    "vol.py": ["vol.py", "volatility3"],
    "scout": ["scout", "scout-suite"],
    "theHarvester": ["theHarvester", "theharvester"],
    "shodan": ["shodan", "shodan-cli"],
    "censys": ["censys", "censys-cli"],
}


def resolve(command: str) -> str | None:
    for candidate in ALIASES.get(command, [command]):
        path = shutil.which(candidate)
        if path:
            return str(Path(path).resolve())
    return None


def sha256_file(path: str) -> str | None:
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > 100 * 1024 * 1024:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def dpkg_owner(path: str) -> str | None:
    if not shutil.which("dpkg-query"):
        return None
    try:
        proc = subprocess.run(
            ["dpkg-query", "-S", path],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout.split(":", 1)[0].strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def dpkg_version(package: str | None) -> str | None:
    if not package or not shutil.which("dpkg-query"):
        return None
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", package],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def package_versions() -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for package in PYTHON_PACKAGES:
        try:
            result[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            result[package] = None
    return result


def parse_profiles(raw: str, profiles: dict[str, Any]) -> list[str]:
    selected = list(profiles) if raw == "all" else [x.strip() for x in raw.split(",") if x.strip()]
    unknown = [x for x in selected if x not in profiles]
    if unknown:
        raise ValueError("unknown profiles: " + ", ".join(unknown))
    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", default="core,web", help="Comma-separated profiles or all")
    parser.add_argument("--output", default="kali-environment.lock.json", help="Output JSON path")
    args = parser.parse_args()

    with MANIFEST_PATH.open(encoding="utf-8") as f:
        manifest = json.load(f)
    try:
        selected = parse_profiles(args.profiles, manifest["profiles"])
    except ValueError as exc:
        parser.error(str(exc))

    commands: list[str] = []
    for profile in selected:
        for command in manifest["profiles"][profile]:
            if command not in commands:
                commands.append(command)

    tools: dict[str, Any] = {}
    for command in commands:
        path = resolve(command)
        owner = dpkg_owner(path) if path else None
        tools[command] = {
            "path": path,
            "sha256": sha256_file(path) if path else None,
            "apt_package": owner,
            "apt_version": dpkg_version(owner),
        }

    report = {
        "schema_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "platform": platform.platform(),
        "python": {
            "executable": sys.executable,
            "version": platform.python_version(),
            "packages": package_versions(),
        },
        "profiles": selected,
        "tools": tools,
    }

    output = Path(args.output)
    if not output.is_absolute():
        output = ROOT / output
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Snapshot written: {output}")
    print(f"Tools found: {sum(1 for item in tools.values() if item['path'])}/{len(tools)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
