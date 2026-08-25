#!/usr/bin/env python3
"""Check Kali-side Python imports and external security-tool availability.

This script is read-only. It does not install or update anything.

Examples:
  python3 scripts/check_kali_dependencies.py
  python3 scripts/check_kali_dependencies.py --profiles core,web
  python3 scripts/check_kali_dependencies.py --profiles core,web --strict
  python3 scripts/check_kali_dependencies.py --json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "kali-tools.json"

PYTHON_GROUPS = {
    "core": {
        "flask": "Flask",
        "requests": "requests",
        "aiohttp": "aiohttp",
        "psutil": "psutil",
        "bs4": "beautifulsoup4",
        "selenium": "selenium",
        "mitmproxy": "mitmproxy",
        "langgraph": "langgraph",
        "numpy": "numpy",
    },
    "browser": {"playwright": "playwright"},
    "ctf": {"pwn": "pwntools", "angr": "angr"},
}

COMMAND_ALIASES = {
    "ROPgadget": ["ROPgadget", "ropgadget"],
    "analyzeHeadless": ["analyzeHeadless", "ghidra"],
    "vol.py": ["vol.py", "volatility3"],
    "scout": ["scout", "scout-suite"],
    "theHarvester": ["theHarvester", "theharvester"],
    "shodan": ["shodan", "shodan-cli"],
    "censys": ["censys", "censys-cli"],
}


def load_manifest() -> dict[str, Any]:
    with MANIFEST_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def command_path(command: str) -> str | None:
    for candidate in COMMAND_ALIASES.get(command, [command]):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def check_python() -> dict[str, Any]:
    groups: dict[str, Any] = {}
    for group, modules in PYTHON_GROUPS.items():
        entries = []
        for module, package in modules.items():
            found = importlib.util.find_spec(module) is not None
            entries.append({"module": module, "package": package, "available": found})
        groups[group] = entries
    return {
        "version": platform.python_version(),
        "recommended": sys.version_info[:2] in {(3, 11), (3, 12)},
        "groups": groups,
    }


def parse_profiles(raw: str, available: dict[str, Any]) -> list[str]:
    if raw == "all":
        return list(available)
    selected = [item.strip() for item in raw.split(",") if item.strip()]
    unknown = [item for item in selected if item not in available]
    if unknown:
        raise ValueError(f"unknown profiles: {', '.join(unknown)}")
    return selected


def check_tools(manifest: dict[str, Any], profiles: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for profile in profiles:
        entries = []
        for command in manifest["profiles"][profile]:
            path = command_path(command)
            entries.append({"command": command, "available": bool(path), "path": path})
        result[profile] = entries
    return result


def print_human(report: dict[str, Any]) -> None:
    print("=" * 72)
    print("HexStrike AI - Kali dependency check")
    print("=" * 72)
    py = report["python"]
    version_note = "recommended" if py["recommended"] else "not recommended; use Python 3.11/3.12"
    print(f"Python: {py['version']} ({version_note})")

    for group, entries in py["groups"].items():
        print(f"\nPython group: {group}")
        for entry in entries:
            mark = "OK" if entry["available"] else "MISSING"
            print(f"  [{mark:7}] {entry['package']} (import {entry['module']})")

    for profile, entries in report["tools"].items():
        present = sum(1 for entry in entries if entry["available"])
        print(f"\nTool profile: {profile} ({present}/{len(entries)} available)")
        for entry in entries:
            mark = "OK" if entry["available"] else "MISSING"
            suffix = f" -> {entry['path']}" if entry["path"] else ""
            print(f"  [{mark:7}] {entry['command']}{suffix}")

    missing_python = report["summary"]["missing_python_core"]
    missing_tools = report["summary"]["missing_selected_tools"]
    print("\nSummary")
    print(f"  Missing core Python packages: {missing_python}")
    print(f"  Missing selected CLI tools:   {missing_tools}")
    print(f"  Manifest: {MANIFEST_PATH}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profiles",
        default="core,web",
        help="Comma-separated tool profiles, or 'all' (default: core,web)",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any selected CLI tool or core Python package is missing",
    )
    args = parser.parse_args()

    manifest = load_manifest()
    try:
        profiles = parse_profiles(args.profiles, manifest["profiles"])
    except ValueError as exc:
        parser.error(str(exc))

    python_report = check_python()
    tools_report = check_tools(manifest, profiles)
    missing_python_core = sum(
        1 for item in python_report["groups"]["core"] if not item["available"]
    )
    missing_selected_tools = sum(
        1 for entries in tools_report.values() for item in entries if not item["available"]
    )
    report = {
        "python": python_report,
        "tools": tools_report,
        "summary": {
            "missing_python_core": missing_python_core,
            "missing_selected_tools": missing_selected_tools,
        },
    }

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_human(report)

    if missing_python_core:
        return 2
    if args.strict and missing_selected_tools:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
