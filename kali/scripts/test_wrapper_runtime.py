#!/usr/bin/env python3
"""Verify OrchestratorWrapper publishes new runtime and legacy UI events."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "UI" / "backend")]
os.environ["HEXSTRIKE_RUNTIME_DIR"] = tempfile.mkdtemp(prefix="runtime_wrapper_")

from orchestrator_wrapper_v2 import OrchestratorWrapper


class FakeSocket:
    def __init__(self):
        self.items = []

    def emit(self, event, data, room=None):
        self.items.append((event, data, room))


class FakeMcp:
    def _call_tool(self, name, arguments):
        if name == "sqlmap_scan":
            return {"success": True, "stdout": "Parameter 'id' is vulnerable\nback-end DBMS: MySQL"}
        return {"success": True, "message": "done"}


def main() -> int:
    socket = FakeSocket()
    wrapper = OrchestratorWrapper(socket, "sid-test")
    wrapper._execute_tool_calls([
        {
            "id": "call-1",
            "function": {
                "name": "sqlmap_scan",
                "arguments": '{"url":"https://example.test?id=1"}',
            },
        }
    ], FakeMcp())

    names = [item[0] for item in socket.items]
    for expected in ["runtime_event", "tool_start", "tool_complete", "vulnerability_found"]:
        assert expected in names, names
    assert wrapper.messages[-1]["role"] == "tool"
    events = wrapper.event_bus.replay("sid-test")
    assert [event["type"] for event in events] == [
        "tool.started",
        "tool.completed",
        "finding.upsert",
    ]
    print("WRAPPER_RUNTIME_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
