#!/usr/bin/env python3
"""Contract tests for runtime models, event ordering and tool adapters."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from user_server.runtime import (
    EventBus,
    EventSource,
    EventType,
    ExecutionEvent,
    JsonlEventStore,
    ToolExecutionRequest,
    ToolGateway,
)
from user_server.runtime.adapters import AdapterRegistry


class FakeClient:
    def __init__(self, responses):
        self.responses = responses

    def _call_tool(self, name, arguments):
        return self.responses[name]


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="hexstrike_runtime_"))
    store = JsonlEventStore(root / "events")
    bus = EventBus(store)
    received = []
    bus.subscribe(received.append)

    # Ordering and replay
    for index in range(2):
        bus.publish(ExecutionEvent(
            type=EventType.AGENT_MESSAGE,
            session_id="session-a",
            trace_id="trace-a",
            source=EventSource(kind="agent", id="main"),
            payload={"message": f"m{index}"},
        ))
    assert [event.seq for event in received] == [1, 2]
    assert [item["seq"] for item in bus.replay("session-a", after_seq=1)] == [2]

    responses = {
        "sqlmap_scan": {"result": {"success": True, "stdout": "Parameter 'id' is vulnerable\nback-end DBMS: MySQL"}},
        "nuclei_scan": {"success": True, "stdout": "[cve-test] [http] [high] https://example.test"},
        "nmap_scan": {"success": True, "stdout": "80/tcp open http nginx\n443/tcp open https"},
        "unknown_tool": {"success": True, "custom": {"a": 1}, "message": "done"},
        "false_sqlmap": {"success": True, "vulnerable": False, "stdout": "not injectable"},
    }
    client = FakeClient(responses)
    gateway = ToolGateway(client, bus, AdapterRegistry())

    sql = gateway.call(ToolExecutionRequest(
        tool_name="sqlmap_scan",
        arguments={"url": "https://example.test?id=1"},
        target="https://example.test?id=1",
        session_id="session-a",
    ))
    assert sql.success and len(sql.findings) == 1
    assert sql.findings[0].status.value == "validated"
    assert sql.extensions["sqlmap"]["dbms"] == "MySQL"

    nuclei = gateway.call(ToolExecutionRequest(
        tool_name="nuclei_scan", arguments={}, target="https://example.test", session_id="session-a"
    ))
    assert len(nuclei.findings) == 1
    assert nuclei.findings[0].status.value == "suspected"

    nmap = gateway.call(ToolExecutionRequest(
        tool_name="nmap_scan", arguments={}, target="127.0.0.1", session_id="session-a"
    ))
    assert nmap.metrics["open_port_count"] == 2

    generic = gateway.call(ToolExecutionRequest(
        tool_name="unknown_tool", arguments={}, target="t", session_id="session-a"
    ))
    assert generic.success and generic.raw["custom"]["a"] == 1
    assert generic.metrics["adapter"] == "generic"

    # Explicit false must never become a finding merely because the word exists.
    registry = AdapterRegistry()
    false_request = ToolExecutionRequest(tool_name="sqlmap", arguments={}, target="t", session_id="session-a")
    false_result = registry.get("sqlmap").normalize(false_request, responses["false_sqlmap"], false_request.created_at, 1)
    assert not false_result.findings

    events = bus.replay("session-a")
    assert any(item["type"] == "tool.started" for item in events)
    assert any(item["type"] == "tool.completed" for item in events)
    assert any(item["type"] == "finding.upsert" for item in events)
    assert all(item["schema_version"] == "1.0" for item in events)

    # Every event must remain JSON serializable.
    json.dumps(events, ensure_ascii=False)
    print("RUNTIME_CONTRACTS_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
