"""Tool gateway: one normalization and event path for every MCP invocation."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .adapters import AdapterRegistry
from .event_bus import EventBus
from .models import (
    ErrorInfo,
    EventSource,
    EventType,
    ExecutionEvent,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolStatus,
    utc_now,
)


class ToolGateway:
    def __init__(
        self,
        mcp_client: Any,
        event_bus: EventBus,
        adapter_registry: AdapterRegistry | None = None,
        source_kind: str = "agent",
        source_name: str = "HexStrike Agent",
    ):
        self.client = mcp_client
        self.event_bus = event_bus
        self.adapters = adapter_registry or AdapterRegistry()
        self.source_kind = source_kind
        self.source_name = source_name

    def _source(self, request: ToolExecutionRequest) -> EventSource:
        return EventSource(kind=self.source_kind, id=request.agent_id, name=self.source_name)

    def _publish(self, request: ToolExecutionRequest, event_type: EventType, payload: Dict[str, Any], error: ErrorInfo | None = None) -> None:
        self.event_bus.publish(ExecutionEvent(
            type=event_type,
            session_id=request.session_id,
            trace_id=request.trace_id,
            parent_id=request.parent_id or request.call_id,
            source=self._source(request),
            payload=payload,
            error=error,
        ))

    def call(
        self,
        request: ToolExecutionRequest,
        invoke: Callable[[str, Dict[str, Any]], Any] | None = None,
    ) -> ToolExecutionResult:
        """Execute an MCP tool, normalize any return shape and publish events.

        `invoke` exists for tests and migration adapters. Production defaults to
        the existing HexstrikeMcpClient._call_tool API, so Kali endpoints remain unchanged.
        """
        self._publish(request, EventType.TOOL_STARTED, {
            "call_id": request.call_id,
            "tool_name": request.tool_name,
            "target": request.target,
            "arguments": request.arguments,
            "agent_id": request.agent_id,
        })
        started_at = utc_now()
        started = time.monotonic()
        try:
            executor = invoke or self.client._call_tool
            raw = executor(request.tool_name, request.arguments)
            duration_ms = int((time.monotonic() - started) * 1000)
            adapter = self.adapters.get(request.tool_name)
            result = adapter.normalize(request, raw, started_at, duration_ms)
        except TimeoutError as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            result = ToolExecutionResult(
                tool_name=request.tool_name,
                call_id=request.call_id,
                target=request.target,
                status=ToolStatus.TIMEOUT,
                started_at=started_at,
                finished_at=utc_now(),
                duration_ms=duration_ms,
                summary=f"{request.tool_name} timed out",
                error=ErrorInfo(code="TOOL_TIMEOUT", message=str(exc), retryable=True),
            )
        except Exception as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            result = ToolExecutionResult(
                tool_name=request.tool_name,
                call_id=request.call_id,
                target=request.target,
                status=ToolStatus.FAILED,
                started_at=started_at,
                finished_at=utc_now(),
                duration_ms=duration_ms,
                summary=f"{request.tool_name} failed",
                error=ErrorInfo(code="TOOL_GATEWAY_ERROR", message=str(exc), retryable=False),
            )

        self._publish(
            request,
            EventType.TOOL_COMPLETED,
            result.to_dict(include_raw=False),
            error=result.error,
        )
        for finding in result.findings:
            self._publish(request, EventType.FINDING_UPSERT, finding.to_dict())
        return result
