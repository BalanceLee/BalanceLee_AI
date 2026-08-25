"""Safe fallback adapter for every MCP tool without a dedicated parser."""

from __future__ import annotations

from typing import Any

from .base import ToolResultAdapter, text_value, unwrap_result
from ..models import ToolExecutionRequest, ToolExecutionResult


class GenericAdapter(ToolResultAdapter):
    def matches(self, tool_name: str) -> bool:
        return True

    def normalize(self, request: ToolExecutionRequest, raw_result: Any, started_at: str, duration_ms: int) -> ToolExecutionResult:
        data = unwrap_result(raw_result)
        summary = ""
        if isinstance(data, dict):
            summary = text_value(data.get("summary") or data.get("message"), 1000)
        result = self.base_result(request, raw_result, started_at, duration_ms, summary=summary)
        result.metrics["adapter"] = "generic"
        return result
