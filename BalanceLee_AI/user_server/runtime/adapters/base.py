"""Base helpers for converting heterogeneous tool output to runtime contracts."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, Optional

from ..models import ErrorInfo, ToolExecutionRequest, ToolExecutionResult, ToolStatus, utc_now


def unwrap_result(raw: Any) -> Any:
    if isinstance(raw, dict) and isinstance(raw.get("result"), dict):
        return raw["result"]
    return raw


def text_value(value: Any, limit: int | None = None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except TypeError:
            text = str(value)
    return text if limit is None else text[:limit]


def infer_success(data: Any) -> bool:
    if isinstance(data, dict):
        if "success" in data:
            return bool(data["success"])
        if str(data.get("status", "")).lower() in {"failed", "error", "timeout"}:
            return False
        if data.get("error") and not data.get("result"):
            return False
    return True


def extract_streams(data: Any) -> tuple[str, str]:
    if isinstance(data, dict):
        stdout = data.get("stdout") or data.get("output") or data.get("content") or data.get("text") or ""
        stderr = data.get("stderr") or ""
        return text_value(stdout), text_value(stderr)
    return text_value(data), ""


class ToolResultAdapter(ABC):
    tool_names: set[str] = set()

    def matches(self, tool_name: str) -> bool:
        return tool_name in self.tool_names

    @abstractmethod
    def normalize(
        self,
        request: ToolExecutionRequest,
        raw_result: Any,
        started_at: str,
        duration_ms: int,
    ) -> ToolExecutionResult:
        raise NotImplementedError

    def base_result(
        self,
        request: ToolExecutionRequest,
        raw_result: Any,
        started_at: str,
        duration_ms: int,
        summary: str = "",
    ) -> ToolExecutionResult:
        data = unwrap_result(raw_result)
        stdout, stderr = extract_streams(data)
        success = infer_success(data)
        error = None
        if not success:
            if isinstance(data, dict):
                message = text_value(data.get("error") or stderr or "tool execution failed", 2000)
            else:
                message = stderr or "tool execution failed"
            error = ErrorInfo(code="TOOL_EXECUTION_FAILED", message=message, retryable=False)
        return ToolExecutionResult(
            tool_name=request.tool_name,
            call_id=request.call_id,
            target=request.target,
            status=ToolStatus.SUCCEEDED if success else ToolStatus.FAILED,
            started_at=started_at,
            finished_at=utc_now(),
            duration_ms=duration_ms,
            exit_code=data.get("exit_code") if isinstance(data, dict) else None,
            stdout=stdout,
            stderr=stderr,
            summary=summary or (f"{request.tool_name} completed" if success else f"{request.tool_name} failed"),
            raw=raw_result,
            error=error,
        )
