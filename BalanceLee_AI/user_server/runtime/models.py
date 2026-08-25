"""Versioned runtime contracts shared by Web, headless and future agents."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


class ToolStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class FindingStatus(str, Enum):
    SUSPECTED = "suspected"
    VALIDATING = "validating"
    VALIDATED = "validated"
    REJECTED = "rejected"


class EventType(str, Enum):
    SESSION_CREATED = "session.created"
    SESSION_RESTORED = "session.restored"
    AGENT_STATUS = "agent.status"
    AGENT_MESSAGE = "agent.message"
    TASK_CREATED = "task.created"
    TASK_STATUS = "task.status"
    TOOL_STARTED = "tool.started"
    TOOL_PROGRESS = "tool.progress"
    TOOL_COMPLETED = "tool.completed"
    FINDING_UPSERT = "finding.upsert"
    MEMORY_UPSERT = "memory.upsert"
    IDEA_UPSERT = "idea.upsert"
    APPROVAL_REQUIRED = "approval.required"
    APPROVAL_RESOLVED = "approval.resolved"
    REPORT_READY = "report.ready"
    RUNTIME_ERROR = "runtime.error"
    RUNTIME_COMPLETED = "runtime.completed"


@dataclass
class ErrorInfo:
    code: str
    message: str
    retryable: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    evidence_id: str = field(default_factory=lambda: new_id("evidence"))
    kind: str = "text"
    summary: str = ""
    value: Any = None
    artifact_id: Optional[str] = None
    source_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Artifact:
    artifact_id: str = field(default_factory=lambda: new_id("artifact"))
    name: str = ""
    path: str = ""
    mime_type: str = "application/octet-stream"
    size: int = 0
    sha256: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    type: str
    title: str
    target: str
    finding_id: str = ""
    severity: str = "info"
    confidence: float = 0.0
    status: FindingStatus = FindingStatus.SUSPECTED
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    description: str = ""
    evidence_refs: List[str] = field(default_factory=list)
    source_tools: List[str] = field(default_factory=list)
    solver_id: Optional[str] = None
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)
    extensions: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.finding_id:
            key = "|".join(
                [self.target or "", self.endpoint or "", self.parameter or "", self.type or ""]
            )
            self.finding_id = hashlib.sha256(key.encode("utf-8")).hexdigest()
        if isinstance(self.status, str):
            self.status = FindingStatus(self.status)
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class ToolExecutionRequest:
    tool_name: str
    arguments: Dict[str, Any]
    target: str = ""
    call_id: str = field(default_factory=lambda: new_id("call"))
    session_id: str = ""
    trace_id: str = field(default_factory=lambda: new_id("trace"))
    parent_id: Optional[str] = None
    agent_id: str = "main"
    timeout: int = 300
    created_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.call_id:
            self.call_id = new_id("call")
        if not self.trace_id:
            self.trace_id = new_id("trace")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolExecutionResult:
    tool_name: str
    call_id: str
    target: str = ""
    status: ToolStatus = ToolStatus.SUCCEEDED
    started_at: str = field(default_factory=utc_now)
    finished_at: str = field(default_factory=utc_now)
    duration_ms: int = 0
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    summary: str = ""
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    raw: Any = None
    extensions: Dict[str, Any] = field(default_factory=dict)
    error: Optional[ErrorInfo] = None

    def __post_init__(self) -> None:
        if isinstance(self.status, str):
            self.status = ToolStatus(self.status)

    @property
    def success(self) -> bool:
        return self.status in {ToolStatus.SUCCEEDED, ToolStatus.PARTIAL}

    def to_dict(self, include_raw: bool = True) -> Dict[str, Any]:
        data = {
            "schema_version": SCHEMA_VERSION,
            "tool_name": self.tool_name,
            "call_id": self.call_id,
            "target": self.target,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "summary": self.summary,
            "findings": [item.to_dict() for item in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "metrics": self.metrics,
            "extensions": self.extensions,
            "error": self.error.to_dict() if self.error else None,
        }
        if include_raw:
            data["raw"] = self.raw
        return data


@dataclass
class EventSource:
    kind: str
    id: str
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionEvent:
    type: EventType
    session_id: str
    payload: Dict[str, Any]
    source: EventSource
    event_id: str = field(default_factory=lambda: new_id("evt"))
    trace_id: str = field(default_factory=lambda: new_id("trace"))
    parent_id: Optional[str] = None
    seq: int = 0
    timestamp: str = field(default_factory=utc_now)
    error: Optional[ErrorInfo] = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.type, str):
            self.type = EventType(self.type)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "parent_id": self.parent_id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "type": self.type.value,
            "source": self.source.to_dict(),
            "payload": self.payload,
            "error": self.error.to_dict() if self.error else None,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))
