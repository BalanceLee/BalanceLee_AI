"""Temporary compatibility adapter from runtime events to the legacy UI events."""

from __future__ import annotations

from typing import Any, Dict

from .models import EventType, ExecutionEvent


class LegacySocketAdapter:
    def __init__(self, socketio):
        self.socketio = socketio

    def emit(self, event: ExecutionEvent) -> None:
        data = event.to_dict()
        self.socketio.emit("runtime_event", data, room=event.session_id)

        payload = event.payload
        timestamp = event.timestamp
        if event.type == EventType.TOOL_STARTED:
            self.socketio.emit("tool_start", {
                "tool_name": payload.get("tool_name"),
                "parameters": payload.get("arguments", {}),
                "timestamp": timestamp,
                "call_id": payload.get("call_id"),
            }, room=event.session_id)
        elif event.type == EventType.TOOL_COMPLETED:
            self.socketio.emit("tool_complete", {
                "tool_name": payload.get("tool_name"),
                "success": payload.get("status") in {"succeeded", "partial"},
                "result": payload,
                "timestamp": timestamp,
                "call_id": payload.get("call_id"),
            }, room=event.session_id)
        elif event.type == EventType.FINDING_UPSERT:
            self.socketio.emit("vulnerability_found", {
                "finding_id": payload.get("finding_id"),
                "vuln_type": payload.get("title") or payload.get("type"),
                "severity": payload.get("severity", "info"),
                "confidence": payload.get("confidence", 0),
                "description": payload.get("description", ""),
                "payload": payload.get("payload"),
                "affected_url": payload.get("target"),
                "timestamp": timestamp,
            }, room=event.session_id)
        elif event.type == EventType.AGENT_MESSAGE:
            self.socketio.emit("ai_message", {
                "message": payload.get("message", ""),
                "timestamp": timestamp,
            }, room=event.session_id)
        elif event.type == EventType.RUNTIME_ERROR:
            self.socketio.emit("error", {
                "message": (data.get("error") or {}).get("message") or payload.get("message", "Runtime error")
            }, room=event.session_id)
