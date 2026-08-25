"""Append-only JSONL event store with per-session sequence numbers."""

from __future__ import annotations

import json
import os
import threading
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List

from .models import ExecutionEvent


class JsonlEventStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._seq: Dict[str, int] = defaultdict(int)

    def _safe_session_id(self, session_id: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in session_id)
        return safe or "default"

    def _path(self, session_id: str) -> Path:
        return self.root / f"{self._safe_session_id(session_id)}.jsonl"

    def _load_last_seq(self, session_id: str) -> int:
        path = self._path(session_id)
        if not path.exists():
            return 0
        last = 0
        with path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    last = max(last, int(json.loads(line).get("seq", 0)))
                except (json.JSONDecodeError, ValueError, TypeError):
                    continue
        return last

    def append(self, event: ExecutionEvent) -> ExecutionEvent:
        with self._lock:
            if self._seq[event.session_id] == 0:
                self._seq[event.session_id] = self._load_last_seq(event.session_id)
            if event.seq <= 0:
                self._seq[event.session_id] += 1
                event.seq = self._seq[event.session_id]
            else:
                self._seq[event.session_id] = max(self._seq[event.session_id], event.seq)
            path = self._path(event.session_id)
            with path.open("a", encoding="utf-8") as f:
                f.write(event.to_json() + "\n")
                f.flush()
                os.fsync(f.fileno())
        return event

    def list_after(self, session_id: str, after_seq: int = 0, limit: int = 500) -> List[dict]:
        path = self._path(session_id)
        if not path.exists():
            return []
        result: List[dict] = []
        with self._lock, path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if int(item.get("seq", 0)) > after_seq:
                    result.append(item)
                    if len(result) >= limit:
                        break
        return result

    def last_seq(self, session_id: str) -> int:
        with self._lock:
            if self._seq[session_id] == 0:
                self._seq[session_id] = self._load_last_seq(session_id)
            return self._seq[session_id]
