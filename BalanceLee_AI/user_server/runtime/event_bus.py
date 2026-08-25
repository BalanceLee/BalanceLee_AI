"""Runtime event bus with durable ordering and pluggable subscribers."""

from __future__ import annotations

import threading
from typing import Callable, List, Optional

from .event_store import JsonlEventStore
from .models import ExecutionEvent

EventSubscriber = Callable[[ExecutionEvent], None]


class EventBus:
    def __init__(self, store: JsonlEventStore):
        self.store = store
        self._subscribers: List[EventSubscriber] = []
        self._lock = threading.RLock()

    def subscribe(self, callback: EventSubscriber) -> Callable[[], None]:
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

    def publish(self, event: ExecutionEvent) -> ExecutionEvent:
        event = self.store.append(event)
        with self._lock:
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:
                # Event persistence must not be rolled back by a faulty UI/observer subscriber.
                continue
        return event

    def replay(self, session_id: str, after_seq: int = 0, limit: int = 500) -> list[dict]:
        return self.store.list_after(session_id, after_seq=after_seq, limit=limit)
