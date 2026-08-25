"""Adapter registry. Unknown tools always fall back to GenericAdapter."""

from __future__ import annotations

from typing import Iterable, List

from .base import ToolResultAdapter
from .core_tools import (
    BrowserAdapter,
    DalfoxAdapter,
    HttpxAdapter,
    NmapAdapter,
    NucleiAdapter,
    SqlmapAdapter,
    WebSkillAdapter,
)
from .generic import GenericAdapter


class AdapterRegistry:
    def __init__(self, adapters: Iterable[ToolResultAdapter] | None = None):
        self.adapters: List[ToolResultAdapter] = list(adapters or [
            NmapAdapter(),
            HttpxAdapter(),
            NucleiAdapter(),
            SqlmapAdapter(),
            DalfoxAdapter(),
            BrowserAdapter(),
            WebSkillAdapter(),
        ])
        self.fallback = GenericAdapter()

    def get(self, tool_name: str) -> ToolResultAdapter:
        for adapter in self.adapters:
            if adapter.matches(tool_name):
                return adapter
        return self.fallback

    def register(self, adapter: ToolResultAdapter, prepend: bool = True) -> None:
        if prepend:
            self.adapters.insert(0, adapter)
        else:
            self.adapters.append(adapter)
