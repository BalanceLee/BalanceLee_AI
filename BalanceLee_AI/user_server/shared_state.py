#!/usr/bin/env python3
"""
共享状态板（Shared State Board）—— 多智能体协同的团队经验沉淀。

对照绿盟 AI 小分队《Adaptive Architecture for Pentest Agents》的双层状态设计：
  - Idea Board（策略层）：值得继续验证的攻击方向 & 假设，
    状态机 Pending -> Testing -> Verified / Failed
  - Memory Board（事实层）：已知事实、证据与边界，
    类型 Evidence / FailureBoundary / Hint / Constraint

存储方案：JSON 分文件（一个 target 一个文件），Repository 抽象接口，未来可平滑切换 SQLite。
并发说明：写入者只有 Observer 一个（Solver 局部记忆不直接广播），天然串行；
          这里仍加 threading.RLock 作为兜底，并用临时文件 + os.replace 原子写入。

纯标准库实现，无第三方依赖。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

# 合法状态与类型，写入时做校验，防止脏数据。
IDEA_STATUSES = ("Pending", "Testing", "Verified", "Failed")
MEMORY_TYPES = ("Evidence", "FailureBoundary", "Hint", "Constraint")


def _now() -> str:
    """统一时间戳格式（ISO 8601，秒级）。"""
    return datetime.now().isoformat(timespec="seconds")


def _safe_filename(target: str) -> str:
    """把 target（可能是 URL / IP / 域名）转成安全的文件名，防路径穿越。"""
    cleaned = (
        target.replace("://", "_")
        .replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace("*", "_")
        .replace("?", "_")
        .replace('"', "_")
        .replace("<", "_")
        .replace(">", "_")
        .replace("|", "_")
        .strip()
    )
    return cleaned or "default"


@dataclass
class Idea:
    """策略层：一条待验证的攻击假设 / 方向。"""

    id: int
    category: str
    status: str
    content: str
    evidence_ref: Optional[int] = None
    created_at: str = ""
    updated_at: str = ""


@dataclass
class Memory:
    """事实层：一条已知事实、证据或边界。"""

    id: int
    type: str
    content: str
    source_tool: Optional[str] = None
    created_at: str = ""


class SharedStateStore:
    """抽象接口（Repository 模式）。业务代码只依赖这个接口。"""

    def add_idea(
        self,
        target: str,
        category: str,
        content: str,
        status: str = "Pending",
        evidence_ref: Optional[int] = None,
    ) -> Idea:
        raise NotImplementedError

    def update_idea_status(
        self,
        target: str,
        idea_id: int,
        new_status: str,
        evidence_ref: Optional[int] = None,
    ) -> Optional[Idea]:
        raise NotImplementedError

    def list_ideas(self, target: str, status: Optional[str] = None) -> List[Idea]:
        raise NotImplementedError

    def add_memory(
        self,
        target: str,
        type: str,
        content: str,
        source_tool: Optional[str] = None,
    ) -> Memory:
        raise NotImplementedError

    def list_memories(self, target: str, type: Optional[str] = None) -> List[Memory]:
        raise NotImplementedError

    def get_summary(self, target: str) -> Dict[str, Any]:
        """给 Manager 的"可决策视图"：活跃/已验证/已失败 idea + 事实层 + 统计。"""
        raise NotImplementedError


class JsonStateStore(SharedStateStore):
    """JSON 文件实现：memory/<target>.json。"""

    def __init__(self, dir_path: str = "memory/"):
        self.dir_path = dir_path
        self._lock = threading.RLock()
        os.makedirs(self.dir_path, exist_ok=True)

    # ---------- 内部读写 ----------

    def _file_path(self, target: str) -> str:
        return os.path.join(self.dir_path, _safe_filename(target) + ".json")

    def _load(self, target: str) -> Dict[str, Any]:
        path = self._file_path(target)
        if not os.path.exists(path):
            return {"target": target, "ideas": [], "memories": []}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("ideas", [])
        data.setdefault("memories", [])
        return data

    def _save(self, target: str, data: Dict[str, Any]) -> None:
        path = self._file_path(target)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)  # 原子替换，避免写一半损坏

    def _next_id(self, items: List[Dict[str, Any]]) -> int:
        existing = [it.get("id", 0) for it in items if isinstance(it, dict)]
        return (max(existing) if existing else 0) + 1

    # ---------- Idea Board ----------

    def add_idea(
        self,
        target: str,
        category: str,
        content: str,
        status: str = "Pending",
        evidence_ref: Optional[int] = None,
    ) -> Idea:
        if status not in IDEA_STATUSES:
            raise ValueError(f"invalid status: {status!r}, allowed: {IDEA_STATUSES}")
        with self._lock:
            data = self._load(target)
            idea_id = self._next_id(data["ideas"])
            now = _now()
            idea = Idea(
                id=idea_id,
                category=category,
                status=status,
                content=content,
                evidence_ref=evidence_ref,
                created_at=now,
                updated_at=now,
            )
            data["ideas"].append(asdict(idea))
            self._save(target, data)
            return idea

    def update_idea_status(
        self,
        target: str,
        idea_id: int,
        new_status: str,
        evidence_ref: Optional[int] = None,
    ) -> Optional[Idea]:
        if new_status not in IDEA_STATUSES:
            raise ValueError(f"invalid status: {new_status!r}, allowed: {IDEA_STATUSES}")
        with self._lock:
            data = self._load(target)
            for item in data["ideas"]:
                if item.get("id") == idea_id:
                    item["status"] = new_status
                    if evidence_ref is not None:
                        item["evidence_ref"] = evidence_ref
                    item["updated_at"] = _now()
                    self._save(target, data)
                    return Idea(**item)
        return None

    def list_ideas(self, target: str, status: Optional[str] = None) -> List[Idea]:
        with self._lock:
            data = self._load(target)
        ideas = [Idea(**it) for it in data["ideas"]]
        if status:
            ideas = [i for i in ideas if i.status == status]
        return ideas

    # ---------- Memory Board ----------

    def add_memory(
        self,
        target: str,
        type: str,
        content: str,
        source_tool: Optional[str] = None,
    ) -> Memory:
        if type not in MEMORY_TYPES:
            raise ValueError(f"invalid type: {type!r}, allowed: {MEMORY_TYPES}")
        with self._lock:
            data = self._load(target)
            memory_id = self._next_id(data["memories"])
            memory = Memory(
                id=memory_id,
                type=type,
                content=content,
                source_tool=source_tool,
                created_at=_now(),
            )
            data["memories"].append(asdict(memory))
            self._save(target, data)
            return memory

    def list_memories(self, target: str, type: Optional[str] = None) -> List[Memory]:
        with self._lock:
            data = self._load(target)
        memories = [Memory(**it) for it in data["memories"]]
        if type:
            memories = [m for m in memories if m.type == type]
        return memories

    # ---------- 汇总视图 ----------

    def get_summary(self, target: str) -> Dict[str, Any]:
        with self._lock:
            data = self._load(target)
        ideas = data["ideas"]
        memories = data["memories"]
        return {
            "target": target,
            "active_ideas": [i for i in ideas if i["status"] in ("Pending", "Testing")],
            "verified_ideas": [i for i in ideas if i["status"] == "Verified"],
            "failed_ideas": [i for i in ideas if i["status"] == "Failed"],
            "memories": memories,
            "stats": {
                "total_ideas": len(ideas),
                "total_memories": len(memories),
            },
        }
