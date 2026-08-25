"""
HexStrike RL Optimizer - 强化学习工具选择优化器

使用Multi-Armed Bandit和简单的强化学习算法优化工具选择。
"""

from __future__ import annotations

import json
import math
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np


@dataclass
class ToolPerformance:
    """工具性能统计"""
    tool_name: str
    total_uses: int = 0
    successful_uses: int = 0
    total_reward: float = 0.0
    average_reward: float = 0.0
    confidence_interval: float = 0.0
    last_used: Optional[datetime] = None
    
    # 上下文相关的性能
    context_performance: Dict[str, Dict[str, float]] = field(default_factory=dict)


@dataclass
class ActionReward:
    """动作奖励记录"""
    tool_name: str
    context_hash: str
    reward: float
    timestamp: datetime
    success: bool
    execution_time: float = 0.0
    vulnerability_found: bool = False


class RewardCalculator:
    """奖励计算器"""
    
    def __init__(self):
        # 奖励权重配置
        self.reward_weights = {
            "success": 1.0,           # 工具执行成功
            "vulnerability": 5.0,     # 发现漏洞
            "critical_vuln": 10.0,    # 发现严重漏洞
            "speed": 0.5,             # 执行速度快
            "accuracy": 2.0,          # 结果准确性
            "coverage": 1.5,          # 覆盖范围
            "false_positive": -2.0,   # 误报惩罚
            "timeout": -1.0,          # 超时惩罚
            "error": -0.5,            # 执行错误惩罚
        }
    
    def calculate_reward(
        self,
        tool_name: str,
        execution_result: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> float:
        """
        计算工具执行的奖励值
        
        Args:
            tool_name: 工具名称
            execution_result: 工具执行结果
            context: 执行上下文
            
        Returns:
            奖励值 (-10.0 到 10.0)
        """
        reward = 0.0
        context = context or {}
        
        # 基础成功奖励
        if execution_result.get("success", False):
            reward += self.reward_weights["success"]
        else:
            reward += self.reward_weights["error"]
        
        # 漏洞发现奖励
        vulnerabilities = execution_result.get("vulnerabilities", [])
        if vulnerabilities:
            reward += len(vulnerabilities) * self.reward_weights["vulnerability"]
            
            # 严重漏洞额外奖励
            critical_vulns = [v for v in vulnerabilities if v.get("severity") == "critical"]
            reward += len(critical_vulns) * self.reward_weights["critical_vuln"]
        
        # 执行时间奖励/惩罚
        execution_time = execution_result.get("execution_time", 0)
        if execution_time > 0:
            # 快速执行奖励（小于30秒）
            if execution_time < 30:
                reward += self.reward_weights["speed"]
            # 超时惩罚（大于300秒）
            elif execution_time > 300:
                reward += self.reward_weights["timeout"]
        
        # 结果质量评估
        stdout = execution_result.get("stdout", "")
        if stdout:
            # 简单的结果质量评估
            if len(stdout) > 100:  # 有实质性输出
                reward += self.reward_weights["accuracy"] * 0.5
            
            # 检查是否有明显的误报指标
            false_positive_indicators = ["no results", "not found", "failed to", "error"]
            if any(indicator in stdout.lower() for indicator in false_positive_indicators):
                reward += self.reward_weights["false_positive"] * 0.5
        
        # 上下文相关的奖励调整
        current_phase = context.get("current_phase", "discovery")
        
        # 阶段匹配奖励
        phase_tool_mapping = {
            "discovery": ["gobuster", "dirb", "ffuf", "nikto"],
            "vulnerability_scan": ["nuclei", "sqlmap", "xss"],
            "exploitation": ["metasploit", "exploit", "payload"],
        }
        
        if any(phase_tool in tool_name.lower() for phase_tool in phase_tool_mapping.get(current_phase, [])):
            reward += 0.5  # 阶段匹配奖励
        
        # 限制奖励范围
        return max(-10.0, min(10.0, reward))


class ToolSelectionBandit:
    """多臂老虎机工具选择器"""
    
    def __init__(self, exploration_rate: float = 0.1):
        self.exploration_rate = exploration_rate  # ε-greedy 探索率
        self.tool_performance: Dict[str, ToolPerformance] = {}
        self.reward_calculator = RewardCalculator()
        self.action_history: List[ActionReward] = []
        
        # UCB (Upper Confidence Bound) 参数
        self.confidence_level = 2.0
        self.total_actions = 0
    
    def select_tools(
        self,
        available_tools: List[str],
        context: Dict[str, Any] = None,
        strategy: str = "ucb",  # "epsilon_greedy", "ucb", "thompson_sampling"
        top_k: int = 5
    ) -> List[Tuple[str, float]]:
        """
        选择工具
        
        Args:
            available_tools: 可用工具列表
            context: 当前上下文
            strategy: 选择策略
            top_k: 返回前K个工具
            
        Returns:
            (工具名, 选择置信度) 的列表
        """
        context = context or {}
        context_hash = self._hash_context(context)
        
        tool_scores = []
        
        for tool in available_tools:
            if strategy == "epsilon_greedy":
                score = self._epsilon_greedy_score(tool, context_hash)
            elif strategy == "ucb":
                score = self._ucb_score(tool, context_hash)
            elif strategy == "thompson_sampling":
                score = self._thompson_sampling_score(tool, context_hash)
            else:
                score = self._ucb_score(tool, context_hash)  # 默认使用UCB
            
            tool_scores.append((tool, score))
        
        # 按分数排序
        tool_scores.sort(key=lambda x: x[1], reverse=True)
        
        return tool_scores[:top_k]
    
    def _epsilon_greedy_score(self, tool: str, context_hash: str) -> float:
        """ε-贪婪策略评分"""
        if random.random() < self.exploration_rate:
            # 探索：随机分数
            return random.random()
        else:
            # 利用：使用平均奖励
            return self._get_average_reward(tool, context_hash)
    
    def _ucb_score(self, tool: str, context_hash: str) -> float:
        """Upper Confidence Bound 评分"""
        performance = self.tool_performance.get(tool)
        if not performance or performance.total_uses == 0:
            return float('inf')  # 未使用过的工具优先尝试
        
        average_reward = self._get_average_reward(tool, context_hash)
        confidence_bonus = self.confidence_level * math.sqrt(
            math.log(self.total_actions) / performance.total_uses
        )
        
        return average_reward + confidence_bonus
    
    def _thompson_sampling_score(self, tool: str, context_hash: str) -> float:
        """Thompson Sampling 评分"""
        performance = self.tool_performance.get(tool)
        if not performance or performance.total_uses == 0:
            # 使用先验分布
            alpha, beta = 1, 1
        else:
            # 使用Beta分布参数
            alpha = performance.successful_uses + 1
            beta = performance.total_uses - performance.successful_uses + 1
        
        # 从Beta分布采样
        return np.random.beta(alpha, beta)
    
    def _get_average_reward(self, tool: str, context_hash: str) -> float:
        """获取工具的平均奖励"""
        performance = self.tool_performance.get(tool)
        if not performance or performance.total_uses == 0:
            return 0.0
        
        # 优先使用上下文相关的性能
        if context_hash in performance.context_performance:
            context_perf = performance.context_performance[context_hash]
            if context_perf.get("total_uses", 0) > 0:
                return context_perf.get("average_reward", 0.0)
        
        return performance.average_reward
    
    def update_performance(
        self,
        tool: str,
        execution_result: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> None:
        """更新工具性能"""
        context = context or {}
        context_hash = self._hash_context(context)
        
        # 计算奖励
        reward = self.reward_calculator.calculate_reward(tool, execution_result, context)
        success = execution_result.get("success", False)
        execution_time = execution_result.get("execution_time", 0.0)
        vulnerability_found = bool(execution_result.get("vulnerabilities"))
        
        # 记录动作奖励
        action_reward = ActionReward(
            tool_name=tool,
            context_hash=context_hash,
            reward=reward,
            timestamp=datetime.now(),
            success=success,
            execution_time=execution_time,
            vulnerability_found=vulnerability_found
        )
        self.action_history.append(action_reward)
        
        # 更新工具性能统计
        if tool not in self.tool_performance:
            self.tool_performance[tool] = ToolPerformance(tool_name=tool)
        
        performance = self.tool_performance[tool]
        performance.total_uses += 1
        if success:
            performance.successful_uses += 1
        
        performance.total_reward += reward
        performance.average_reward = performance.total_reward / performance.total_uses
        performance.last_used = datetime.now()
        
        # 更新上下文相关性能
        if context_hash not in performance.context_performance:
            performance.context_performance[context_hash] = {
                "total_uses": 0,
                "successful_uses": 0,
                "total_reward": 0.0,
                "average_reward": 0.0
            }
        
        context_perf = performance.context_performance[context_hash]
        context_perf["total_uses"] += 1
        if success:
            context_perf["successful_uses"] += 1
        context_perf["total_reward"] += reward
        context_perf["average_reward"] = context_perf["total_reward"] / context_perf["total_uses"]
        
        self.total_actions += 1
    
    def _hash_context(self, context: Dict[str, Any]) -> str:
        """生成上下文哈希"""
        # 选择关键上下文特征
        key_features = [
            "current_phase",
            "target_type",
            "cms_detected",
            "waf_detected",
            "has_login_page",
            "has_file_upload",
            "technology_stack"
        ]
        
        context_key = {}
        for feature in key_features:
            if feature in context:
                value = context[feature]
                if isinstance(value, list):
                    value = tuple(sorted(value))
                context_key[feature] = value
        
        return str(hash(json.dumps(context_key, sort_keys=True)))
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """获取性能统计"""
        stats = {
            "total_actions": self.total_actions,
            "total_tools": len(self.tool_performance),
            "exploration_rate": self.exploration_rate,
            "tools": {}
        }
        
        for tool_name, performance in self.tool_performance.items():
            success_rate = performance.successful_uses / performance.total_uses if performance.total_uses > 0 else 0.0
            
            stats["tools"][tool_name] = {
                "total_uses": performance.total_uses,
                "successful_uses": performance.successful_uses,
                "success_rate": success_rate,
                "average_reward": performance.average_reward,
                "last_used": performance.last_used.isoformat() if performance.last_used else None,
                "context_variants": len(performance.context_performance)
            }
        
        return stats
    
    def get_top_performing_tools(self, top_k: int = 10) -> List[Tuple[str, float]]:
        """获取表现最好的工具"""
        tool_scores = []
        
        for tool_name, performance in self.tool_performance.items():
            if performance.total_uses >= 3:  # 至少使用3次才考虑
                score = performance.average_reward
                tool_scores.append((tool_name, score))
        
        tool_scores.sort(key=lambda x: x[1], reverse=True)
        return tool_scores[:top_k]


# 便捷函数
def create_rl_optimizer(exploration_rate: float = 0.1) -> ToolSelectionBandit:
    """创建强化学习优化器"""
    return ToolSelectionBandit(exploration_rate)


def calculate_tool_reward(
    tool_name: str,
    execution_result: Dict[str, Any],
    context: Dict[str, Any] = None
) -> float:
    """计算工具奖励"""
    calculator = RewardCalculator()
    return calculator.calculate_reward(tool_name, execution_result, context)