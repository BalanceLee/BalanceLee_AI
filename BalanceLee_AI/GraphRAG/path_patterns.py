"""
HexStrike Path Pattern Matching - 渗透测试路径模式匹配

基于历史成功路径和模式识别，为工具选择提供路径建议。
"""

from __future__ import annotations

import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter


@dataclass
class PentestPath:
    """渗透测试路径"""
    name: str
    description: str
    tools: List[str]
    success_rate: float
    conditions: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    difficulty: str = "medium"  # easy, medium, hard
    estimated_time: int = 30  # minutes
    
    # 统计信息
    total_attempts: int = 0
    successful_attempts: int = 0
    last_used: Optional[datetime] = None


@dataclass
class PathRecommendation:
    """路径推荐"""
    path: PentestPath
    match_score: float
    reasons: List[str]
    next_tools: List[str]
    estimated_success_rate: float


class PentestPathPattern:
    """渗透测试路径模式匹配器"""
    
    def __init__(self):
        # 预定义的成功路径模式
        self.predefined_paths = [
            PentestPath(
                name="Classic Web App Discovery",
                description="经典Web应用发现流程",
                tools=["browser_visit_page", "gobuster_scan", "nikto_scan", "nuclei_scan"],
                success_rate=0.85,
                conditions={"target_type": "web_application"},
                tags=["web", "discovery", "basic"],
                difficulty="easy",
                estimated_time=20
            ),
            PentestPath(
                name="WordPress Exploitation Chain",
                description="WordPress漏洞利用链",
                tools=["browser_visit_page", "wpscan", "wp_plugin_exploit", "wp_user_enum"],
                success_rate=0.72,
                conditions={"cms": "WordPress"},
                tags=["wordpress", "cms", "exploitation"],
                difficulty="medium",
                estimated_time=45
            ),
            PentestPath(
                name="SQL Injection Discovery & Exploitation",
                description="SQL注入发现和利用",
                tools=["arjun_scan", "sqlmap_scan", "sqlmap_exploit", "database_dump"],
                success_rate=0.68,
                conditions={"has_parameters": True, "has_database": True},
                tags=["sqli", "database", "exploitation"],
                difficulty="medium",
                estimated_time=60
            ),
            PentestPath(
                name="API Security Testing",
                description="API安全测试流程",
                tools=["api_discovery", "jwt_analyzer", "api_fuzzing", "graphql_scanner"],
                success_rate=0.75,
                conditions={"target_type": "api", "has_api_endpoints": True},
                tags=["api", "rest", "graphql"],
                difficulty="medium",
                estimated_time=40
            ),
            PentestPath(
                name="File Upload Vulnerability Chain",
                description="文件上传漏洞利用链",
                tools=["file_upload_discovery", "upload_bypass_test", "webshell_upload", "privilege_escalation"],
                success_rate=0.65,
                conditions={"has_file_upload": True},
                tags=["file_upload", "webshell", "rce"],
                difficulty="hard",
                estimated_time=90
            ),
            PentestPath(
                name="Authentication Bypass Flow",
                description="认证绕过测试流程",
                tools=["login_discovery", "auth_bypass_test", "brute_force", "session_analysis"],
                success_rate=0.58,
                conditions={"has_login": True},
                tags=["auth", "bypass", "brute_force"],
                difficulty="medium",
                estimated_time=50
            ),
            PentestPath(
                name="XSS Discovery & Exploitation",
                description="XSS发现和利用",
                tools=["parameter_discovery", "xss_scanner", "dom_xss_test", "xss_payload_craft"],
                success_rate=0.70,
                conditions={"has_user_input": True, "has_reflection": True},
                tags=["xss", "client_side", "javascript"],
                difficulty="easy",
                estimated_time=35
            ),
            PentestPath(
                name="Network Service Enumeration",
                description="网络服务枚举",
                tools=["nmap_scan", "service_enum", "version_detection", "vulnerability_scan"],
                success_rate=0.80,
                conditions={"target_type": "network", "has_open_ports": True},
                tags=["network", "enumeration", "services"],
                difficulty="easy",
                estimated_time=25
            ),
            PentestPath(
                name="OSINT & Reconnaissance",
                description="开源情报收集",
                tools=["subdomain_enum", "dns_enum", "social_media_recon", "email_harvest"],
                success_rate=0.90,
                conditions={"phase": "reconnaissance"},
                tags=["osint", "recon", "passive"],
                difficulty="easy",
                estimated_time=30
            ),
            PentestPath(
                name="Cloud Security Assessment",
                description="云安全评估",
                tools=["cloud_enum", "s3_bucket_scan", "iam_analysis", "cloud_misconfig_scan"],
                success_rate=0.65,
                conditions={"target_type": "cloud", "cloud_provider": ["aws", "azure", "gcp"]},
                tags=["cloud", "aws", "azure", "gcp"],
                difficulty="hard",
                estimated_time=120
            )
        ]
        
        # 历史路径数据（模拟）
        self.historical_paths = defaultdict(list)
        self.path_statistics = defaultdict(lambda: {"attempts": 0, "successes": 0})
        
        # 工具序列模式
        self.tool_sequences = defaultdict(Counter)
        
        # 初始化一些模拟数据
        self._initialize_mock_data()
    
    def _initialize_mock_data(self):
        """初始化模拟的历史数据"""
        # 模拟一些成功的工具序列
        successful_sequences = [
            ["browser_visit_page", "gobuster_scan", "nuclei_scan"],
            ["nmap_scan", "gobuster_scan", "sqlmap_scan"],
            ["subdomain_enum", "nmap_scan", "nuclei_scan"],
            ["wpscan", "wp_plugin_exploit"],
            ["arjun_scan", "sqlmap_scan"],
            ["api_discovery", "jwt_analyzer"],
        ]
        
        for sequence in successful_sequences:
            for i in range(len(sequence) - 1):
                current_tool = sequence[i]
                next_tool = sequence[i + 1]
                self.tool_sequences[current_tool][next_tool] += 1
    
    def find_matching_paths(
        self,
        context: Dict[str, Any],
        executed_tools: List[str] = None,
        max_paths: int = 5
    ) -> List[PathRecommendation]:
        """
        查找匹配的路径模式
        
        Args:
            context: 当前上下文信息
            executed_tools: 已执行的工具
            max_paths: 最大返回路径数
            
        Returns:
            路径推荐列表
        """
        executed_tools = executed_tools or []
        recommendations = []
        
        for path in self.predefined_paths:
            match_score, reasons = self._calculate_path_match(path, context, executed_tools)
            
            if match_score > 0.3:  # 最低匹配阈值
                next_tools = self._get_next_tools_in_path(path, executed_tools)
                estimated_success_rate = self._estimate_success_rate(path, context)
                
                recommendation = PathRecommendation(
                    path=path,
                    match_score=match_score,
                    reasons=reasons,
                    next_tools=next_tools,
                    estimated_success_rate=estimated_success_rate
                )
                recommendations.append(recommendation)
        
        # 按匹配分数排序
        recommendations.sort(key=lambda x: x.match_score, reverse=True)
        
        return recommendations[:max_paths]
    
    def _calculate_path_match(
        self,
        path: PentestPath,
        context: Dict[str, Any],
        executed_tools: List[str]
    ) -> Tuple[float, List[str]]:
        """计算路径匹配度"""
        score = 0.0
        reasons = []
        
        # 条件匹配检查
        for condition, expected_value in path.conditions.items():
            context_value = context.get(condition)
            
            if isinstance(expected_value, bool):
                if context_value == expected_value:
                    score += 0.3
                    reasons.append(f"条件匹配: {condition}={expected_value}")
            elif isinstance(expected_value, str):
                if context_value == expected_value:
                    score += 0.3
                    reasons.append(f"条件匹配: {condition}={expected_value}")
            elif isinstance(expected_value, list):
                if context_value in expected_value:
                    score += 0.3
                    reasons.append(f"条件匹配: {condition} in {expected_value}")
        
        # 已执行工具匹配
        path_tools_set = set(path.tools)
        executed_tools_set = set(executed_tools)
        
        # 如果已经执行了路径中的一些工具，增加匹配度
        common_tools = path_tools_set & executed_tools_set
        if common_tools:
            score += len(common_tools) / len(path_tools_set) * 0.4
            reasons.append(f"已执行路径工具: {list(common_tools)}")
        
        # 阶段匹配
        current_phase = context.get("current_phase", "discovery")
        if current_phase in path.tags:
            score += 0.2
            reasons.append(f"阶段匹配: {current_phase}")
        
        # 目标类型匹配
        target_type = context.get("target_type", "web_application")
        if target_type in path.tags:
            score += 0.2
            reasons.append(f"目标类型匹配: {target_type}")
        
        # 技术栈匹配
        technology_stack = context.get("technology_stack", [])
        for tech in technology_stack:
            if tech.lower() in path.tags:
                score += 0.1
                reasons.append(f"技术栈匹配: {tech}")
        
        # CMS匹配
        cms_detected = context.get("cms_detected")
        if cms_detected and cms_detected.lower() in path.tags:
            score += 0.3
            reasons.append(f"CMS匹配: {cms_detected}")
        
        return min(1.0, score), reasons
    
    def _get_next_tools_in_path(self, path: PentestPath, executed_tools: List[str]) -> List[str]:
        """获取路径中的下一个工具"""
        next_tools = []
        
        for tool in path.tools:
            if tool not in executed_tools:
                next_tools.append(tool)
                if len(next_tools) >= 3:  # 最多返回3个下一步工具
                    break
        
        return next_tools
    
    def _estimate_success_rate(self, path: PentestPath, context: Dict[str, Any]) -> float:
        """估算成功率"""
        base_rate = path.success_rate
        
        # 根据上下文调整成功率
        adjustments = 0.0
        
        # WAF检测会降低成功率
        if context.get("waf_detected"):
            adjustments -= 0.2
        
        # 安全头会降低成功率
        security_headers = context.get("security_headers", [])
        if security_headers:
            adjustments -= len(security_headers) * 0.05
        
        # 已知漏洞会提高成功率
        suspected_vulns = context.get("suspected_vulns", [])
        if suspected_vulns:
            adjustments += len(suspected_vulns) * 0.1
        
        # 技术栈匹配会提高成功率
        technology_stack = context.get("technology_stack", [])
        for tech in technology_stack:
            if tech.lower() in path.tags:
                adjustments += 0.05
        
        return max(0.1, min(0.95, base_rate + adjustments))
    
    def get_next_tool_suggestions(
        self,
        last_tool: str,
        context: Dict[str, Any] = None,
        top_k: int = 5
    ) -> List[Tuple[str, float]]:
        """
        基于上一个工具获取下一个工具建议
        
        Args:
            last_tool: 上一个执行的工具
            context: 上下文信息
            top_k: 返回前K个建议
            
        Returns:
            (工具名, 置信度) 的列表
        """
        suggestions = []
        
        # 基于历史序列模式
        if last_tool in self.tool_sequences:
            total_count = sum(self.tool_sequences[last_tool].values())
            for next_tool, count in self.tool_sequences[last_tool].most_common(top_k):
                confidence = count / total_count
                suggestions.append((next_tool, confidence))
        
        # 基于路径模式
        context = context or {}
        matching_paths = self.find_matching_paths(context, [last_tool], max_paths=3)
        
        for recommendation in matching_paths:
            for next_tool in recommendation.next_tools[:2]:  # 每个路径最多取2个工具
                # 避免重复
                if not any(tool == next_tool for tool, _ in suggestions):
                    confidence = recommendation.match_score * 0.8  # 稍微降低置信度
                    suggestions.append((next_tool, confidence))
        
        # 按置信度排序并返回前K个
        suggestions.sort(key=lambda x: x[1], reverse=True)
        return suggestions[:top_k]
    
    def record_path_execution(
        self,
        tools: List[str],
        success: bool,
        context: Dict[str, Any] = None
    ) -> None:
        """记录路径执行结果"""
        # 更新工具序列统计
        for i in range(len(tools) - 1):
            current_tool = tools[i]
            next_tool = tools[i + 1]
            if success:
                self.tool_sequences[current_tool][next_tool] += 1
        
        # 查找匹配的预定义路径并更新统计
        context = context or {}
        for path in self.predefined_paths:
            match_score, _ = self._calculate_path_match(path, context, tools)
            if match_score > 0.5:  # 高匹配度才记录
                path.total_attempts += 1
                if success:
                    path.successful_attempts += 1
                path.success_rate = path.successful_attempts / path.total_attempts
                path.last_used = datetime.now()
    
    def get_path_statistics(self) -> Dict[str, Any]:
        """获取路径统计信息"""
        stats = {
            "total_paths": len(self.predefined_paths),
            "paths": []
        }
        
        for path in self.predefined_paths:
            path_stats = {
                "name": path.name,
                "success_rate": path.success_rate,
                "total_attempts": path.total_attempts,
                "successful_attempts": path.successful_attempts,
                "last_used": path.last_used.isoformat() if path.last_used else None,
                "tags": path.tags,
                "difficulty": path.difficulty
            }
            stats["paths"].append(path_stats)
        
        return stats


# 便捷函数
def find_pentest_paths(
    context: Dict[str, Any],
    executed_tools: List[str] = None,
    max_paths: int = 5
) -> List[PathRecommendation]:
    """便捷函数：查找渗透测试路径"""
    pattern_matcher = PentestPathPattern()
    return pattern_matcher.find_matching_paths(context, executed_tools, max_paths)


def get_next_tool_suggestions(
    last_tool: str,
    context: Dict[str, Any] = None,
    top_k: int = 5
) -> List[Tuple[str, float]]:
    """便捷函数：获取下一个工具建议"""
    pattern_matcher = PentestPathPattern()
    return pattern_matcher.get_next_tool_suggestions(last_tool, context, top_k)