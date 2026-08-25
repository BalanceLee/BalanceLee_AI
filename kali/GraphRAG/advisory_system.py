"""
HexStrike Advisory System - 知识顾问系统

这个系统只提供建议，不做决策。
最终决策权完全在LLM Agent手中。

核心原则：
1. 提供建议，不强制执行
2. 给出理由，不只是结论
3. 展示全部工具，只是排序
4. LLM可以完全忽略建议
"""

from __future__ import annotations

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from .tool_selector import HexStrikeToolSelector, ToolRecommendation
from .phase_aware import WebPentestContext, ContextUpdater
from .fingerprint_engine import WebFingerprintExtractor, extract_web_fingerprint
from .path_patterns import PentestPathPattern, find_pentest_paths
from .rl_optimizer import ToolSelectionBandit, create_rl_optimizer


@dataclass
class ToolAdvisory:
    """工具建议（非命令）"""
    tool_name: str
    advisory_score: float  # 建议分数，不是决策分数
    reasons: List[str]
    confidence: float
    source: str  # "GraphRAG", "Fingerprint", "PathPattern", "RL"
    category: str
    phase: str
    
    # 统计信息（供LLM参考）
    historical_stats: Dict[str, Any] = field(default_factory=dict)
    
    # 警告信息
    warnings: List[str] = field(default_factory=list)


@dataclass
class PentestAdvisory:
    """完整的渗透测试建议"""
    
    # 当前状态观察
    current_situation: Dict[str, Any]
    
    # 所有可用工具（不过滤）
    all_available_tools: List[Dict[str, Any]]
    
    # 建议（按置信度分组）
    recommendations: Dict[str, List[ToolAdvisory]]
    
    # 知识库信息
    knowledge: Dict[str, Any]
    
    # 警告和提示
    warnings: List[str]
    alerts: List[str]
    
    # 历史成功路径（仅供参考）
    historical_paths: List[Dict[str, Any]]
    
    # 上下文提示
    context_hints: Dict[str, Any]
    
    # 生成时间
    timestamp: datetime = field(default_factory=datetime.now)


class AdvisorySystem:
    """知识顾问系统 - 只提供建议，不做决策"""
    
    def __init__(self):
        # 保留原有的GraphRAG选择器
        self.graph_selector = HexStrikeToolSelector()
        
        # 新增的增强模块
        self.fingerprint_extractor = WebFingerprintExtractor()
        self.path_pattern = PentestPathPattern()
        self.rl_optimizer = create_rl_optimizer(exploration_rate=0.15)
        
        # 配置
        self.config = {
            "provide_all_tools": True,  # 提供全部工具
            "max_recommendations": 30,   # 最多推荐数量
            "min_confidence": 0.3,       # 最低置信度
            "use_fingerprinting": True,  # 启用指纹识别
            "use_path_patterns": True,   # 启用路径模式
            "use_rl_optimization": True, # 启用强化学习
        }
    
    def provide_advisory(
        self, 
        context: WebPentestContext,
        html: Optional[str] = None,
        headers: Optional[Dict] = None,
        executed_tools: Optional[List[str]] = None
    ) -> PentestAdvisory:
        """
        提供完整的建议（不做决策）
        
        Args:
            context: 当前渗透测试上下文
            html: 网页HTML（可选）
            headers: HTTP头（可选）
            executed_tools: 已执行工具列表（可选）
        
        Returns:
            PentestAdvisory: 完整的建议信息
        """
        executed_tools = executed_tools or []
        
        # 1. 观察当前状态
        current_situation = self._observe_situation(context)
        
        # 2. 获取所有可用工具
        all_tools = self._get_all_available_tools()
        
        # 3. 生成建议（使用GraphRAG）
        recommendations = self._generate_recommendations(
            context, html, headers, executed_tools
        )
        
        # 4. 提取知识库信息
        knowledge = self._extract_knowledge(context, html, headers)
        
        # 5. 生成警告和提示
        warnings, alerts = self._generate_warnings_and_alerts(
            context, html, headers
        )
        
        # 6. 查找历史成功路径
        historical_paths = self._find_historical_paths(
            context, executed_tools
        )
        
        # 7. 生成上下文提示
        context_hints = self._generate_context_hints(context)
        
        return PentestAdvisory(
            current_situation=current_situation,
            all_available_tools=all_tools,
            recommendations=recommendations,
            knowledge=knowledge,
            warnings=warnings,
            alerts=alerts,
            historical_paths=historical_paths,
            context_hints=context_hints
        )
    
    def _observe_situation(self, context: WebPentestContext) -> Dict[str, Any]:
        """观察当前状态"""
        return {
            "target": context.target_url,
            "current_phase": context.current_phase,
            "phase_history": context.phase_history,
            
            # 已发现的信息
            "discoveries": {
                "urls": len(context.discovered_urls),
                "forms": len(context.discovered_forms),
                "endpoints": len(context.discovered_endpoints),
                "parameters": len(context.injectable_params),
                "vulnerabilities": len(context.suspected_vulns),
            },
            
            # 技术栈
            "technology": {
                "stack": context.technology_stack,
                "cms": context.cms_detected,
                "waf": context.waf_detected,
            },
            
            # 特征标记
            "features": {
                "has_login": context.has_login_page,
                "has_upload": context.has_file_upload,
                "has_search": context.has_search_function,
                "is_authenticated": context.is_authenticated,
            },
            
            # 测试状态
            "test_status": context.vuln_test_status,
        }
    
    def _get_all_available_tools(self) -> List[Dict[str, Any]]:
        """获取所有可用工具（不过滤）"""
        all_tools = []
        
        for tool_name, tool_node in self.graph_selector.graph.tool_nodes.items():
            all_tools.append({
                "name": tool_name,
                "category": tool_node.category,
                "phase": tool_node.phase,
                "description": tool_node.description,
                "execution_time": tool_node.execution_time,
                "is_aggressive": tool_node.is_aggressive,
                "requires_auth": tool_node.requires_auth,
                "tags": list(tool_node.tags),
            })
        
        return all_tools
    
    def _generate_recommendations(
        self,
        context: WebPentestContext,
        html: Optional[str],
        headers: Optional[Dict],
        executed_tools: List[str]
    ) -> Dict[str, List[ToolAdvisory]]:
        """生成工具建议（分置信度等级）- 集成多种智能算法"""
        
        # 1. GraphRAG 基础推荐
        graph_recs = self.graph_selector.select_tools(
            context.target_url,
            context=self._context_to_dict(context),
            max_tools=self.config["max_recommendations"]
        )
        
        # 2. 指纹识别增强
        fingerprint_features = []
        if self.config["use_fingerprinting"] and (html or headers):
            try:
                fingerprint = self.fingerprint_extractor.extract_fingerprint(
                    url=context.target_url,
                    html=html,
                    headers=headers
                )
                fingerprint_features = self.fingerprint_extractor.fingerprint_to_context_features(fingerprint)
            except Exception as e:
                # 指纹识别失败不影响主流程
                pass
        
        # 3. 路径模式匹配
        path_recommendations = []
        if self.config["use_path_patterns"]:
            try:
                context_dict = self._context_to_dict(context)
                path_matches = self.path_pattern.find_matching_paths(
                    context_dict, executed_tools, max_paths=5
                )
                path_recommendations = path_matches
            except Exception as e:
                # 路径匹配失败不影响主流程
                pass
        
        # 4. 强化学习优化
        rl_scores = {}
        if self.config["use_rl_optimization"]:
            try:
                available_tools = [rec.tool_name for rec in graph_recs]
                context_dict = self._context_to_dict(context)
                rl_selections = self.rl_optimizer.select_tools(
                    available_tools, context_dict, strategy="ucb", top_k=15
                )
                rl_scores = {tool: score for tool, score in rl_selections}
            except Exception as e:
                # RL优化失败不影响主流程
                pass
        
        # 5. 融合所有建议
        advisories = []
        for rec in graph_recs:
            # 基础分数来自GraphRAG
            base_score = rec.score
            reasons = rec.reasons.copy()
            
            # 指纹识别加成
            fingerprint_boost = 0.0
            if fingerprint_features:
                # 检查工具是否匹配指纹特征
                tool_name_lower = rec.tool_name.lower()
                for feature in fingerprint_features:
                    if any(keyword in tool_name_lower for keyword in feature.split('_')):
                        fingerprint_boost += 2.0
                        reasons.append(f"指纹特征匹配: {feature}")
            
            # 路径模式加成
            path_boost = 0.0
            for path_rec in path_recommendations:
                if rec.tool_name in path_rec.next_tools:
                    path_boost += path_rec.match_score * 3.0
                    reasons.append(f"路径模式匹配: {path_rec.path.name}")
                    break
            
            # 强化学习加成
            rl_boost = 0.0
            if rec.tool_name in rl_scores:
                rl_boost = rl_scores[rec.tool_name] * 2.0
                reasons.append(f"RL优化推荐: 置信度 {rl_scores[rec.tool_name]:.2f}")
            
            # 计算最终分数
            final_score = base_score + fingerprint_boost + path_boost + rl_boost
            
            advisory = ToolAdvisory(
                tool_name=rec.tool_name,
                advisory_score=final_score,
                reasons=reasons,
                confidence=self._calculate_confidence(final_score),
                source="Hybrid(GraphRAG+Fingerprint+PathPattern+RL)",
                category=rec.category,
                phase=rec.phase,
                historical_stats={
                    "priority": rec.priority,
                    "graphrag_score": base_score,
                    "fingerprint_boost": fingerprint_boost,
                    "path_boost": path_boost,
                    "rl_boost": rl_boost,
                },
                warnings=self._get_tool_warnings(rec.tool_name, context)
            )
            advisories.append(advisory)
        
        # 按置信度分组
        recommendations = {
            "high_confidence": [],
            "medium_confidence": [],
            "low_confidence": [],
            "exploratory": []
        }
        
        for advisory in advisories:
            if advisory.confidence >= 0.8:
                recommendations["high_confidence"].append(advisory)
            elif advisory.confidence >= 0.6:
                recommendations["medium_confidence"].append(advisory)
            elif advisory.confidence >= 0.4:
                recommendations["low_confidence"].append(advisory)
            else:
                recommendations["exploratory"].append(advisory)
        
        return recommendations
    
    def _extract_knowledge(
        self,
        context: WebPentestContext,
        html: Optional[str],
        headers: Optional[Dict]
    ) -> Dict[str, Any]:
        """提取知识库信息"""
        knowledge = {
            "penetration_testing_principles": [
                "Start with passive reconnaissance before active scanning",
                "Understand the target before exploitation",
                "Always check for WAF/IDS before aggressive testing",
                "Document all findings for reporting"
            ],
            
            "current_phase_guidance": self._get_phase_guidance(context.current_phase),
            
            "vulnerability_indicators": self._get_vulnerability_indicators(context),
            
            "tool_capabilities": self._get_tool_capabilities_summary(),
            
            "common_attack_vectors": self._get_common_attack_vectors(context),
        }
        
        return knowledge
    
    def _generate_warnings_and_alerts(
        self,
        context: WebPentestContext,
        html: Optional[str],
        headers: Optional[Dict]
    ) -> tuple[List[str], List[str]]:
        """生成警告和提示"""
        warnings = []
        alerts = []
        
        # WAF检测警告
        if context.waf_detected:
            warnings.append(
                f"⚠️ WAF detected: {context.waf_detected}. "
                "Aggressive scanning may trigger blocking."
            )
        
        # 缺少关键信息警告
        if not context.technology_stack:
            alerts.append(
                "ℹ️ Technology stack not identified yet. "
                "Consider using fingerprinting tools first."
            )
        
        # 阶段推进提示
        if context.current_phase == "discovery" and not context.discovered_urls:
            alerts.append(
                "ℹ️ No URLs discovered yet. "
                "Consider crawling or directory scanning."
            )
        
        if context.current_phase == "parameter_analysis" and not context.injectable_params:
            alerts.append(
                "ℹ️ No injectable parameters found yet. "
                "Consider parameter discovery tools."
            )
        
        return warnings, alerts
    
    def _find_historical_paths(
        self,
        context: WebPentestContext,
        executed_tools: List[str]
    ) -> List[Dict[str, Any]]:
        """查找历史成功路径（集成路径模式匹配）"""
        historical_paths = []
        
        # 使用路径模式匹配器
        if self.config["use_path_patterns"]:
            try:
                context_dict = self._context_to_dict(context)
                path_matches = self.path_pattern.find_matching_paths(
                    context_dict, executed_tools, max_paths=5
                )
                
                for path_rec in path_matches:
                    path_info = {
                        "name": path_rec.path.name,
                        "description": path_rec.path.description,
                        "path": path_rec.path.tools,
                        "success_rate": path_rec.estimated_success_rate,
                        "match_score": path_rec.match_score,
                        "reasons": path_rec.reasons,
                        "next_tools": path_rec.next_tools,
                        "difficulty": path_rec.path.difficulty,
                        "estimated_time": path_rec.path.estimated_time,
                        "tags": path_rec.path.tags
                    }
                    historical_paths.append(path_info)
            except Exception as e:
                # 路径匹配失败，使用默认路径
                pass
        
        # 如果没有找到路径，使用默认示例
        if not historical_paths:
            historical_paths = [
                {
                    "name": "Classic Web App Pentest",
                    "path": ["browser_visit_page", "gobuster_scan", "arjun_scan", "nuclei_scan"],
                    "success_rate": 0.75,
                    "note": "Common path for web application testing"
                },
                {
                    "name": "WordPress Exploitation",
                    "path": ["browser_visit_page", "wpscan_analyze", "wp_plugin_exploit"],
                    "success_rate": 0.68,
                    "note": "Effective for WordPress sites",
                    "condition": "cms_detected == 'WordPress'"
                }
            ]
        
        return historical_paths
    
    def _generate_context_hints(self, context: WebPentestContext) -> Dict[str, Any]:
        """生成上下文提示"""
        return {
            "missing_information": self._identify_missing_info(context),
            "next_phase_requirements": self._get_next_phase_requirements(context),
            "suggested_focus_areas": self._suggest_focus_areas(context),
        }
    
    def _calculate_confidence(self, score: float) -> float:
        """将分数转换为置信度"""
        # 简单的归一化
        return min(1.0, score / 100.0)
    
    def _get_tool_warnings(self, tool_name: str, context: WebPentestContext) -> List[str]:
        """获取工具相关警告"""
        warnings = []
        
        # 攻击性工具警告
        tool = self.graph_selector.graph.get_tool(tool_name)
        if tool and tool.is_aggressive:
            warnings.append("⚠️ This is an aggressive tool. Use with caution.")
        
        # WAF相关警告
        if context.waf_detected and tool_name in ["sqlmap_scan", "nuclei_scan"]:
            warnings.append(f"⚠️ May trigger {context.waf_detected} WAF")
        
        return warnings
    
    def _context_to_dict(self, context: WebPentestContext) -> Dict[str, Any]:
        """将Context转换为字典"""
        return {
            "target_url": context.target_url,
            "current_phase": context.current_phase,
            "technology_stack": context.technology_stack,
            "cms_detected": context.cms_detected,
            "has_login_page": context.has_login_page,
            "has_file_upload": context.has_file_upload,
            "has_search_function": context.has_search_function,
            "is_authenticated": context.is_authenticated,
        }
    
    def _get_phase_guidance(self, phase: str) -> Dict[str, Any]:
        """获取阶段指导"""
        guidance = {
            "recon": {
                "objective": "Gather information about the target",
                "key_activities": ["Port scanning", "Service enumeration", "Technology fingerprinting"],
                "success_criteria": "Identified open ports, services, and technology stack"
            },
            "discovery": {
                "objective": "Discover endpoints, directories, and entry points",
                "key_activities": ["Directory scanning", "Endpoint enumeration", "Form detection"],
                "success_criteria": "Found URLs, forms, and potential attack surfaces"
            },
            "parameter_analysis": {
                "objective": "Identify injectable parameters",
                "key_activities": ["Parameter discovery", "Input analysis", "Hidden parameter detection"],
                "success_criteria": "Identified parameters that accept user input"
            },
            "vulnerability_scan": {
                "objective": "Detect security vulnerabilities",
                "key_activities": ["SQL injection testing", "XSS testing", "Security misconfiguration checks"],
                "success_criteria": "Found potential vulnerabilities"
            },
            "exploitation": {
                "objective": "Exploit confirmed vulnerabilities",
                "key_activities": ["Vulnerability exploitation", "Privilege escalation", "Data extraction"],
                "success_criteria": "Successfully exploited vulnerability"
            },
        }
        
        return guidance.get(phase, {})
    
    def _get_vulnerability_indicators(self, context: WebPentestContext) -> List[Dict[str, Any]]:
        """获取漏洞指标"""
        indicators = []
        
        if context.has_login_page:
            indicators.append({
                "type": "SQL Injection",
                "reason": "Login forms are common SQL injection targets",
                "confidence": "medium"
            })
            indicators.append({
                "type": "Authentication Bypass",
                "reason": "Authentication mechanisms may have vulnerabilities",
                "confidence": "medium"
            })
        
        if context.has_search_function:
            indicators.append({
                "type": "XSS (Cross-Site Scripting)",
                "reason": "Search functions often reflect user input",
                "confidence": "high"
            })
        
        if context.has_file_upload:
            indicators.append({
                "type": "File Upload Vulnerability",
                "reason": "File upload functionality detected",
                "confidence": "high"
            })
        
        return indicators
    
    def _get_tool_capabilities_summary(self) -> Dict[str, str]:
        """获取工具能力摘要"""
        return {
            "sqlmap": "Automated SQL injection detection and exploitation",
            "nuclei": "Template-based vulnerability scanning for various CVEs",
            "gobuster": "Directory and file enumeration",
            "wpscan": "WordPress-specific security scanner",
            "nmap": "Network port scanning and service detection",
            "arjun": "HTTP parameter discovery",
            "dalfox": "Advanced XSS detection and exploitation",
        }
    
    def _get_common_attack_vectors(self, context: WebPentestContext) -> List[str]:
        """获取常见攻击向量"""
        vectors = []
        
        if "PHP" in context.technology_stack:
            vectors.extend(["Local File Inclusion (LFI)", "Remote Code Execution (RCE)"])
        
        if context.has_login_page:
            vectors.extend(["SQL Injection", "Brute Force", "Authentication Bypass"])
        
        if context.cms_detected == "WordPress":
            vectors.extend(["Plugin Vulnerabilities", "Theme Vulnerabilities", "XML-RPC Attacks"])
        
        return vectors
    
    def _identify_missing_info(self, context: WebPentestContext) -> List[str]:
        """识别缺失信息"""
        missing = []
        
        if not context.technology_stack:
            missing.append("Technology stack not identified")
        
        if not context.open_ports:
            missing.append("Open ports not scanned")
        
        if context.current_phase in ["parameter_analysis", "vulnerability_scan"] and not context.injectable_params:
            missing.append("No injectable parameters found")
        
        return missing
    
    def _get_next_phase_requirements(self, context: WebPentestContext) -> List[str]:
        """获取下一阶段要求"""
        requirements = {
            "recon": ["Identify at least 3 open ports or services"],
            "discovery": ["Find at least 5 URLs or endpoints"],
            "parameter_analysis": ["Identify at least 3 injectable parameters"],
            "vulnerability_scan": ["Detect at least 1 potential vulnerability"],
            "exploitation": ["Confirm vulnerability exploitability"],
        }
        
        return requirements.get(context.current_phase, [])
    
    def _suggest_focus_areas(self, context: WebPentestContext) -> List[str]:
        """建议关注领域"""
        focus = []
        
        if context.cms_detected:
            focus.append(f"Focus on {context.cms_detected}-specific vulnerabilities")
        
        if context.has_login_page and not context.is_authenticated:
            focus.append("Consider authentication testing")
        
        if len(context.injectable_params) > 0:
            focus.append("Test identified parameters for injection vulnerabilities")
        
        return focus


# 便捷函数
def provide_advisory(
    context: WebPentestContext,
    html: Optional[str] = None,
    headers: Optional[Dict] = None,
    executed_tools: Optional[List[str]] = None
) -> PentestAdvisory:
    """便捷函数：提供建议"""
    system = AdvisorySystem()
    return system.provide_advisory(context, html, headers, executed_tools)
