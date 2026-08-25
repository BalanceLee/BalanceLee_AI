"""
HexStrike GraphRAG Tool Selector - 智能工具选择器

基于知识图谱的工具选择和推荐系统。
支持：
1. URL/目标分析 -> 场景识别
2. 场景 -> 工具推荐
3. 工具链推荐
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass

from .graph_schema import ToolGraph, ToolNode, Scenario, TargetType, Phase
from .tool_knowledge_graph import build_hexstrike_tool_graph


@dataclass
class ScenarioAnalysis:
    """场景分析结果"""
    scenarios: List[str]           # 识别到的场景
    targets: List[str]             # 识别到的目标类型
    phase: str                     # 当前阶段
    confidence: float              # 置信度
    keywords: Set[str]             # 匹配到的关键词
    reasoning: str                 # 推理说明


@dataclass
class ToolRecommendation:
    """工具推荐结果"""
    tool_name: str                 # 工具名称
    score: float                   # 推荐分数
    reasons: List[str]             # 推荐理由
    category: str                  # 工具类别
    phase: str                     # 所属阶段
    priority: int                  # 优先级


class HexStrikeToolSelector:
    """HexStrike智能工具选择器"""
    
    def __init__(self, graph: ToolGraph = None):
        """初始化工具选择器
        
        Args:
            graph: 工具知识图谱，如果为None则自动构建
        """
        self.graph = graph or build_hexstrike_tool_graph()
        
        # URL特征 -> 场景映射
        self.url_patterns = {
            # SQL注入特征
            r'sqli|sql|injection|id=|uid=|pid=|catid=': 'sql_injection',
            # XSS特征
            r'xss|script|alert|search=|q=|query=|keyword=': 'xss_attack',
            # LFI/RFI特征
            r'lfi|rfi|file=|path=|page=|include|\.\.\/': 'lfi_rfi',
            # 命令注入特征
            r'cmd|command|exec|ping|shell': 'command_injection',
            # 认证相关
            r'login|signin|auth|password|session|logout': 'auth_bypass',
            # API相关
            r'api|\/v\d+\/|rest|graphql|swagger|openapi': 'api_testing',
            # GraphQL
            r'graphql|\/graphql': 'graphql_attack',
            # WordPress
            r'wp-|wordpress|wp-admin|wp-content|wp-login': 'technology_detection',
            # 文件上传
            r'upload|file|attachment|image': 'file_upload',
            # SSRF
            r'url=|redirect|proxy|fetch|request': 'ssrf',
            # 目录遍历
            r'dir|directory|folder|path': 'directory_discovery',
        }
        
        # 目标类型识别模式
        self.target_patterns = {
            r'login|signin|auth': 'login_page',
            r'api|\/v\d+\/|rest': 'api_endpoint',
            r'graphql': 'graphql_api',
            r'wp-|wordpress': 'wordpress_site',
            r'smb|445|cifs|share': 'smb_share',
            r'dns|domain|nameserver': 'dns_server',
            r'\.exe|\.elf|binary': 'binary_executable',
            r'memory|dump|\.dmp|\.raw': 'memory_dump',
            r'aws|azure|gcp|cloud|s3|ec2': 'cloud_service',
            r'docker|container|image': 'container',
            r'k8s|kubernetes|pod|cluster': 'kubernetes',
        }
    
    def analyze_input(self, user_input: str, context: Dict[str, Any] = None) -> ScenarioAnalysis:
        """分析用户输入，识别场景和目标
        
        Args:
            user_input: 用户输入（URL、描述等）
            context: 额外上下文信息
            
        Returns:
            场景分析结果
        """
        input_lower = user_input.lower()
        context = context or {}
        
        scenarios = []
        targets = []
        keywords = set()
        reasoning_parts = []
        
        # 1. URL模式匹配
        for pattern, scenario in self.url_patterns.items():
            if re.search(pattern, input_lower):
                if scenario not in scenarios:
                    scenarios.append(scenario)
                    keywords.update(re.findall(pattern, input_lower))
                    reasoning_parts.append(f"URL匹配到{scenario}特征")
        
        # 2. 目标类型识别
        for pattern, target in self.target_patterns.items():
            if re.search(pattern, input_lower):
                if target not in targets:
                    targets.append(target)
                    reasoning_parts.append(f"识别到目标类型: {target}")
        
        # 3. 默认处理
        if input_lower.startswith(('http://', 'https://')):
            if 'web_application' not in targets:
                targets.append('web_application')
            if not scenarios:
                # 默认进行漏洞评估
                scenarios.append('vulnerability_assessment')
                reasoning_parts.append("默认进行Web漏洞评估")
        
        # 4. IP地址识别
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, user_input):
            if 'network_host' not in targets:
                targets.append('network_host')
            if not scenarios:
                scenarios.append('port_scan')
                reasoning_parts.append("识别到IP地址，建议端口扫描")
        
        # 5. 域名识别
        domain_pattern = r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}'
        if re.search(domain_pattern, user_input) and not input_lower.startswith('http'):
            if 'dns_server' not in targets:
                targets.append('dns_server')
            if 'subdomain_enum' not in scenarios:
                scenarios.append('subdomain_enum')
                reasoning_parts.append("识别到域名，建议子域名枚举")
        
        # 6. 上下文增强
        if context.get('is_login_page'):
            if 'auth_bypass' not in scenarios:
                scenarios.append('auth_bypass')
            if 'login_page' not in targets:
                targets.append('login_page')
        
        if context.get('has_params'):
            if 'parameter_discovery' not in scenarios:
                scenarios.append('parameter_discovery')
        
        if context.get('technology'):
            tech = context['technology'].lower()
            if 'wordpress' in tech and 'wordpress_site' not in targets:
                targets.append('wordpress_site')
        
        # 7. 确定当前阶段
        phase = self._determine_phase(scenarios, context)
        
        # 8. 计算置信度
        confidence = min(1.0, len(scenarios) * 0.3 + len(targets) * 0.2 + 0.3)
        
        reasoning = "; ".join(reasoning_parts) if reasoning_parts else "基于默认规则分析"
        
        return ScenarioAnalysis(
            scenarios=scenarios,
            targets=targets,
            phase=phase,
            confidence=confidence,
            keywords=keywords,
            reasoning=reasoning
        )
    
    def _determine_phase(self, scenarios: List[str], context: Dict[str, Any]) -> str:
        """确定当前渗透阶段"""
        # 根据场景推断阶段
        exploitation_scenarios = {'sql_injection', 'xss_attack', 'command_injection', 
                                 'binary_exploitation', 'auth_bypass', 'brute_force'}
        vuln_scan_scenarios = {'vulnerability_assessment', 'api_testing', 'graphql_attack'}
        discovery_scenarios = {'directory_discovery', 'parameter_discovery', 'endpoint_discovery'}
        recon_scenarios = {'port_scan', 'subdomain_enum', 'osint', 'technology_detection'}
        
        for scenario in scenarios:
            if scenario in exploitation_scenarios:
                return 'exploitation'
            if scenario in vuln_scan_scenarios:
                return 'vuln_scan'
            if scenario in discovery_scenarios:
                return 'discovery'
            if scenario in recon_scenarios:
                return 'recon'
        
        # 根据上下文
        if context.get('has_vulnerability'):
            return 'exploitation'
        if context.get('has_endpoints'):
            return 'vuln_scan'
        
        return 'discovery'  # 默认发现阶段
    
    def select_tools(self, user_input: str, context: Dict[str, Any] = None,
                    max_tools: int = 30) -> List[ToolRecommendation]:
        """选择推荐工具
        
        Args:
            user_input: 用户输入
            context: 上下文信息
            max_tools: 最大返回工具数
            
        Returns:
            工具推荐列表
        """
        # 1. 分析输入
        analysis = self.analyze_input(user_input, context)
        
        # 2. 收集候选工具及其得分
        tool_scores: Dict[str, Tuple[float, List[str]]] = {}
        
        # 场景匹配（权重最高）
        for scenario in analysis.scenarios:
            tools = self.graph.get_tools_for_scenario(scenario)
            for tool in tools:
                score, reasons = tool_scores.get(tool.name, (0, []))
                score += 3.0 * tool.priority / 10
                reasons.append(f"适用于{scenario}场景")
                tool_scores[tool.name] = (score, reasons)
        
        # 目标类型匹配
        for target in analysis.targets:
            tools = self.graph.get_tools_for_target(target)
            for tool in tools:
                score, reasons = tool_scores.get(tool.name, (0, []))
                score += 2.0 * tool.priority / 10
                reasons.append(f"针对{target}目标")
                tool_scores[tool.name] = (score, reasons)
        
        # 阶段匹配
        phase_tools = self.graph.get_tools_for_phase(analysis.phase)
        for tool in phase_tools:
            score, reasons = tool_scores.get(tool.name, (0, []))
            score += 1.0 * tool.priority / 10
            reasons.append(f"属于{analysis.phase}阶段")
            tool_scores[tool.name] = (score, reasons)
        
        # 关键词匹配
        for tool_name, tool in self.graph.tool_nodes.items():
            if tool.tags & analysis.keywords:
                score, reasons = tool_scores.get(tool_name, (0, []))
                match_count = len(tool.tags & analysis.keywords)
                score += 0.5 * match_count
                reasons.append(f"标签匹配: {tool.tags & analysis.keywords}")
                tool_scores[tool_name] = (score, reasons)
        
        # 3. 排序并生成推荐
        sorted_tools = sorted(tool_scores.items(), key=lambda x: -x[1][0])
        
        recommendations = []
        for tool_name, (score, reasons) in sorted_tools[:max_tools]:
            tool = self.graph.get_tool(tool_name)
            if tool:
                recommendations.append(ToolRecommendation(
                    tool_name=tool_name,
                    score=score,
                    reasons=reasons,
                    category=tool.category,
                    phase=tool.phase,
                    priority=tool.priority
                ))
        
        return recommendations
    
    def get_tool_chain(self, start_tool: str, max_depth: int = 3) -> List[List[str]]:
        """获取工具执行链
        
        Args:
            start_tool: 起始工具
            max_depth: 最大深度
            
        Returns:
            工具链列表
        """
        chains = []
        
        def dfs(current: str, chain: List[str], depth: int):
            if depth >= max_depth:
                if len(chain) > 1:
                    chains.append(chain.copy())
                return
            
            following = self.graph.get_following_tools(current)
            if not following:
                if len(chain) > 1:
                    chains.append(chain.copy())
                return
            
            for next_tool in following[:3]:  # 限制分支
                chain.append(next_tool.name)
                dfs(next_tool.name, chain, depth + 1)
                chain.pop()
        
        dfs(start_tool, [start_tool], 0)
        return chains
    
    def get_alternative_tools(self, tool_name: str) -> List[ToolNode]:
        """获取替代工具
        
        Args:
            tool_name: 工具名称
            
        Returns:
            替代工具列表
        """
        return self.graph.get_alternative_tools(tool_name)
    
    def filter_tools_by_openai_format(self, tools: List[Dict[str, Any]], 
                                      recommendations: List[ToolRecommendation]) -> List[Dict[str, Any]]:
        """根据推荐结果过滤OpenAI格式的工具列表
        
        Args:
            tools: OpenAI格式的工具列表
            recommendations: 推荐结果
            
        Returns:
            过滤后的工具列表
        """
        recommended_names = {r.tool_name for r in recommendations}
        
        filtered = []
        for tool in tools:
            func = tool.get('function', {})
            name = func.get('name', '')
            if name in recommended_names:
                filtered.append(tool)
        
        # 按推荐分数排序
        name_to_score = {r.tool_name: r.score for r in recommendations}
        filtered.sort(key=lambda t: -name_to_score.get(t.get('function', {}).get('name', ''), 0))
        
        return filtered
    
    def select_tools_with_phase_intent(
        self, 
        user_input: str, 
        phase_intent: Dict[str, Any],
        context_features: List[str] = None,
        context: Dict[str, Any] = None,
        max_tools: int = 30
    ) -> List[ToolRecommendation]:
        """结合 Phase-Aware 的阶段意图选择工具
        
        这是 GraphRAG 与 Phase-Aware 协作的核心方法。
        Phase-Aware 提供阶段意图和上下文特征，GraphRAG 负责精准匹配工具。
        
        Args:
            user_input: 用户输入（目标URL等）
            phase_intent: Phase-Aware 输出的阶段意图
            context_features: 上下文特征列表（如 has_login_form, has_post_params 等）
            context: 额外上下文信息
            max_tools: 最大返回工具数
            
        Returns:
            工具推荐列表
        """
        context = context or {}
        context_features = context_features or []
        
        # 1. 从阶段意图获取允许的场景
        allowed_scenarios = set(phase_intent.get("scenarios", []))
        current_phase = phase_intent.get("phase", "discovery")
        
        # 2. 上下文特征 → 场景映射
        from .phase_aware import CONTEXT_TO_SCENARIO, InputType
        for feature in context_features:
            feature_scenarios = CONTEXT_TO_SCENARIO.get(feature, [])
            allowed_scenarios.update(feature_scenarios)
        
        # 3. 收集候选工具及其得分
        tool_scores: Dict[str, Tuple[float, List[str]]] = {}
        
        # ============================================================
        # 【关键改进】根据阶段和输入类型，优先推荐核心工具
        # ============================================================
        
        # 3.0 阶段核心工具（最高优先级）
        PHASE_PRIORITY_TOOLS = {
            "discovery": {
                # Discovery 阶段：先访问页面，再扫目录
                "first_priority": [
                    ("browser_visit_page", 15.0, "Discovery首选：先访问页面查看结构"),
                    ("browser_visit", 15.0, "Discovery首选：先访问页面查看结构"),
                ],
                "second_priority": [
                    ("crawl_site_endpoints", 10.0, "爬取站点端点"),
                    ("view_source_code", 8.0, "查看源码"),
                ],
                "third_priority": [
                    ("gobuster_scan", 5.0, "目录扫描"),
                    ("dirb_scan", 5.0, "目录扫描"),
                    ("ffuf_scan", 5.0, "目录扫描"),
                ]
            },
            "vulnerability_scan": {
                "first_priority": [
                    ("sqlmap_scan", 15.0, "SQL注入检测首选"),
                    ("intelligent_quick_test", 12.0, "智能快速测试"),
                ],
                "second_priority": [
                    ("nuclei_scan", 10.0, "通用漏洞扫描"),
                    ("nikto_scan", 8.0, "Web漏洞扫描"),
                ],
            },
            "parameter_analysis": {
                "first_priority": [
                    ("discover_injectable_params", 12.0, "参数发现"),
                    ("arjun_scan", 10.0, "参数发现"),
                ],
            },
            "exploitation": {
                "first_priority": [
                    ("sqlmap_scan", 15.0, "SQL注入利用"),
                    ("commix_scan", 12.0, "命令注入利用"),
                ],
            },
        }
        
        # 应用阶段优先级工具
        phase_priority = PHASE_PRIORITY_TOOLS.get(current_phase, {})
        for priority_level in ["first_priority", "second_priority", "third_priority"]:
            tools_config = phase_priority.get(priority_level, [])
            for tool_name, base_score, reason in tools_config:
                score, reasons = tool_scores.get(tool_name, (0, []))
                score += base_score
                reasons.append(reason)
                tool_scores[tool_name] = (score, reasons)
        
        # 3.1 场景匹配
        for scenario in allowed_scenarios:
            tools = self.graph.get_tools_for_scenario(scenario)
            for tool in tools:
                score, reasons = tool_scores.get(tool.name, (0, []))
                score += 4.0 * tool.priority / 10
                reasons.append(f"场景匹配: {scenario}")
                tool_scores[tool.name] = (score, reasons)
        
        # 3.2 上下文特征直接匹配工具
        FEATURE_TOOL_BOOST = {
            "has_login_form": [
                ("sqlmap_scan", 12.0), ("hydra_scan", 8.0), 
                ("smart_login_attempt", 10.0), ("burp_intruder", 6.0)
            ],
            "has_post_params": [
                ("sqlmap_scan", 12.0), ("xss_scanner", 8.0), ("burp_repeater", 6.0)
            ],
            "has_get_params": [
                ("sqlmap_scan", 10.0), ("xss_scanner", 8.0), 
                ("lfi_scanner", 6.0), ("param_miner", 5.0)
            ],
            "has_forms": [
                ("sqlmap_scan", 10.0), ("xss_scanner", 8.0), ("form_analyzer", 6.0)
            ],
            "has_file_upload": [
                ("upload_scanner", 10.0), ("webshell_upload", 8.0), ("file_upload_test", 6.0)
            ],
            "has_search_box": [
                ("xss_scanner", 10.0), ("sqli_scanner", 8.0), ("ssti_scanner", 6.0)
            ],
            "has_id_param": [
                ("sqlmap_scan", 12.0), ("idor_scanner", 8.0), ("bola_test", 6.0)
            ],
            "has_file_param": [
                ("lfi_scanner", 10.0), ("rfi_scanner", 8.0), ("path_traversal_test", 6.0)
            ],
            "has_url_param": [
                ("ssrf_scanner", 10.0), ("redirect_scanner", 8.0), ("url_redirect_test", 6.0)
            ],
            "has_cmd_param": [
                ("commix_scan", 12.0), ("rce_scanner", 10.0), ("command_injection_test", 8.0)
            ],
            "cms_wordpress": [("wpscan", 12.0), ("wp_vuln_scanner", 8.0)],
            "cms_drupal": [("droopescan", 10.0), ("drupal_scanner", 8.0)],
            "cms_joomla": [("joomscan", 10.0), ("joomla_scanner", 8.0)],
            "php_backend": [("lfi_scanner", 8.0), ("rce_scanner", 6.0), ("php_vuln_test", 5.0)],
            "java_backend": [("deserialization_scanner", 8.0), ("log4j_scanner", 10.0)],
            "is_api": [("api_scanner", 10.0), ("jwt_scanner", 8.0), ("graphql_scanner", 6.0)],
            "has_sensitive_files": [("git_dumper", 10.0), ("backup_scanner", 8.0)],
            "is_authenticated": [("idor_scanner", 10.0), ("privilege_test", 8.0)],
        }
        
        for feature in context_features:
            boost_tools = FEATURE_TOOL_BOOST.get(feature, [])
            for tool_name, boost_score in boost_tools:
                score, reasons = tool_scores.get(tool_name, (0, []))
                score += boost_score
                reasons.append(f"上下文特征: {feature}")
                tool_scores[tool_name] = (score, reasons)
        
        # 3.3 阶段匹配
        phase_tools = self.graph.get_tools_for_phase(current_phase)
        for tool in phase_tools:
            score, reasons = tool_scores.get(tool.name, (0, []))
            score += 1.5 * tool.priority / 10
            reasons.append(f"阶段匹配: {current_phase}")
            tool_scores[tool.name] = (score, reasons)
        
        # 3.4 URL特征匹配（原有逻辑）
        analysis = self.analyze_input(user_input, context)
        for scenario in analysis.scenarios:
            if scenario in allowed_scenarios:  # 只考虑允许的场景
                tools = self.graph.get_tools_for_scenario(scenario)
                for tool in tools:
                    score, reasons = tool_scores.get(tool.name, (0, []))
                    score += 2.0 * tool.priority / 10
                    reasons.append(f"URL特征: {scenario}")
                    tool_scores[tool.name] = (score, reasons)
        
        # 3.5 关键词匹配
        for tool_name, tool in self.graph.tool_nodes.items():
            if tool.tags & analysis.keywords:
                score, reasons = tool_scores.get(tool_name, (0, []))
                match_count = len(tool.tags & analysis.keywords)
                score += 0.5 * match_count
                reasons.append(f"关键词匹配: {tool.tags & analysis.keywords}")
                tool_scores[tool_name] = (score, reasons)
        
        # 4. 排序并生成推荐
        sorted_tools = sorted(tool_scores.items(), key=lambda x: -x[1][0])
        
        recommendations = []
        for tool_name, (score, reasons) in sorted_tools[:max_tools]:
            tool = self.graph.get_tool(tool_name)
            if tool:
                recommendations.append(ToolRecommendation(
                    tool_name=tool_name,
                    score=score,
                    reasons=reasons,
                    category=tool.category,
                    phase=tool.phase,
                    priority=tool.priority
                ))
            else:
                # 工具不在图谱中，但被上下文特征推荐
                recommendations.append(ToolRecommendation(
                    tool_name=tool_name,
                    score=score,
                    reasons=reasons,
                    category="unknown",
                    phase=current_phase,
                    priority=5
                ))
        
        return recommendations


# ============================================================================
# 便捷函数
# ============================================================================

_global_selector: Optional[HexStrikeToolSelector] = None


def get_selector() -> HexStrikeToolSelector:
    """获取全局工具选择器实例"""
    global _global_selector
    if _global_selector is None:
        _global_selector = HexStrikeToolSelector()
    return _global_selector


def select_tools_for_target(target: str, context: Dict[str, Any] = None,
                           max_tools: int = 30) -> List[ToolRecommendation]:
    """为目标选择工具的便捷函数
    
    Args:
        target: 目标URL或描述
        context: 上下文信息
        max_tools: 最大工具数
        
    Returns:
        工具推荐列表
    """
    selector = get_selector()
    return selector.select_tools(target, context, max_tools)


def analyze_target(target: str, context: Dict[str, Any] = None) -> ScenarioAnalysis:
    """分析目标的便捷函数
    
    Args:
        target: 目标URL或描述
        context: 上下文信息
        
    Returns:
        场景分析结果
    """
    selector = get_selector()
    return selector.analyze_input(target, context)


def get_recommended_tool_names(target: str, context: Dict[str, Any] = None,
                              max_tools: int = 30) -> List[str]:
    """获取推荐工具名称列表
    
    Args:
        target: 目标
        context: 上下文
        max_tools: 最大数量
        
    Returns:
        工具名称列表
    """
    recommendations = select_tools_for_target(target, context, max_tools)
    return [r.tool_name for r in recommendations]


def filter_openai_tools(tools: List[Dict[str, Any]], target: str,
                       context: Dict[str, Any] = None,
                       max_tools: int = 30) -> List[Dict[str, Any]]:
    """过滤OpenAI格式工具列表
    
    Args:
        tools: OpenAI格式工具列表
        target: 目标
        context: 上下文
        max_tools: 最大数量
        
    Returns:
        过滤后的工具列表
    """
    selector = get_selector()
    recommendations = selector.select_tools(target, context, max_tools)
    return selector.filter_tools_by_openai_format(tools, recommendations)


def select_tools_with_phase_aware(
    tools: List[Dict[str, Any]],
    target: str,
    phase_intent: Dict[str, Any],
    context_features: List[str] = None,
    context: Dict[str, Any] = None,
    max_tools: int = 30
) -> List[Dict[str, Any]]:
    """结合 Phase-Aware 选择并过滤工具（便捷函数）
    
    这是 GraphRAG + Phase-Aware 协作的主入口。
    
    Args:
        tools: OpenAI格式的全量工具列表
        target: 目标URL
        phase_intent: Phase-Aware 输出的阶段意图
        context_features: 上下文特征列表
        context: 额外上下文
        max_tools: 最大工具数
        
    Returns:
        过滤后的OpenAI格式工具列表
    """
    selector = get_selector()
    recommendations = selector.select_tools_with_phase_intent(
        target, phase_intent, context_features, context, max_tools
    )
    return selector.filter_tools_by_openai_format(tools, recommendations)
