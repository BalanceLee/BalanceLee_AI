"""
HexStrike GraphRAG Schema - 完整的工具知识图谱数据结构

支持节点类型：
- Tool: 安全工具节点
- Scenario: 攻击场景节点
- Target: 目标类型节点
- Phase: 渗透阶段节点

支持边关系：
- SUITABLE_FOR: 工具适用于场景
- TARGETS: 工具针对目标类型
- BELONGS_TO: 工具属于阶段
- FOLLOWS: 工具执行顺序
- ALTERNATIVE_TO: 工具可替代
- REQUIRES: 场景需要阶段
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from enum import Enum


class NodeType(Enum):
    """节点类型枚举"""
    TOOL = "tool"
    SCENARIO = "scenario"
    TARGET = "target"
    PHASE = "phase"


class RelationType(Enum):
    """关系类型枚举"""
    SUITABLE_FOR = "suitable_for"      # 工具适用于场景
    TARGETS = "targets"                 # 工具针对目标类型
    BELONGS_TO = "belongs_to"           # 工具属于阶段
    FOLLOWS = "follows"                 # 工具执行顺序（A执行后执行B）
    ALTERNATIVE_TO = "alternative_to"   # 工具可替代
    REQUIRES = "requires"               # 场景需要阶段
    PRECEDES = "precedes"               # 场景前置关系


class Phase(Enum):
    """渗透测试阶段"""
    RECON = "recon"                     # 侦察阶段
    DISCOVERY = "discovery"             # 发现阶段
    VULN_SCAN = "vuln_scan"             # 漏洞扫描
    EXPLOITATION = "exploitation"       # 利用阶段
    POST_EXPLOIT = "post_exploit"       # 后渗透
    REPORTING = "reporting"             # 报告阶段


class TargetType(Enum):
    """目标类型"""
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    NETWORK_HOST = "network_host"
    DATABASE = "database"
    CLOUD_SERVICE = "cloud_service"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    BINARY_EXECUTABLE = "binary_executable"
    MEMORY_DUMP = "memory_dump"
    SMB_SHARE = "smb_share"
    DNS_SERVER = "dns_server"
    WORDPRESS_SITE = "wordpress_site"
    LOGIN_PAGE = "login_page"
    FILE_SYSTEM = "file_system"
    GRAPHQL_API = "graphql_api"
    JWT_TOKEN = "jwt_token"


class Scenario(Enum):
    """攻击场景"""
    # Web漏洞场景
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    LFI_RFI = "lfi_rfi"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    OPEN_REDIRECT = "open_redirect"
    FILE_UPLOAD = "file_upload"
    PATH_TRAVERSAL = "path_traversal"
    
    # 认证场景
    AUTH_BYPASS = "auth_bypass"
    BRUTE_FORCE = "brute_force"
    SESSION_HIJACK = "session_hijack"
    JWT_ATTACK = "jwt_attack"
    PASSWORD_CRACK = "password_crack"
    
    # 网络场景
    PORT_SCAN = "port_scan"
    SERVICE_ENUM = "service_enum"
    SMB_ATTACK = "smb_attack"
    DNS_ENUM = "dns_enum"
    NETWORK_RECON = "network_recon"
    
    # 发现场景
    SUBDOMAIN_ENUM = "subdomain_enum"
    DIRECTORY_DISCOVERY = "directory_discovery"
    PARAMETER_DISCOVERY = "parameter_discovery"
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    TECHNOLOGY_DETECTION = "technology_detection"
    
    # 云/容器场景
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"
    CONTAINER_ESCAPE = "container_escape"
    K8S_ATTACK = "k8s_attack"
    IAC_SECURITY = "iac_security"
    
    # 二进制/逆向场景
    BINARY_EXPLOITATION = "binary_exploitation"
    MEMORY_FORENSICS = "memory_forensics"
    REVERSE_ENGINEERING = "reverse_engineering"
    ROP_CHAIN = "rop_chain"
    
    # API场景
    API_TESTING = "api_testing"
    GRAPHQL_ATTACK = "graphql_attack"
    
    # 综合场景
    BUG_BOUNTY = "bug_bounty"
    CTF_CHALLENGE = "ctf_challenge"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    OSINT = "osint"
    WAF_BYPASS = "waf_bypass"


@dataclass
class ToolNode:
    """工具节点"""
    name: str                                    # 工具名称（函数名）
    category: str                                # 工具类别
    phase: str                                   # 所属阶段
    description: str                             # 工具描述
    target_types: Set[str] = field(default_factory=set)  # 适用目标类型
    scenarios: Set[str] = field(default_factory=set)     # 适用场景
    tags: Set[str] = field(default_factory=set)          # 标签
    priority: int = 5                            # 优先级 1-10，越高越优先
    requires_auth: bool = False                  # 是否需要认证
    is_aggressive: bool = False                  # 是否为攻击性工具
    execution_time: str = "medium"               # 执行时间: fast/medium/slow


@dataclass
class ScenarioNode:
    """场景节点"""
    name: str                                    # 场景名称
    description: str                             # 场景描述
    keywords: Set[str] = field(default_factory=set)      # 关键词（用于匹配）
    required_phases: List[str] = field(default_factory=list)  # 需要的阶段
    risk_level: str = "medium"                   # 风险等级: low/medium/high/critical


@dataclass
class TargetNode:
    """目标类型节点"""
    name: str                                    # 目标类型名称
    description: str                             # 描述
    indicators: Set[str] = field(default_factory=set)    # 识别指标


@dataclass
class PhaseNode:
    """阶段节点"""
    name: str                                    # 阶段名称
    order: int                                   # 执行顺序
    description: str                             # 描述


@dataclass
class ToolEdge:
    """边关系"""
    source: str                                  # 源节点
    target: str                                  # 目标节点
    relation: str                                # 关系类型
    weight: float = 1.0                          # 权重（用于排序）
    metadata: Dict = field(default_factory=dict) # 额外元数据


class ToolGraph:
    """工具知识图谱"""
    
    def __init__(self) -> None:
        self.tool_nodes: Dict[str, ToolNode] = {}
        self.scenario_nodes: Dict[str, ScenarioNode] = {}
        self.target_nodes: Dict[str, TargetNode] = {}
        self.phase_nodes: Dict[str, PhaseNode] = {}
        self.edges: List[ToolEdge] = []
        self._adjacency: Dict[str, List[ToolEdge]] = {}
        self._reverse_adjacency: Dict[str, List[ToolEdge]] = {}

    def add_tool(self, node: ToolNode) -> None:
        """添加工具节点"""
        self.tool_nodes[node.name] = node

    def add_scenario(self, node: ScenarioNode) -> None:
        """添加场景节点"""
        self.scenario_nodes[node.name] = node

    def add_target(self, node: TargetNode) -> None:
        """添加目标类型节点"""
        self.target_nodes[node.name] = node

    def add_phase(self, node: PhaseNode) -> None:
        """添加阶段节点"""
        self.phase_nodes[node.name] = node

    def add_edge(self, edge: ToolEdge) -> None:
        """添加边"""
        self.edges.append(edge)
        self._adjacency.setdefault(edge.source, []).append(edge)
        self._reverse_adjacency.setdefault(edge.target, []).append(edge)

    def get_tool(self, name: str) -> Optional[ToolNode]:
        """获取工具节点"""
        return self.tool_nodes.get(name)

    def get_scenario(self, name: str) -> Optional[ScenarioNode]:
        """获取场景节点"""
        return self.scenario_nodes.get(name)

    def get_tools_for_scenario(self, scenario: str) -> List[ToolNode]:
        """获取适用于某场景的所有工具"""
        tools = []
        for edge in self._reverse_adjacency.get(scenario, []):
            if edge.relation == RelationType.SUITABLE_FOR.value:
                tool = self.get_tool(edge.source)
                if tool:
                    tools.append((tool, edge.weight))
        # 按权重和优先级排序
        tools.sort(key=lambda x: (-x[1], -x[0].priority))
        return [t[0] for t in tools]

    def get_tools_for_target(self, target: str) -> List[ToolNode]:
        """获取适用于某目标类型的所有工具"""
        tools = []
        for edge in self._reverse_adjacency.get(target, []):
            if edge.relation == RelationType.TARGETS.value:
                tool = self.get_tool(edge.source)
                if tool:
                    tools.append((tool, edge.weight))
        tools.sort(key=lambda x: (-x[1], -x[0].priority))
        return [t[0] for t in tools]

    def get_tools_for_phase(self, phase: str) -> List[ToolNode]:
        """获取属于某阶段的所有工具"""
        tools = []
        for edge in self._reverse_adjacency.get(phase, []):
            if edge.relation == RelationType.BELONGS_TO.value:
                tool = self.get_tool(edge.source)
                if tool:
                    tools.append(tool)
        tools.sort(key=lambda x: -x.priority)
        return tools

    def get_following_tools(self, tool_name: str) -> List[ToolNode]:
        """获取某工具之后应该执行的工具"""
        tools = []
        for edge in self._adjacency.get(tool_name, []):
            if edge.relation == RelationType.FOLLOWS.value:
                tool = self.get_tool(edge.target)
                if tool:
                    tools.append((tool, edge.weight))
        tools.sort(key=lambda x: -x[1])
        return [t[0] for t in tools]

    def get_alternative_tools(self, tool_name: str) -> List[ToolNode]:
        """获取某工具的替代工具"""
        tools = []
        for edge in self._adjacency.get(tool_name, []):
            if edge.relation == RelationType.ALTERNATIVE_TO.value:
                tool = self.get_tool(edge.target)
                if tool:
                    tools.append(tool)
        return tools

    def query_tools(self, scenario: str = None, target: str = None, 
                   phase: str = None, tags: Set[str] = None,
                   max_results: int = 30) -> List[ToolNode]:
        """综合查询工具
        
        Args:
            scenario: 场景名称
            target: 目标类型
            phase: 阶段
            tags: 标签集合
            max_results: 最大返回数量
            
        Returns:
            排序后的工具列表
        """
        # 收集候选工具及其得分
        tool_scores: Dict[str, float] = {}
        
        # 场景匹配
        if scenario:
            for tool in self.get_tools_for_scenario(scenario):
                tool_scores[tool.name] = tool_scores.get(tool.name, 0) + 3.0
        
        # 目标类型匹配
        if target:
            for tool in self.get_tools_for_target(target):
                tool_scores[tool.name] = tool_scores.get(tool.name, 0) + 2.0
        
        # 阶段匹配
        if phase:
            for tool in self.get_tools_for_phase(phase):
                tool_scores[tool.name] = tool_scores.get(tool.name, 0) + 1.0
        
        # 标签匹配
        if tags:
            for tool_name, tool in self.tool_nodes.items():
                if tool.tags & tags:
                    match_count = len(tool.tags & tags)
                    tool_scores[tool_name] = tool_scores.get(tool_name, 0) + match_count * 0.5
        
        # 如果没有任何匹配条件，返回所有工具
        if not tool_scores:
            all_tools = list(self.tool_nodes.values())
            all_tools.sort(key=lambda x: -x.priority)
            return all_tools[:max_results]
        
        # 按得分排序
        sorted_tools = sorted(tool_scores.items(), key=lambda x: -x[1])
        
        result = []
        for tool_name, score in sorted_tools[:max_results]:
            tool = self.get_tool(tool_name)
            if tool:
                result.append(tool)
        
        return result

    def all_tools(self) -> List[ToolNode]:
        """获取所有工具"""
        return list(self.tool_nodes.values())

    def all_scenarios(self) -> List[ScenarioNode]:
        """获取所有场景"""
        return list(self.scenario_nodes.values())

    def all_edges(self) -> List[ToolEdge]:
        """获取所有边"""
        return list(self.edges)

    def stats(self) -> Dict:
        """获取图谱统计信息"""
        return {
            "total_tools": len(self.tool_nodes),
            "total_scenarios": len(self.scenario_nodes),
            "total_targets": len(self.target_nodes),
            "total_phases": len(self.phase_nodes),
            "total_edges": len(self.edges)
        }
