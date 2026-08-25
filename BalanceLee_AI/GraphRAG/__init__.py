"""
HexStrike GraphRAG - 基于知识图谱的智能工具选择系统

模块：
- graph_schema: 图谱数据结构定义
- tool_knowledge_graph: 完整的工具知识图谱（160+工具）
- tool_selector: 智能工具选择器

使用示例：
    from GraphRAG import select_tools_for_target, filter_openai_tools
    
    # 为目标选择工具
    recommendations = select_tools_for_target("http://example.com/sqli")
    
    # 过滤OpenAI格式工具列表
    filtered_tools = filter_openai_tools(all_tools, target_url)
"""

from .graph_schema import (
    ToolGraph,
    ToolNode,
    ToolEdge,
    ScenarioNode,
    TargetNode,
    PhaseNode,
    NodeType,
    RelationType,
    Phase,
    TargetType,
    Scenario,
)

from .tool_knowledge_graph import (
    build_hexstrike_tool_graph,
    build_default_hexstrike_tool_graph,
    get_tools_for_url,
)

from .tool_selector import (
    HexStrikeToolSelector,
    ScenarioAnalysis,
    ToolRecommendation,
    get_selector,
    select_tools_for_target,
    analyze_target,
    get_recommended_tool_names,
    filter_openai_tools,
    select_tools_with_phase_aware,
)

from .phase_aware import (
    InputType,
    PentestPhase,
    WebPentestContext,
    InputTypeDetector,
    PhaseTransitionRules,
    ContextUpdater,
    PhaseAwareToolSelector,
    PhaseToolRecommendation,
    get_phase_selector,
    create_pentest_context,
    select_phase_tools,
    get_phase_intent,
    extract_context_features,
    update_context,
    check_phase_transition,
    advance_phase,
    filter_tools_by_phase_recommendations,
    PHASE_INTENT_MAPPING,
    CONTEXT_TO_SCENARIO,
    PARAM_VULN_HINTS,
)

from .advisory_system import (
    AdvisorySystem,
    ToolAdvisory,
    PentestAdvisory,
    provide_advisory,
)

from .fingerprint_engine import (
    WebFingerprintExtractor,
    WebFingerprint,
    extract_web_fingerprint,
    fingerprint_to_features,
)

from .path_patterns import (
    PentestPathPattern,
    PentestPath,
    PathRecommendation,
    find_pentest_paths,
    get_next_tool_suggestions,
)

from .rl_optimizer import (
    ToolSelectionBandit,
    ToolPerformance,
    RewardCalculator,
    create_rl_optimizer,
    calculate_tool_reward,
)

__all__ = [
    # Schema
    'ToolGraph',
    'ToolNode',
    'ToolEdge',
    'ScenarioNode',
    'TargetNode',
    'PhaseNode',
    'NodeType',
    'RelationType',
    'Phase',
    'TargetType',
    'Scenario',
    
    # Knowledge Graph
    'build_hexstrike_tool_graph',
    'build_default_hexstrike_tool_graph',
    'get_tools_for_url',
    
    # Tool Selector
    'HexStrikeToolSelector',
    'ScenarioAnalysis',
    'ToolRecommendation',
    'get_selector',
    'select_tools_for_target',
    'analyze_target',
    'get_recommended_tool_names',
    'filter_openai_tools',
    'select_tools_with_phase_aware',
    
    # Phase Aware
    'InputType',
    'PentestPhase',
    'WebPentestContext',
    'InputTypeDetector',
    'PhaseTransitionRules',
    'ContextUpdater',
    'PhaseAwareToolSelector',
    'PhaseToolRecommendation',
    'get_phase_selector',
    'create_pentest_context',
    'select_phase_tools',
    'get_phase_intent',
    'extract_context_features',
    'update_context',
    'check_phase_transition',
    'advance_phase',
    'filter_tools_by_phase_recommendations',
    'PHASE_INTENT_MAPPING',
    'CONTEXT_TO_SCENARIO',
    'PARAM_VULN_HINTS',
    
    # Advisory System
    'AdvisorySystem',
    'ToolAdvisory',
    'PentestAdvisory',
    'provide_advisory',
    
    # Fingerprint Engine
    'WebFingerprintExtractor',
    'WebFingerprint',
    'extract_web_fingerprint',
    'fingerprint_to_features',
    
    # Path Patterns
    'PentestPathPattern',
    'PentestPath',
    'PathRecommendation',
    'find_pentest_paths',
    'get_next_tool_suggestions',
    
    # RL Optimizer
    'ToolSelectionBandit',
    'ToolPerformance',
    'RewardCalculator',
    'create_rl_optimizer',
    'calculate_tool_reward',
]

__version__ = '2.3.0'  # Updated with Advisory System
