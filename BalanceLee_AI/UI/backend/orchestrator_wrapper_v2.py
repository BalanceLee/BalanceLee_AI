#!/usr/bin/env python3
"""
Orchestrator Wrapper V2 - 直接调用 orchestrator_demo.py
通过猴子补丁（Monkey Patch）注入 WebSocket 推送
"""

import sys
import os
import time
from pathlib import Path
from typing import Dict, Any

# 添加父目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))


class OrchestratorWrapper:
    """包装器：通过猴子补丁注入 WebSocket 推送到 orchestrator_demo"""
    
    def __init__(self, socketio, session_id: str):
        self.socketio = socketio
        self.session_id = session_id
        self.should_stop_flag = False
        self.user_choice_value = None
        self.waiting_for_user_flag = False
        
        # 配置状态（每个会话独立）
        self.config = {
            'enable_graphrag': True,  # 默认启用
            'enable_phase_aware': True,  # 默认启用
            'max_rounds': 50,
            'timeout': 300
        }
        
        # 【新增】对话记忆（OpenAI格式）
        from user_server.orchestrator_demo import HEXSTRIKE_SYSTEM_PROMPT
        self.messages = [
            {"role": "system", "content": HEXSTRIKE_SYSTEM_PROMPT}
        ]
        self.max_history_length = 20  # 保留最近20轮对话（40条消息）

        # Versioned runtime path. Legacy events remain enabled through the adapter.
        from user_server.runtime import EventBus, JsonlEventStore
        from user_server.runtime.legacy import LegacySocketAdapter
        runtime_root = Path(os.environ.get(
            "HEXSTRIKE_RUNTIME_DIR",
            str(Path(__file__).resolve().parents[2] / "runtime"),
        ))
        self.event_store = JsonlEventStore(runtime_root / "events")
        self.event_bus = EventBus(self.event_store)
        self.legacy_event_adapter = LegacySocketAdapter(self.socketio)
        self.event_bus.subscribe(self.legacy_event_adapter.emit)
        
    def emit(self, event: str, data: Dict[str, Any]):
        """推送事件到前端"""
        self.socketio.emit(event, data, room=self.session_id)
        
    def stop(self):
        """停止测试"""
        self.should_stop_flag = True
    
    def clear_chat_history(self):
        """清空对话历史"""
        from user_server.orchestrator_demo import HEXSTRIKE_SYSTEM_PROMPT
        self.messages = [
            {"role": "system", "content": HEXSTRIKE_SYSTEM_PROMPT}
        ]
        
    def handle_user_choice(self, choice: str):
        """处理用户选择"""
        self.user_choice_value = choice
        self.waiting_for_user_flag = False
    
    def _is_config_command(self, message: str) -> bool:
        """判断是否是配置命令（只保留配置检测）"""
        message_lower = message.lower()
        
        # 配置命令检测（补充更多关键词）
        config_keywords = [
            '开启', '启用', '打开', '使用', '开',
            '关闭', '禁用', '停用', '禁止', '关',
            '查询', '显示', '状态', '配置', '设置'
        ]
        feature_keywords = ['graphrag', 'phase-aware', 'phase_aware', '阶段感知', '知识图谱']
        
        # 统一转小写匹配
        has_config_keyword = any(k in message_lower for k in config_keywords)
        has_feature_keyword = any(k in message_lower for k in feature_keywords)
        
        return has_config_keyword and has_feature_keyword
    

    
    def _parse_config_command(self, message: str) -> dict:
        """解析配置命令"""
        message_lower = message.lower()
        result = {'feature': None, 'action': None}
        
        # 识别功能（不区分大小写）
        if 'graphrag' in message_lower or '知识图谱' in message:
            result['feature'] = 'graphrag'
        elif 'phase-aware' in message_lower or 'phase_aware' in message_lower or '阶段感知' in message:
            result['feature'] = 'phase_aware'
        
        # 识别动作（补充更多关键词）
        if any(k in message_lower for k in ['开启', '启用', '打开', '使用', '开']):
            result['action'] = 'enable'
        elif any(k in message_lower for k in ['关闭', '禁用', '停用', '禁止', '关']):
            result['action'] = 'disable'
        elif any(k in message_lower for k in ['查询', '显示', '状态', '吗', '配置']):
            result['action'] = 'query'
        
        return result
    
    def _handle_config_command(self, message: str):
        """处理配置命令"""
        parsed = self._parse_config_command(message)
        feature = parsed['feature']
        action = parsed['action']
        
        if not feature or not action:
            # 可能是查询所有配置
            if action == 'query' or '配置' in message:
                self._show_config()
            else:
                self.emit('ai_message', {
                    'message': '❓ 无法识别配置命令\n\n支持的命令：\n- 开启/关闭 GraphRAG\n- 开启/关闭 Phase-Aware\n- 显示配置',
                    'timestamp': time.strftime('%H:%M:%S')
                })
            # 发送完成信号
            self.emit('test_complete', {
                'summary': {'type': 'config'},
                'message': '配置完成'
            })
            return
        
        # 应用配置
        if action == 'enable':
            self.config[f'enable_{feature}'] = True
            feature_name = 'GraphRAG' if feature == 'graphrag' else 'Phase-Aware'
            self.emit('ai_message', {
                'message': f'✅ {feature_name} 已启用',
                'timestamp': time.strftime('%H:%M:%S')
            })
            self.emit('terminal_output', {
                'output': f'[{time.strftime("%H:%M:%S")}] ✅ {feature_name} 已启用\n',
                'stream': 'stdout'
            })
            # 显示当前配置
            self._show_config()
            
        elif action == 'disable':
            self.config[f'enable_{feature}'] = False
            feature_name = 'GraphRAG' if feature == 'graphrag' else 'Phase-Aware'
            self.emit('ai_message', {
                'message': f'❌ {feature_name} 已禁用',
                'timestamp': time.strftime('%H:%M:%S')
            })
            self.emit('terminal_output', {
                'output': f'[{time.strftime("%H:%M:%S")}] ❌ {feature_name} 已禁用\n',
                'stream': 'stdout'
            })
            # 显示当前配置
            self._show_config()
            
        elif action == 'query':
            self._show_config()
        
        # 发送完成信号
        self.emit('test_complete', {
            'summary': {'type': 'config'},
            'message': '配置完成'
        })
        
        # 【新增】推送配置状态到前端
        self._push_config_status()
    
    def _push_config_status(self):
        """推送配置状态到前端"""
        self.emit('config_status', {
            'enable_graphrag': self.config['enable_graphrag'],
            'enable_phase_aware': self.config['enable_phase_aware'],
            'max_rounds': self.config['max_rounds'],
            'timeout': self.config['timeout']
        })
    
    def _validate_messages(self, messages: list) -> list:
        """验证消息列表，确保所有 content 字段非空
        
        OpenAI API 要求：
        - system/user/tool 消息必须有非空 content
        - assistant 消息可以没有 content（如果有 tool_calls）
        """
        validated = []
        
        for i, msg in enumerate(messages):
            role = msg.get("role", "")
            content = msg.get("content")
            tool_calls = msg.get("tool_calls")
            
            # System 消息：必须有 content
            if role == "system":
                if content and content.strip():
                    validated.append(msg)
                else:
                    print(f"[消息验证] 跳过空 system 消息 (索引 {i})")
            
            # User 消息：必须有 content
            elif role == "user":
                if content and content.strip():
                    validated.append(msg)
                else:
                    print(f"[消息验证] 跳过空 user 消息 (索引 {i})")
            
            # Assistant 消息：可以没有 content（如果有 tool_calls）
            elif role == "assistant":
                if tool_calls:
                    # 有 tool_calls，content 可以为空
                    # 但为了兼容性，如果 content 为空，设置为 None
                    if not content or not content.strip():
                        msg_copy = dict(msg)
                        msg_copy["content"] = None
                        validated.append(msg_copy)
                    else:
                        validated.append(msg)
                elif content and content.strip():
                    # 没有 tool_calls，必须有 content
                    validated.append(msg)
                else:
                    print(f"[消息验证] 跳过空 assistant 消息 (索引 {i}，无 tool_calls)")
            
            # Tool 消息：必须有 content
            elif role == "tool":
                if content and str(content).strip():
                    validated.append(msg)
                else:
                    # 工具消息不能为空，添加占位符
                    print(f"[消息验证] 修复空 tool 消息 (索引 {i})")
                    msg_copy = dict(msg)
                    msg_copy["content"] = "工具执行完成（无输出）"
                    validated.append(msg_copy)
            
            else:
                # 其他角色，保留
                validated.append(msg)
        
        return validated
    
    def _validate_tool_params(self, tool_name: str, arguments: dict, target_url: str = "") -> tuple:
        """验证工具调用参数是否完整，并尝试自动补全
        
        Args:
            tool_name: 工具名称
            arguments: 工具参数
            target_url: 目标 URL（用于自动补全）
        
        Returns:
            (是否有效, 补全后的参数)
        """
        # 定义常见工具的必需参数
        required_params = {
            'http_framework_test': ['url'],
            'execute_browser_js': ['url', 'js_code'],
            'browser_get_rendered_content': ['url'],
            'browser_visit_page': ['url'],
            'sqlmap_scan': ['url'],
            'nuclei_scan': ['url'],
            'dalfox_xss_scan': ['url'],
            'nikto_scan': ['url'],
            'crawl_site_endpoints': ['url'],
            'discover_injectable_params': ['url'],
            'smart_login_attempt': ['url'],
            'view_source_code': ['url'],
            'analyze_source_code': ['source_code'],
        }
        
        # 检查工具是否需要验证
        if tool_name not in required_params:
            # 未定义必需参数的工具，默认通过
            return True, arguments
        
        # 复制参数（避免修改原始参数）
        fixed_arguments = arguments.copy()
        
        # 检查并补全必需参数
        missing_params = []
        for param in required_params[tool_name]:
            if param not in fixed_arguments or not fixed_arguments[param]:
                missing_params.append(param)
                
                # 尝试自动补全 url 参数
                if param == 'url' and target_url:
                    fixed_arguments['url'] = target_url
                    print(f"[参数补全] ✅ 自动补全 {tool_name} 的 url 参数: {target_url}")
                    missing_params.remove(param)
        
        # 如果还有缺失参数，返回失败
        if missing_params:
            print(f"[参数验证] ❌ 工具 {tool_name} 缺少必需参数: {', '.join(missing_params)}")
            print(f"[参数验证] 当前参数: {arguments}")
            return False, arguments
        
        print(f"[参数验证] ✅ 工具 {tool_name} 参数完整")
        return True, fixed_arguments
    
    def _show_config(self):
        """显示当前配置"""
        graphrag_status = '✅ 已启用' if self.config['enable_graphrag'] else '❌ 未启用'
        phase_aware_status = '✅ 已启用' if self.config['enable_phase_aware'] else '❌ 未启用'
        
        config_text = f"""📊 当前配置：

🔧 功能开关：
  - GraphRAG (智能工具选择): {graphrag_status}
  - Phase-Aware (阶段感知): {phase_aware_status}

⚙️ 性能参数：
  - 最大轮次: {self.config['max_rounds']}
  - 超时时间: {self.config['timeout']}秒

💡 提示：
  - 开启 GraphRAG: 根据目标智能筛选工具（160个→20-30个）
  - 开启 Phase-Aware: 根据渗透阶段动态推荐工具
  - 两者协作: 最佳性能和准确性"""
        
        self.emit('ai_message', {
            'message': config_text,
            'timestamp': time.strftime('%H:%M:%S')
        })
        
        self.emit('terminal_output', {
            'output': f'[{time.strftime("%H:%M:%S")}] 📊 配置查询完成\n',
            'stream': 'stdout'
        })
        
    def _extract_target(self, message: str) -> str:
        """从消息中提取目标 URL/IP"""
        import re
        
        # URL
        url_match = re.search(r'https?://[^\s]+', message)
        if url_match:
            return url_match.group(0)
        
        # IP:端口
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', message)
        if ip_match:
            return f"http://{ip_match.group(0)}"
        
        # 域名
        domain_match = re.search(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', message)
        if domain_match:
            return f"http://{domain_match.group(0)}"
        
        return ""
    
    def _apply_tool_filtering(
        self, 
        all_tools: list,
        message: str,
        enable_graphrag: bool,
        enable_phase_aware: bool
    ) -> list:
        """应用工具筛选机制
        
        筛选策略：
        - 无筛选：返回前 128 个（API 限制）
        - 只 GraphRAG：返回 GraphRAG 筛选结果（20-30 个）
        - 只 Phase-Aware：返回 Phase-Aware 筛选结果（20-30 个）
        - 两者都启用：返回交集（10-20 个）
        """
        
        # 情况 1：两者都不启用 - 基础模式
        if not enable_graphrag and not enable_phase_aware:
            print(f"[工具筛选] 基础模式：使用前 128 个工具（API 限制）")
            return all_tools[:128]
        
        # 情况 2：只启用 GraphRAG
        if enable_graphrag and not enable_phase_aware:
            graphrag_tools = self._graphrag_filter(all_tools, message)
            print(f"[工具筛选] GraphRAG 模式：{len(graphrag_tools)} 个工具")
            return graphrag_tools
        
        # 情况 3：只启用 Phase-Aware
        if not enable_graphrag and enable_phase_aware:
            phase_tools = self._phase_aware_filter(all_tools, message)
            print(f"[工具筛选] Phase-Aware 模式：{len(phase_tools)} 个工具")
            return phase_tools
        
        # 情况 4：两者都启用 - 协作模式（取交集）
        graphrag_tools = self._graphrag_filter(all_tools, message)
        phase_tools = self._phase_aware_filter(all_tools, message)
        
        # 取交集
        graphrag_names = {t['function']['name'] for t in graphrag_tools}
        phase_names = {t['function']['name'] for t in phase_tools}
        intersection_names = graphrag_names & phase_names
        
        # 构建交集工具列表
        intersection_tools = [
            t for t in all_tools 
            if t['function']['name'] in intersection_names
        ]
        
        print(f"[工具筛选] 协作模式：")
        print(f"  - GraphRAG: {len(graphrag_tools)} 个")
        print(f"  - Phase-Aware: {len(phase_tools)} 个")
        print(f"  - 交集: {len(intersection_tools)} 个")
        
        # 如果交集太小，使用并集
        if len(intersection_tools) < 5:
            union_names = graphrag_names | phase_names
            union_tools = [
                t for t in all_tools 
                if t['function']['name'] in union_names
            ]
            print(f"  - ⚠️ 交集过小，使用并集: {len(union_tools)} 个")
            return union_tools
        
        return intersection_tools
    
    def _graphrag_filter(self, all_tools: list, message: str) -> list:
        """使用 GraphRAG 筛选工具"""
        try:
            from GraphRAG import HexStrikeToolSelector
            
            # 初始化 GraphRAG（如果还没初始化）
            if not hasattr(self, 'tool_selector'):
                self.tool_selector = HexStrikeToolSelector()
                print(f"[GraphRAG] ✅ 知识图谱已加载")
            
            # 提取目标 URL
            target = self._extract_target(message)
            if not target:
                # 如果没有明确目标，使用消息内容
                target = message
            
            # 使用 GraphRAG 选择工具（第一个参数是位置参数）
            recommendations = self.tool_selector.select_tools(
                target,  # ✅ 位置参数，不是关键字参数
                context={'user_instruction': message},
                max_tools=30
            )
            
            # 筛选工具列表
            filtered_tools = self.tool_selector.filter_tools_by_openai_format(
                all_tools, recommendations
            )
            
            # 显示推荐理由（前 5 个）
            print(f"[GraphRAG] 推荐工具：")
            for rec in recommendations[:5]:
                reasons = ', '.join(rec.reasons[:2])
                print(f"  - {rec.tool_name} (分数:{rec.score:.1f}): {reasons}")
            
            return filtered_tools
            
        except Exception as e:
            print(f"[GraphRAG] ⚠️ 筛选失败: {e}，回退到全量工具")
            import traceback
            traceback.print_exc()
            return all_tools[:128]
    
    def _phase_aware_filter(self, all_tools: list, message: str) -> list:
        """使用 Phase-Aware 筛选工具"""
        try:
            from GraphRAG import (
                PhaseAwareToolSelector,
                filter_tools_by_phase_recommendations
            )
            
            # 初始化 Phase-Aware（如果还没初始化）
            if not hasattr(self, 'phase_selector'):
                self.phase_selector = PhaseAwareToolSelector()
                print(f"[Phase-Aware] ✅ 阶段感知已启用")
            
            # 初始化或更新渗透上下文
            if not hasattr(self, 'pentest_context'):
                target = self._extract_target(message)
                if target:
                    self.pentest_context = self.phase_selector.initialize_context(target)
                else:
                    # 没有目标，无法使用 Phase-Aware
                    print(f"[Phase-Aware] ⚠️ 未检测到目标，无法初始化上下文")
                    return all_tools[:128]
            
            # 获取阶段推荐工具
            phase_recs = self.phase_selector.select_tools(
                self.pentest_context, 
                max_tools=30
            )
            
            # 筛选工具列表
            filtered_tools = filter_tools_by_phase_recommendations(
                all_tools, phase_recs
            )
            
            # 显示推荐理由
            print(f"[Phase-Aware] 当前阶段: {self.pentest_context.current_phase}")
            print(f"[Phase-Aware] 推荐工具：")
            for rec in phase_recs[:5]:
                print(f"  - {rec.tool_name}: {', '.join(rec.reasons)}")
            
            return filtered_tools
            
        except Exception as e:
            print(f"[Phase-Aware] ⚠️ 筛选失败: {e}，回退到全量工具")
            import traceback
            traceback.print_exc()
            return all_tools[:128]
    
    def _handle_unified(self, message: str):
        """ChatGPT式智能对话：先判断意图，再决定是否加载工具

        核心思路：
        1. 智能预判断：简单对话直接回答，复杂任务才加载工具
        2. 自然交互：像ChatGPT一样思考后决定行动
        3. 工具按需：只在真正需要时才初始化渗透测试工具
        """
        from user_server.llm_client import LLMClient

        self.emit('ai_thinking', {'message': '正在思考...'})

        try:
            # 初始化LLM客户端
            llm_client = LLMClient()

            # 添加用户消息到历史
            self.messages.append({
                "role": "user", 
                "content": message
            })

            # 智能预判断：是否为简单对话
            is_simple_chat = self._is_simple_conversation(message)
            
            if is_simple_chat:
                print(f"[智能模式] 识别为简单对话，直接回答")
                
                try:
                    # 简单对话：不加载工具，直接调用LLM
                    response = llm_client.chat_with_tools(
                        messages=self.messages,
                        tools=[],  # 不提供任何工具
                        temperature=0.7,
                        max_retries=2,  # 简单对话重试次数少一些
                        timeout=30      # 简单对话超时时间短一些
                    )
                    
                    content = response.get("content", "")
                    if content:
                        # 添加到消息历史
                        self.messages.append({
                            "role": "assistant",
                            "content": content
                        })
                        
                        # 发送回复
                        self.emit('ai_message', {
                            'message': content,
                            'timestamp': time.strftime('%H:%M:%S')
                        })
                        print(f"[智能模式] 简单对话完成")
                    else:
                        # LLM返回空内容
                        error_message = "抱歉，LLM服务暂时不可用，请稍后再试。"
                        self.emit('ai_message', {
                            'message': error_message,
                            'timestamp': time.strftime('%H:%M:%S')
                        })
                        
                except Exception as e:
                    print(f"[智能模式] 简单对话LLM调用失败: {e}")
                    
                    # 发送错误信息给用户
                    error_message = f"抱歉，LLM服务暂时不可用。错误: {str(e)}"
                    self.emit('ai_message', {
                        'message': error_message,
                        'timestamp': time.strftime('%H:%M:%S')
                    })
                    
                    # 添加到消息历史
                    self.messages.append({
                        "role": "assistant",
                        "content": error_message
                    })
                
            else:
                print(f"[智能模式] 识别为复杂任务，加载工具")
                # 复杂任务：加载所有工具，进入完整模式
                from user_server.mcp_hexstrike_client import HexstrikeMcpClient
                from user_server.orchestrator_demo import build_openai_tools_from_mcp

                target_url = self._extract_target(message)
                
                server_url = os.environ.get('HEXSTRIKE_SERVER_URL', 'http://127.0.0.1:8888')
                mcp_client = HexstrikeMcpClient(server_url)
                from user_server.runtime import ToolExecutionRequest, ToolGateway
                tool_gateway = ToolGateway(mcp_client, self.event_bus)

                # Skill-first: 优先走Kali端 LangGraph skills，保持统一响应结构
                if target_url:
                    route = llm_client.choose_web_skill(message, target_url)
                    skill_id = route.get("skill_id", "web_sqli")
                    self.emit('terminal_output', {
                        'output': f'[{time.strftime("%H:%M:%S")}] 🧭 技能路由: {skill_id} ({route.get("reason", "")})\n',
                        'stream': 'stdout'
                    })
                    request = ToolExecutionRequest(
                        tool_name="run_web_skill",
                        arguments={
                            "skill_id": skill_id,
                            "target_url": target_url,
                            "session_id": self.session_id,
                            "trace_id": "",
                            "cookies": {},
                        },
                        target=target_url,
                        session_id=self.session_id,
                        agent_id="main",
                    )
                    normalized = tool_gateway.call(request)
                    raw_skill = normalized.raw
                    if isinstance(raw_skill, dict) and isinstance(raw_skill.get("result"), dict):
                        skill_result = raw_skill["result"]
                    elif isinstance(raw_skill, dict):
                        skill_result = raw_skill
                    else:
                        skill_result = {}
                    skill_success = normalized.success
                    summary = normalized.summary or skill_result.get("summary", "技能执行完成")
                    findings = [item.to_dict() for item in normalized.findings]
                    if not skill_success and normalized.error:
                        summary = normalized.error.message
                    self.emit('ai_message', {
                        'message': f"已执行技能 `{skill_id}`。\n\n{summary}\n发现数量: {len(findings)}",
                        'timestamp': time.strftime('%H:%M:%S')
                    })
                    self.emit('test_complete', {
                        'summary': {'type': 'web_skill', 'skill_id': skill_id},
                        'message': summary,
                        'result': skill_result
                    })
                    return

                all_tools = build_openai_tools_from_mcp(mcp_client)
                print(f"[智能模式] 加载了 {len(all_tools)} 个工具")

                # 开始工具模式对话循环（最多10轮）
                max_rounds = 10
                for round_num in range(1, max_rounds + 1):
                    if self.should_stop_flag:
                        break

                    print(f"[智能模式] 第 {round_num} 轮对话")

                    # 调用LLM，让它自己决定是否使用工具
                    try:
                        self.emit('ai_thinking', {'message': '🧠 正在分析结果...'})
                        
                        response = llm_client.chat_with_tools(
                            messages=self.messages,
                            tools=all_tools,
                            temperature=0.7,
                            tool_choice="auto",  # 让LLM自己决定
                            max_retries=2,  # 减少重试次数，避免等待太久
                            timeout=45      # 减少单次超时时间
                        )
                        
                    except Exception as e:
                        print(f"[智能模式] LLM调用完全失败: {e}")
                        
                        # 发送错误信息给用户
                        error_message = f"LLM服务暂时不可用，但工具执行已完成。错误: {str(e)}"
                        self.emit('ai_message', {
                            'message': error_message,
                            'timestamp': time.strftime('%H:%M:%S')
                        })
                        
                        # 添加到消息历史
                        self.messages.append({
                            "role": "assistant",
                            "content": error_message
                        })
                        
                        # 提前结束，不继续循环
                        break

                    content = response.get("content")
                    tool_calls = response.get("tool_calls")

                    # 构建assistant消息
                    assistant_message = {"role": "assistant"}
                    if content:
                        assistant_message["content"] = content
                    if tool_calls:
                        assistant_message["tool_calls"] = tool_calls

                    self.messages.append(assistant_message)

                    # 显示LLM的回答
                    if content:
                        self.emit('ai_message', {
                            'message': content,
                            'timestamp': time.strftime('%H:%M:%S')
                        })
                        print(f"[智能模式] LLM回答: {content[:100]}...")

                    # 处理工具调用
                    if tool_calls:
                        print(f"[智能模式] LLM决定调用 {len(tool_calls)} 个工具")
                        self._execute_tool_calls(tool_calls, mcp_client)
                        # 如果调用了工具，继续下一轮让LLM分析结果
                        continue
                    else:
                        # 没有工具调用，对话结束
                        print(f"[智能模式] 对话完成，共 {round_num} 轮")
                        break

            # 限制历史长度
            if len(self.messages) > 50:
                self.messages = [self.messages[0]] + self.messages[-40:]

            # 发送完成信号
            self.emit('test_complete', {
                'summary': {'type': 'intelligent_mode'},
                'message': '对话完成'
            })

        except Exception as e:
            import traceback
            traceback.print_exc()
            self.emit('error', {'message': f'处理失败: {str(e)}'})

    
    def _is_simple_conversation(self, message: str) -> bool:
        """智能判断是否为简单对话（无需工具）
        
        简单对话特征：
        - 问候语
        - 自我介绍请求
        - 一般性咨询
        - 不包含明确的测试目标或URL
        """
        message_lower = message.lower().strip()
        
        # 问候语模式
        greetings = [
            '你好', 'hello', 'hi', '您好', '嗨',
            '你是谁', '介绍', '自我介绍', 'who are you',
            '你能做什么', '功能', '能力', 'what can you do'
        ]
        
        # 一般咨询模式（不涉及具体测试）
        general_questions = [
            '什么是', 'what is', '如何', 'how to', '为什么', 'why',
            '解释', 'explain', '帮助', 'help', '使用方法', '教程'
        ]
        
        # 检查是否为简单问候
        for greeting in greetings:
            if greeting in message_lower:
                return True
                
        # 检查是否为一般咨询（且不包含URL或明确测试意图）
        has_general_question = any(q in message_lower for q in general_questions)
        has_test_intent = any(keyword in message_lower for keyword in [
            'http://', 'https://', 'www.', '.com', '.cn', '.org',
            '扫描', 'scan', '测试', 'test', '渗透', 'pentest',
            '漏洞', 'vulnerability', '攻击', 'attack', 'exploit'
        ])
        
        if has_general_question and not has_test_intent:
            return True
            
        # 短消息且无明确测试意图
        if len(message.strip()) < 20 and not has_test_intent:
            return True
            
        return False

    def _execute_tool_calls(self, tool_calls, mcp_client):
        """Execute LLM tool calls through the versioned runtime gateway."""
        from user_server.runtime import ToolExecutionRequest, ToolGateway
        tool_gateway = ToolGateway(mcp_client, self.event_bus)
        for tool_call in tool_calls:
            if self.should_stop_flag:
                break

            tool_id = tool_call.get("id", "")
            function = tool_call.get("function", {})
            tool_name = function.get("name", "")

            try:
                import json
                arguments = json.loads(function.get("arguments", "{}"))
            except json.JSONDecodeError:
                arguments = {}

            print(f"[智能模式] 执行工具: {tool_name}")

            try:
                if tool_name == 'ask_user':
                    arguments['session_id'] = self.session_id

                request = ToolExecutionRequest(
                    tool_name=tool_name,
                    arguments=arguments,
                    target=str(arguments.get('target') or arguments.get('url') or ''),
                    call_id=tool_id or None,
                    session_id=self.session_id,
                    agent_id="main",
                )
                normalized = tool_gateway.call(request)
                result = normalized.to_dict(include_raw=False)

                # LLM receives a bounded normalized result, while full raw data
                # remains available to adapters/artifact storage.
                result_str = str(result)[:4000]
                if not result_str.strip():
                    result_str = "工具执行完成"

                tool_result_message = {
                    "role": "tool",
                    "tool_call_id": tool_id,
                    "content": result_str
                }
                self.messages.append(tool_result_message)

            except Exception as e:
                error_msg = f"工具执行失败: {str(e)}"
                print(f"[智能模式] {error_msg}")

                self.emit('tool_complete', {
                    'tool_name': tool_name,
                    'success': False,
                    'error': str(e),
                    'timestamp': time.strftime('%H:%M:%S')
                })

                # 添加错误到消息历史
                tool_result_message = {
                    "role": "tool",
                    "tool_call_id": tool_id,
                    "content": f"Error: {str(e)}"
                }
                self.messages.append(tool_result_message)
    
    def _fallback_intent_analysis(self, thinking_content: str, original_message: str) -> bool:
        """备用意图分析方法：当结构化分析失败时使用"""
        thinking_lower = thinking_content.lower()
        message_lower = original_message.lower()
        
        # 强否定词检测（优先级最高）
        strong_negative_patterns = [
            "不是.*测试", "并不是.*测试", "这不是", "并非.*测试",
            "只是问候", "只是.*问", "仅仅是", "误会",
            "不需要.*工具", "无需.*工具", "不用.*工具"
        ]
        
        import re
        for pattern in strong_negative_patterns:
            if re.search(pattern, thinking_content):
                print(f"[备用分析] 检测到强否定词: {pattern}")
                return False
        
        # 自我介绍检测
        intro_keywords = ["我是", "我叫", "介绍", "能做什么", "我能", "我的能力"]
        if any(keyword in thinking_content for keyword in intro_keywords):
            print(f"[备用分析] 检测到自我介绍模式")
            return False
        
        # 明确的工具需求检测
        explicit_tool_needs = [
            "开始.*测试", "执行.*扫描", "进行.*分析", "运行.*工具",
            "扫描.*目标", "测试.*网站", "分析.*漏洞"
        ]
        
        for pattern in explicit_tool_needs:
            if re.search(pattern, thinking_content):
                print(f"[备用分析] 检测到明确工具需求: {pattern}")
                return True
        
        # URL检测 + 行动词
        has_url = bool(re.search(r'https?://[^\s]+', original_message))
        action_words = ["扫描", "测试", "分析", "检测", "攻击", "渗透"]
        has_action = any(word in message_lower for word in action_words)
        
        if has_url and has_action:
            print(f"[备用分析] 检测到URL + 行动词组合")
            return True
        
        # 默认：简单问候和咨询不需要工具
        simple_patterns = ["你好", "介绍", "是什么", "怎么", "如何"]
        if any(pattern in message_lower for pattern in simple_patterns):
            print(f"[备用分析] 检测到简单问候/咨询")
            return False
        
        print(f"[备用分析] 默认判断：不需要工具")
        return False
    
    def run_pentest(self, target: str, user_instruction: str):
        """运行渗透测试"""
        
        try:
            # 【新增】添加调试日志
            print(f"[调试] run_pentest 被调用")
            print(f"[调试] target: {target}")
            print(f"[调试] user_instruction: {user_instruction}")
            
            # 【关键修改】只检查配置命令，其他全部交给 LLM 决定
            if self._is_config_command(user_instruction):
                # 配置命令
                print(f"[调试] 执行配置命令")
                self._handle_config_command(user_instruction)
                return
            
            # 【关键】所有非配置命令都使用统一处理（让 LLM 自己决定）
            print(f"[调试] 使用统一处理模式（LLM 自主决策）")
            self._handle_unified(user_instruction)
            return
            
        except Exception as e:
            print(f"[错误] run_pentest 入口异常: {e}")
            import traceback
            traceback.print_exc()
            self.emit('error', {'message': f'初始化失败: {str(e)}'})
            return
        
        # 导入必要的模块
        try:
            print(f"[调试] 开始导入模块...")
            from user_server import orchestrator_demo
            from user_server.orchestrator_demo import (
                PenTestSessionState,
                build_openai_tools_from_mcp,
                build_react_prompt,
                execute_tool_call,
                enhance_vuln_result,
                should_pause_for_user_input,
                generate_exploit_code,
                generate_final_report,
                VulnerabilityReport,
                HEXSTRIKE_SYSTEM_PROMPT,
            )
            from user_server.llm_client import LLMClient
            from user_server.mcp_hexstrike_client import HexstrikeMcpClient
            print(f"[调试] 模块导入成功")
        except Exception as e:
            print(f"[错误] 模块导入失败: {e}")
            import traceback
            traceback.print_exc()
            self.emit('error', {'message': f'模块导入失败: {str(e)}'})
            return
        
        # 初始化
        self.emit('ai_message', {
            'message': f'收到目标: {target}\n正在初始化渗透测试环境...',
            'timestamp': time.strftime('%H:%M:%S')
        })
        
        # 【修改】默认值改为 Kali 服务端地址
        server_url = os.environ.get('HEXSTRIKE_SERVER_URL', 'http://127.0.0.1:8888')
        print(f"[调试] MCP服务端地址: {server_url}")  # 添加日志
        
        try:
            print(f"[调试] 正在创建MCP客户端...")
            mcp_client = HexstrikeMcpClient(server_url)
            print(f"[调试] MCP客户端创建成功")
            
            print(f"[调试] 正在创建LLM客户端...")
            llm_client = LLMClient()
            print(f"[调试] LLM客户端创建成功")
            
            self.emit('terminal_output', {
                'output': f'[{time.strftime("%H:%M:%S")}] ✅ 连接到HexStrike服务端: {server_url}\n',
                'stream': 'stdout'
            })
            
        except Exception as e:
            print(f"[错误] 初始化异常: {e}")
            import traceback
            traceback.print_exc()
            self.emit('error', {'message': f'初始化失败: {str(e)}'})
            return
        
        # 创建会话
        print(f"[调试] 正在创建会话...")
        session = PenTestSessionState(
            target=target,
            user_instruction=user_instruction,
            status="running",
            phase="init"
        )
        print(f"[调试] 会话创建成功")
        
        # 获取工具列表
        print(f"[调试] 正在获取工具列表...")
        openai_tools = build_openai_tools_from_mcp(mcp_client)
        print(f"[调试] 工具列表获取成功: {len(openai_tools)}个")
        
        self.emit('terminal_output', {
            'output': f'[{time.strftime("%H:%M:%S")}] 📦 加载了 {len(openai_tools)} 个安全工具\n',
            'stream': 'stdout'
        })
        
        # 构建消息历史
        messages = [
            {"role": "system", "content": HEXSTRIKE_SYSTEM_PROMPT},
            {"role": "user", "content": user_instruction}
        ]
        
        # 主循环
        max_iterations = 50
        
        for iteration in range(1, max_iterations + 1):
            if self.should_stop_flag:
                self.emit('test_complete', {'message': '用户停止测试'})
                break
            
            session.iteration_count = iteration
            
            self.emit('terminal_output', {
                'output': f'\n{"="*70}\n🔄 轮次 {iteration}/{max_iterations}\n{"="*70}\n',
                'stream': 'stdout'
            })
            
            # 构建上下文
            context_prompt = build_react_prompt(session, None, None, None)
            messages.append({"role": "user", "content": context_prompt})
            
            # LLM思考
            self.emit('ai_thinking', {'message': '正在分析目标...'})
            self.emit('terminal_output', {
                'output': f'[{time.strftime("%H:%M:%S")}] 🧠 LLM思考中...\n',
                'stream': 'stdout'
            })
            
            try:
                response = llm_client.chat_with_tools(
                    messages=messages,
                    tools=openai_tools,
                    temperature=0.7
                )
            except Exception as e:
                self.emit('error', {'message': f'LLM调用失败: {str(e)}'})
                break
            
            # 构建assistant消息
            assistant_message = {
                "role": "assistant",
                "content": response.get("content"),
                "tool_calls": response.get("tool_calls")
            }
            messages.append(assistant_message)
            
            # 处理回复
            if assistant_message.get("content"):
                self.emit('ai_message', {
                    'message': assistant_message["content"],
                    'timestamp': time.strftime('%H:%M:%S')
                })
                self.emit('terminal_output', {
                    'output': f'[{time.strftime("%H:%M:%S")}] 💭 {assistant_message["content"]}\n',
                    'stream': 'stdout'
                })
            
            # 处理工具调用
            if assistant_message.get("tool_calls"):
                for tool_call in assistant_message["tool_calls"]:
                    if self.should_stop_flag:
                        break
                    
                    tool_name = tool_call["function"]["name"]
                    
                    try:
                        import json
                        arguments = json.loads(tool_call["function"]["arguments"])
                    except:
                        arguments = {}
                    
                    # 推送工具开始
                    self.emit('tool_start', {
                        'tool_name': tool_name,
                        'parameters': arguments,
                        'timestamp': time.strftime('%H:%M:%S')
                    })
                    
                    self.emit('terminal_output', {
                        'output': f'[{time.strftime("%H:%M:%S")}] 🔧 执行工具: {tool_name}\n',
                        'stream': 'stdout'
                    })
                    
                    self.emit('terminal_output', {
                        'output': f'[{time.strftime("%H:%M:%S")}] 📝 参数: {arguments}\n',
                        'stream': 'stdout'
                    })
                    
                    # 执行工具
                    try:
                        result = execute_tool_call(tool_name, arguments, session, mcp_client)
                        
                        # 增强结果
                        result = enhance_vuln_result(tool_name, result)
                        
                        # 推送工具完成
                        self.emit('tool_complete', {
                            'tool_name': tool_name,
                            'success': result.get('success', True),
                            'result': result,
                            'timestamp': time.strftime('%H:%M:%S')
                        })
                        
                        # 显示结果摘要
                        if result.get('success'):
                            self.emit('terminal_output', {
                                'output': f'[{time.strftime("%H:%M:%S")}] ✅ 工具执行成功\n',
                                'stream': 'stdout'
                            })
                        else:
                            self.emit('terminal_output', {
                                'output': f'[{time.strftime("%H:%M:%S")}] ❌ 工具执行失败: {result.get("error", "未知错误")}\n',
                                'stream': 'stderr'
                            })
                        
                        # 检查是否发现漏洞
                        if result.get('vulnerable'):
                            vuln_report = VulnerabilityReport(
                                vuln_type=result.get('vuln_type', 'Unknown'),
                                severity=result.get('severity', 'MEDIUM'),
                                confidence=result.get('confidence', 0.8),
                                description=f"{tool_name}发现漏洞",
                                payload=result.get('payload'),
                                affected_url=target
                            )
                            
                            session.vulnerabilities.append(vuln_report)
                            
                            # 生成EXP
                            exploit_code = generate_exploit_code(vuln_report, session)
                            
                            # 推送漏洞发现
                            self.emit('vulnerability_found', {
                                'vuln_type': vuln_report.vuln_type,
                                'severity': vuln_report.severity,
                                'confidence': vuln_report.confidence,
                                'description': vuln_report.description,
                                'payload': vuln_report.payload,
                                'exploit_code': exploit_code,
                                'affected_url': vuln_report.affected_url,
                                'timestamp': time.strftime('%H:%M:%S')
                            })
                            
                            self.emit('terminal_output', {
                                'output': f'[{time.strftime("%H:%M:%S")}] 🎯 发现漏洞: {vuln_report.vuln_type}\n',
                                'stream': 'stdout'
                            })
                            
                            # 检查是否需要暂停
                            should_pause, reason = should_pause_for_user_input(session, {'result': result})
                            
                            if should_pause:
                                # 推送暂停请求
                                self.emit('pause_for_input', {
                                    'reason': reason.value if reason else '发现漏洞',
                                    'options': ['continue', 'report', 'stop'],
                                    'vulnerabilities': [
                                        {
                                            'vuln_type': v.vuln_type,
                                            'severity': v.severity,
                                            'description': v.description,
                                            'payload': v.payload
                                        }
                                        for v in session.vulnerabilities
                                    ]
                                })
                                
                                # 等待用户选择
                                self.waiting_for_user_flag = True
                                self.user_choice_value = None
                                
                                timeout = 300  # 5分钟超时
                                elapsed = 0
                                while self.waiting_for_user_flag and elapsed < timeout:
                                    time.sleep(1)
                                    elapsed += 1
                                    
                                    if self.should_stop_flag:
                                        break
                                
                                # 处理用户选择
                                if self.user_choice_value == 'stop':
                                    self.should_stop_flag = True
                                    break
                                elif self.user_choice_value == 'report':
                                    # 生成报告并退出
                                    report = generate_final_report(session)
                                    self.emit('test_complete', {
                                        'summary': {
                                            'target': session.target,
                                            'total_iterations': session.iteration_count,
                                            'findings_count': len(session.findings),
                                            'vulnerabilities_count': len(session.vulnerabilities)
                                        },
                                        'report': report
                                    })
                                    self.should_stop_flag = True
                                    break
                                # continue: 继续循环
                        
                        # 【关键】添加工具结果到消息历史，确保 content 非空
                        result_str = str(result)[:1000]  # 限制长度
                        if not result_str or not result_str.strip():
                            result_str = "工具执行完成（无输出）"
                        
                        tool_result_message = {
                            "role": "tool",
                            "tool_call_id": tool_call["id"],
                            "content": result_str
                        }
                        messages.append(tool_result_message)
                        
                    except Exception as e:
                        import traceback
                        error_msg = f"工具执行异常: {str(e)}\n{traceback.format_exc()}"
                        
                        self.emit('tool_complete', {
                            'tool_name': tool_name,
                            'success': False,
                            'error': str(e),
                            'timestamp': time.strftime('%H:%M:%S')
                        })
                        
                        self.emit('terminal_output', {
                            'output': f'[{time.strftime("%H:%M:%S")}] ❌ {error_msg}\n',
                            'stream': 'stderr'
                        })
                        
                        # 【关键】添加错误到消息历史，确保 content 非空
                        error_content = f"Error: {str(e)}"
                        if not error_content or not error_content.strip():
                            error_content = "Error: 工具执行失败（未知错误）"
                        
                        tool_result_message = {
                            "role": "tool",
                            "tool_call_id": tool_call["id"],
                            "content": error_content
                        }
                        messages.append(tool_result_message)
            
            else:
                # 没有工具调用，可能是任务完成
                if assistant_message.get("content") and ("完成" in assistant_message["content"] or "结束" in assistant_message["content"]):
                    break
        
        # 测试完成
        report = generate_final_report(session)
        self.emit('test_complete', {
            'summary': {
                'target': session.target,
                'total_iterations': session.iteration_count,
                'findings_count': len(session.findings),
                'vulnerabilities_count': len(session.vulnerabilities)
            },
            'report': report
        })
        
        self.emit('terminal_output', {
            'output': report + '\n',
            'stream': 'stdout'
        })
