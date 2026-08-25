from __future__ import annotations

import os
import json
from typing import Any, Dict, List, Optional

import requests


class LLMClient:
    """OpenAI兼容的LLM客户端，支持Function Calling。
    
    自动适配不同API提供商：
    - OpenAI / Azure OpenAI
    - 阿里云DashScope (qwen)
    - 其他OpenAI兼容API
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        self.api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY", "")
        self.base_url = base_url or os.getenv(
            "LLM_API_BASE_URL",
            "https://api.openai.com/v1/chat/completions",
        )
        self.model = model or os.getenv("LLM_MODEL", "gpt-4.1-mini")
        
        # 检测API提供商
        self.provider = self._detect_provider()

    def _detect_provider(self) -> str:
        """检测API提供商"""
        url_lower = self.base_url.lower()
        if "dashscope" in url_lower or "aliyun" in url_lower:
            return "dashscope"
        elif "azure" in url_lower:
            return "azure"
        elif "anthropic" in url_lower:
            return "anthropic"
        elif "deepseek" in url_lower:
            return "deepseek"
        elif "moonshot" in url_lower or "kimi" in url_lower:
            return "moonshot"
        elif "zhipu" in url_lower or "bigmodel" in url_lower:
            return "zhipu"
        else:
            return "openai"

    def _adapt_tools_for_provider(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """根据不同API提供商适配工具格式
        
        对标CherryStudio的processSchemaForO3函数，确保schema符合严格验证要求
        """
        if not tools:
            return tools
        
        adapted_tools = []
        for tool in tools:
            adapted_tool = {"type": "function"}
            func = tool.get("function", {})
            
            # 基础字段
            adapted_func = {
                "name": func.get("name", ""),
                "description": func.get("description", "") or f"Tool: {func.get('name', '')}",
            }
            
            # 处理parameters - 对标CherryStudio的processSchemaForO3
            params = func.get("parameters", {})
            clean_params = self._process_schema_for_strict(params)
            adapted_func["parameters"] = clean_params
            
            adapted_tool["function"] = adapted_func
            adapted_tools.append(adapted_tool)
        
        return adapted_tools

    def _process_schema_for_strict(self, schema: Any) -> Dict[str, Any]:
        """处理schema以符合严格验证要求（对标CherryStudio的processSchemaForO3）"""
        if not schema or not isinstance(schema, dict):
            return {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
        
        # 递归过滤properties
        filtered = self._filter_properties(schema)
        
        # 确保所有属性都在required数组中
        properties = filtered.get("properties", {})
        all_keys = list(properties.keys()) if isinstance(properties, dict) else []
        
        return {
            "type": "object",
            "properties": properties,
            "required": all_keys,
            "additionalProperties": False
        }

    def _filter_properties(self, schema: Any) -> Dict[str, Any]:
        """递归过滤和验证properties（对标CherryStudio的filterProperties）"""
        if not schema or not isinstance(schema, dict):
            return schema if isinstance(schema, dict) else {}
        
        filtered = dict(schema)
        
        # 递归处理properties
        if "properties" in filtered and isinstance(filtered["properties"], dict):
            new_props = {}
            for key, value in filtered["properties"].items():
                if isinstance(value, dict):
                    new_props[key] = self._filter_properties(value)
                else:
                    new_props[key] = value
            filtered["properties"] = new_props
        
        # 处理items（数组类型）
        if "items" in filtered and isinstance(filtered["items"], dict):
            filtered["items"] = self._filter_properties(filtered["items"])
        
        # 处理additionalProperties
        if "additionalProperties" in filtered and isinstance(filtered["additionalProperties"], dict):
            filtered["additionalProperties"] = self._filter_properties(filtered["additionalProperties"])
        
        # 处理组合关键字
        for keyword in ["allOf", "anyOf", "oneOf"]:
            if keyword in filtered and isinstance(filtered[keyword], list):
                filtered[keyword] = [self._filter_properties(item) for item in filtered[keyword] if isinstance(item, dict)]
        
        # 对于object类型，确保符合严格模式
        if filtered.get("type") == "object":
            if "properties" not in filtered:
                filtered["properties"] = {}
            
            # 所有属性必须在required数组中
            prop_keys = list(filtered["properties"].keys()) if isinstance(filtered["properties"], dict) else []
            filtered["required"] = prop_keys
            filtered["additionalProperties"] = False
        
        # 移除可能导致问题的字段
        for field in ["$schema", "$id", "$ref", "definitions", "default"]:
            filtered.pop(field, None)
        
        return filtered

    def _adapt_messages_for_provider(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """根据不同API提供商适配消息格式"""
        adapted_messages = []
        
        for msg in messages:
            role = msg.get("role", "user")
            
            # 处理tool角色的消息
            if role == "tool":
                if self.provider == "dashscope":
                    # DashScope使用function角色
                    adapted_msg = {
                        "role": "function",
                        "name": msg.get("name", "tool_result"),
                        "content": msg.get("content", "")
                    }
                else:
                    # OpenAI标准格式
                    adapted_msg = {
                        "role": "tool",
                        "tool_call_id": msg.get("tool_call_id", ""),
                        "content": msg.get("content", "")
                    }
            elif role == "assistant" and msg.get("tool_calls"):
                # 处理包含tool_calls的assistant消息
                adapted_msg = {
                    "role": "assistant",
                    "content": msg.get("content") or "",
                }
                if self.provider == "dashscope":
                    # DashScope使用function_call
                    tool_calls = msg.get("tool_calls", [])
                    if tool_calls:
                        first_call = tool_calls[0]
                        func = first_call.get("function", {})
                        adapted_msg["function_call"] = {
                            "name": func.get("name", ""),
                            "arguments": func.get("arguments", "{}")
                        }
                else:
                    adapted_msg["tool_calls"] = msg.get("tool_calls")
            else:
                adapted_msg = dict(msg)
            
            adapted_messages.append(adapted_msg)
        
        return adapted_messages

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        extra: Optional[Dict[str, Any]] = None,
        max_retries: int = 3,
        timeout: int = 30,  # 减少单次超时时间
    ) -> str:
        """普通对话模式（不带工具），支持超时重试"""
        import time
        
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if extra:
            payload.update(extra)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_error = None
        
        # 重试循环
        for attempt in range(max_retries):
            try:
                print(f"[LLM] 尝试普通对话 API (第 {attempt + 1}/{max_retries} 次)")
                
                response = requests.post(self.base_url, json=payload, headers=headers, timeout=timeout)
                response.raise_for_status()
                data = response.json()
                choice = (data.get("choices") or [{}])[0]
                message = choice.get("message") or {}
                
                print(f"[LLM] 普通对话 API 调用成功")
                return (message.get("content") or "").strip()
                
            except requests.exceptions.Timeout as e:
                last_error = e
                print(f"[LLM] 普通对话超时 (第 {attempt + 1} 次): {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # 指数退避
                    print(f"[LLM] 等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    raise e
                    
            except Exception as e:
                last_error = e
                print(f"[LLM] 普通对话错误 (第 {attempt + 1} 次): {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    print(f"[LLM] 等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    raise e
        
        # 如果所有重试都失败，抛出最后一个错误
        raise last_error

    def chat_with_tools(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        temperature: float = 0.2,
        tool_choice: str = "auto",
        max_retries: int = 3,
        timeout: int = 60,  # 减少单次超时时间
    ) -> Dict[str, Any]:
        """带工具的对话模式（原生Function Calling）
        
        自动适配不同API提供商的格式差异，支持超时重试
        """
        import time
        
        # 适配消息格式
        adapted_messages = self._adapt_messages_for_provider(messages)
        
        # 适配工具格式
        adapted_tools = self._adapt_tools_for_provider(tools)
        
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": adapted_messages,
            "temperature": temperature,
        }
        
        # 根据提供商设置工具参数
        if self.provider == "dashscope":
            # DashScope使用functions而不是tools
            payload["functions"] = [t["function"] for t in adapted_tools]
            if tool_choice != "none":
                payload["function_call"] = "auto"
        else:
            payload["tools"] = adapted_tools
            payload["tool_choice"] = tool_choice

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_error = None
        
        # 重试循环
        for attempt in range(max_retries):
            try:
                print(f"[LLM] 尝试调用 API (第 {attempt + 1}/{max_retries} 次)")
                
                response = requests.post(self.base_url, json=payload, headers=headers, timeout=timeout)
                response.raise_for_status()
                data = response.json()
                
                print(f"[LLM] API 调用成功")
                break
                
            except requests.exceptions.Timeout as e:
                last_error = e
                print(f"[LLM] API 调用超时 (第 {attempt + 1} 次): {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # 指数退避: 1s, 2s, 4s
                    print(f"[LLM] 等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"[LLM] 达到最大重试次数，回退到普通对话模式")
                    return self._fallback_chat(messages, temperature)
                    
            except requests.exceptions.HTTPError as e:
                last_error = e
                print(f"[LLM] HTTP 错误 (第 {attempt + 1} 次): {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    print(f"[LLM] 等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    # 打印详细错误信息
                    print(f"[LLM] Function Calling失败({e})，回退到普通对话模式")
                    try:
                        error_detail = response.json()
                        print(f"[LLM] API错误详情: {json.dumps(error_detail, ensure_ascii=False, indent=2)}")
                    except:
                        print(f"[LLM] API响应: {response.text[:500]}")
                    return self._fallback_chat(messages, temperature)
                    
            except Exception as e:
                last_error = e
                print(f"[LLM] 其他错误 (第 {attempt + 1} 次): {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    print(f"[LLM] 等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"[LLM] 达到最大重试次数，回退到普通对话模式")
                    return self._fallback_chat(messages, temperature)
        
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        finish_reason = choice.get("finish_reason", "stop")
        
        # 统一处理tool_calls格式
        tool_calls = message.get("tool_calls")
        
        # DashScope返回function_call而不是tool_calls
        if not tool_calls and message.get("function_call"):
            func_call = message["function_call"]
            tool_calls = [{
                "id": f"call_{func_call.get('name', 'unknown')}",
                "type": "function",
                "function": {
                    "name": func_call.get("name", ""),
                    "arguments": func_call.get("arguments", "{}")
                }
            }]
            finish_reason = "tool_calls"
        
        return {
            "content": message.get("content"),
            "tool_calls": tool_calls,
            "finish_reason": finish_reason,
            "raw_message": message,
        }

    def _fallback_chat(self, messages: List[Dict[str, Any]], temperature: float) -> Dict[str, Any]:
        """回退到普通对话模式（不带工具）"""
        # 过滤掉tool相关的消息
        clean_messages = []
        for msg in messages:
            role = msg.get("role", "")
            if role in ["system", "user", "assistant"]:
                clean_msg = {"role": role, "content": msg.get("content", "")}
                clean_messages.append(clean_msg)
        
        try:
            content = self.chat(clean_messages, temperature)
            return {
                "content": content,
                "tool_calls": None,
                "finish_reason": "stop",
                "raw_message": {"role": "assistant", "content": content},
            }
        except Exception as e:
            return {
                "content": f"LLM调用失败: {e}",
                "tool_calls": None,
                "finish_reason": "error",
                "raw_message": {},
            }

    def choose_web_skill(self, user_text: str, target_url: str = "") -> Dict[str, str]:
        prompt = (
            "你是Web渗透测试技能路由器。"
            "只返回JSON，格式: {\"skill_id\":\"web_sqli|web_xss|web_unauth_api\",\"reason\":\"...\"}。"
            "如果用户提到SQL注入、报错注入、盲注，返回web_sqli；"
            "提到XSS、脚本注入，返回web_xss；"
            "提到未授权接口、越权、鉴权绕过，返回web_unauth_api。"
            f"\n用户请求: {user_text}\n目标: {target_url}"
        )
        text = self.chat([{"role": "user", "content": prompt}], temperature=0.0)
        try:
            parsed = json.loads(text)
            skill_id = parsed.get("skill_id", "web_sqli")
            if skill_id not in {"web_sqli", "web_xss", "web_unauth_api"}:
                skill_id = "web_sqli"
            return {"skill_id": skill_id, "reason": parsed.get("reason", "")}
        except Exception:
            lowered = user_text.lower()
            if "xss" in lowered:
                return {"skill_id": "web_xss", "reason": "fallback keyword"}
            if "未授权" in user_text or "越权" in user_text or "auth" in lowered:
                return {"skill_id": "web_unauth_api", "reason": "fallback keyword"}
            return {"skill_id": "web_sqli", "reason": "fallback default"}
