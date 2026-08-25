from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class HexstrikeMcpClient:
    """MCP 客户端抽象：通过 STDIO 调用 ``hexstrike_mcp.py`` 暴露的工具。

    该实现严格遵循 MCP STDIO 模式：

    Windows 侧本地启动 ``hexstrike_mcp.py``（作为 MCP Server，命令形如::

        python hexstrike_mcp.py --server http://<KALI_IP>:8888

    然后通过 Model Context Protocol 的 stdio 传输调用工具，例如
    ``analyze_target_intelligence``、``intelligent_smart_scan``、
    ``nmap_scan``、``gobuster_scan``、``nuclei_scan`` 等。

    对上层 orchestrator / api_server 来说，只看到一个同步的 Python 类，
    每个方法都返回一个 ``Dict[str, Any]``，对应 MCP 工具的 structuredContent。"""

    def __init__(self, server_url: str, timeout: int = 300, transport: str = "mcp") -> None:
        if transport != "mcp":
            raise ValueError("HexstrikeMcpClient 现在仅支持 transport='mcp' (STDIO)")

        self.server_url = server_url
        self.timeout = timeout

        # 计算仓库内 hexstrike_mcp.py 的路径，作为 MCP Server 脚本。
        root_dir = Path(__file__).resolve().parents[1]
        self._mcp_script = str(root_dir / "hexstrike_mcp.py")

    # ------------------------------------------------------------------
    # Internal helpers: one-off MCP stdio calls
    # ------------------------------------------------------------------

    async def _call_tool_async(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Single MCP tool invocation using stdio.

        为了简化实现，这里采用“每次调用启动一个 MCP server 进程并完成一次调用”的模式：
        - 通过 stdio_client 启动 ``hexstrike_mcp.py``
        - 建立 ClientSession 并 initialize
        - 调用指定工具
        - 返回 structuredContent，如果没有则尝试从文本内容解析 JSON
        """

        server_params = StdioServerParameters(
            command=sys.executable,
            args=[
                self._mcp_script,
                "--server",
                self.server_url,
                "--timeout",
                str(self.timeout),
            ],
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments=arguments)

        # 优先使用 structuredContent（FastMCP 对 dict 返回值会自动填充）
        structured = getattr(result, "structuredContent", None)
        if structured is not None:
            return structured

        # 退化到使用第一个文本 content，并尝试解析为 JSON
        contents = getattr(result, "content", None) or []
        if contents:
            block = contents[0]
            text = getattr(block, "text", None) or str(block)
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
            return {"success": True, "content": text}

        return {"success": False, "error": "Empty MCP tool result"}

    def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return asyncio.run(self._call_tool_async(tool_name, arguments))
        except Exception as exc:
            return {
                "success": False,
                "error": f"MCP tool '{tool_name}' failed: {exc}",
            }

    async def _list_tools_async(self) -> list:
        """获取MCP服务端所有可用工具列表"""
        server_params = StdioServerParameters(
            command=sys.executable,
            args=[
                self._mcp_script,
                "--server",
                self.server_url,
                "--timeout",
                str(self.timeout),
            ],
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                return result.tools if hasattr(result, 'tools') else []

    def list_tools(self) -> list:
        """同步获取MCP工具列表"""
        try:
            return asyncio.run(self._list_tools_async())
        except Exception as exc:
            print(f"[MCP] 获取工具列表失败: {exc}")
            return []

    def list_web_skills(self) -> Dict[str, Any]:
        result = self._call_tool("list_web_skills", {})
        if isinstance(result.get("result"), dict):
            return result["result"]
        return result

    def run_web_skill(
        self,
        skill_id: str,
        target_url: str,
        session_id: str = "",
        trace_id: str = "",
        cookies: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        result = self._call_tool(
            "run_web_skill",
            {
                "skill_id": skill_id,
                "target_url": target_url,
                "session_id": session_id,
                "trace_id": trace_id,
                "cookies": cookies or {},
            },
        )
        # 兼容 MCP 返回包裹格式：{"result": {...}, ...}
        if isinstance(result.get("result"), dict):
            return result["result"]
        return result

    # ------------------------------------------------------------------
    # High-level MCP methods mapped to hexstrike_mcp.py tools
    # ------------------------------------------------------------------

    def analyze_target(self, target: str) -> Dict[str, Any]:
        """Wrapper around the intelligent target analysis endpoint.

        语义上对应 MCP 工具 ``analyze_target_intelligence``。
        """

        return self._call_tool("analyze_target_intelligence", {"target": target})

    def select_tools(self, target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """Wrapper around AI tool selection.

        语义上对应 MCP 工具 ``select_optimal_tools_ai``。
        """

        return self._call_tool(
            "select_optimal_tools_ai",
            {"target": target, "objective": objective},
        )

    def optimize_parameters(self, target: str, tool: str, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Wrapper around parameter optimization.

        语义上对应 MCP 工具 ``optimize_tool_parameters_ai``。
        """

        return self._call_tool(
            "optimize_tool_parameters_ai",
            {"target": target, "tool": tool, "context": context or {}},
        )

    def create_attack_chain(self, target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """Wrapper around AI attack-chain creation.

        语义上对应 MCP 工具 ``create_attack_chain_ai``。
        """

        return self._call_tool(
            "create_attack_chain_ai",
            {"target": target, "objective": objective},
        )

    def smart_scan(self, target: str, objective: str = "comprehensive", max_tools: int = 5) -> Dict[str, Any]:
        """Wrapper around intelligent smart scan.

        语义上对应 MCP 工具 ``intelligent_smart_scan``。
        """

        return self._call_tool(
            "intelligent_smart_scan",
            {"target": target, "objective": objective, "max_tools": max_tools},
        )

    def run_nmap(self, target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """Wrapper around Nmap scan.

        语义上对应 MCP 工具 ``nmap_scan``。
        """

        return self._call_tool(
            "nmap_scan",
            {
                "target": target,
                "scan_type": scan_type,
                "ports": ports,
                "additional_args": additional_args,
            },
        )

    # ------------------------------------------------------------------
    # Generic Linux/host utilities (do not depend on Web target)
    # ------------------------------------------------------------------

    def list_directory(self, path: str = "~") -> Dict[str, Any]:
        """List files and directories under ``path`` on the HexStrike/Kali host.

        语义上对应 MCP 工具 ``list_directory``。"""

        return self._call_tool("list_directory", {"path": path})

    def read_file(self, path: str, max_bytes: int = 4096) -> Dict[str, Any]:
        """Read the beginning of a file on the HexStrike/Kali host.

        语义上对应 MCP 工具 ``read_file``。"""

        return self._call_tool("read_file", {"path": path, "max_bytes": max_bytes})

    def list_processes(self, limit: int = 50) -> Dict[str, Any]:
        """List running processes on the HexStrike/Kali host.

        语义上对应 MCP 工具 ``list_processes``。"""

        return self._call_tool("list_processes", {"limit": limit})

    def run_gobuster(
        self,
        url: str,
        mode: str = "dir",
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        additional_args: str = "",
    ) -> Dict[str, Any]:
        """Wrapper around Gobuster scan.

        语义上对应 MCP 工具 ``gobuster_scan``。
        """

        return self._call_tool(
            "gobuster_scan",
            {
                "url": url,
                "mode": mode,
                "wordlist": wordlist,
                "additional_args": additional_args,
            },
        )

    def run_sqlmap(
        self,
        url: str,
        data: str = "",
        additional_args: str = "",
        cookies: Dict[str, str] = None,  # 【P0新增】
    ) -> Dict[str, Any]:
        """Wrapper around SQLMap scan.

        语义上对应 MCP 工具 ``sqlmap_scan``。
        """

        return self._call_tool(
            "sqlmap_scan",
            {
                "url": url,
                "data": data,
                "additional_args": additional_args,
                "cookies": cookies or {},  # 【P0新增】
            },
        )

    def run_nuclei(
        self,
        target: str,
        severity: str = "",
        tags: str = "",
        template: str = "",
        additional_args: str = "",
        cookies: Dict[str, str] = None,  # 【P0新增】
    ) -> Dict[str, Any]:
        """Wrapper around Nuclei vulnerability scan.

        语义上对应 MCP 工具 ``nuclei_scan``。
        """

        return self._call_tool(
            "nuclei_scan",
            {
                "target": target,
                "severity": severity,
                "tags": tags,
                "template": template,
                "additional_args": additional_args,
                "cookies": cookies or {},  # 【P0新增】
            },
        )

    def health(self) -> Dict[str, Any]:
        """Check connectivity with the HexStrike MCP server via the ``server_health`` tool.

        语义上对应 MCP 工具 ``server_health``，其内部再去调用 HexStrike HTTP ``/health``。
        为了与之前 HTTP 版本保持接口相似，这里会根据返回的 ``status`` 字段补充
        一个 ``success`` 布尔值，方便调用方做简单判断。
        """

        result = self._call_tool("server_health", {})
        status = str(result.get("status", ""))
        if "success" not in result:
            result["success"] = status.lower() == "healthy"
        return result

    # ------------------------------------------------------------------
    # Page Awareness Tools (v7.0 - 页面感知工具)
    # ------------------------------------------------------------------

    def browser_visit(self, url: str, timeout: int = 10, follow_redirects: bool = True, cookies: Dict[str, str] = None) -> Dict[str, Any]:
        """访问URL并解析页面结构（表单、输入框、链接）

        语义上对应 MCP 工具 ``browser_visit_page``。
        """

        return self._call_tool(
            "browser_visit_page",
            {
                "url": url,
                "timeout": timeout,
                "follow_redirects": follow_redirects,
                "cookies": cookies or {},  # 【P0新增】
            },
        )

    def crawl_site(
        self,
        url: str,
        max_depth: int = 2,
        max_urls: int = 100,
        include_subdomains: bool = False,
        additional_args: str = "",
        cookies: Dict[str, str] = None,  # 【P0新增】
    ) -> Dict[str, Any]:
        """爬取站点，发现所有可测试的端点

        语义上对应 MCP 工具 ``crawl_site_endpoints``。
        """

        return self._call_tool(
            "crawl_site_endpoints",
            {
                "url": url,
                "max_depth": max_depth,
                "max_urls": max_urls,
                "include_subdomains": include_subdomains,
                "additional_args": additional_args,
                "cookies": cookies or {},  # 【P0新增】
            },
        )

    def discover_params(
        self,
        url: str,
        method: str = "GET",
        test_depth: str = "basic",
        cookies: Dict[str, str] = None,  # 【P0新增】
    ) -> Dict[str, Any]:
        """分析URL，发现可注入的参数位置（GET/POST/Cookie/Header）

        语义上对应 MCP 工具 ``discover_injectable_params``。
        """

        return self._call_tool(
            "discover_injectable_params",
            {
                "url": url,
                "method": method,
                "test_depth": test_depth,
                "cookies": cookies or {},  # 【P0新增】
            },
        )

    def smart_login(
        self,
        url: str,
        username: str = "",
        password: str = "",
        try_defaults: bool = True,
    ) -> Dict[str, Any]:
        """智能登录 - 自动尝试常见凭据或使用用户提供的凭据

        语义上对应 MCP 工具 ``smart_login_attempt``。
        """

        return self._call_tool(
            "smart_login_attempt",
            {
                "url": url,
                "username": username,
                "password": password,
                "try_defaults": try_defaults,
            },
        )

    # ------------------------------------------------------------------
    # Source Code Analysis Tools (P1 - 源码查看和分析)
    # ------------------------------------------------------------------

    def view_source(
        self,
        url: str,
        cookies: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """查看后端源码（如DVWA的View Source按钮）

        语义上对应 MCP 工具 ``view_source_code``。
        """

        return self._call_tool(
            "view_source_code",
            {
                "url": url,
                "cookies": cookies or {},
            },
        )

    def analyze_code(
        self,
        source_code: str,
        language: str = "php",
        url: str = "",
    ) -> Dict[str, Any]:
        """分析源码，识别潜在漏洞

        语义上对应 MCP 工具 ``analyze_source_code``。
        """

        return self._call_tool(
            "analyze_source_code",
            {
                "source_code": source_code,
                "language": language,
                "url": url,
            },
        )

    # ------------------------------------------------------------------
    # Intelligent Quick Test (v7.0 - LLM驱动的快速测试)
    # ------------------------------------------------------------------

    def intelligent_quick_test(
        self,
        target: str,
        vuln_type: str = "xss",
        context: Dict[str, Any] = None,
        cookies: Dict[str, str] = None,
        max_payloads: int = 5,
    ) -> Dict[str, Any]:
        """LLM驱动的智能快速测试 - 生成针对性Payload并快速验证

        语义上对应 MCP 工具 ``intelligent_quick_test``。
        
        Args:
            target: 目标URL
            vuln_type: 漏洞类型（xss, sqli, rce, lfi, open_redirect）
            context: 上下文信息（从browser_visit和analyze_code获取）
            cookies: 会话Cookies
            max_payloads: 最多测试几个Payload
        """

        return self._call_tool(
            "intelligent_quick_test",
            {
                "target": target,
                "vuln_type": vuln_type,
                "context": context or {},
                "cookies": cookies or {},
                "max_payloads": max_payloads,
            },
        )
