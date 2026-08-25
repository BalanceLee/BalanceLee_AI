"""
HexStrike GraphRAG Phase-Aware Module - 动态阶段感知工具选择

支持：
1. 输入类型识别 - 智能判断起始阶段
2. 动态上下文 - 随测试进行更新
3. 阶段推进 - 根据发现自动推进
4. OWASP Top 10 覆盖

使用方式：
  --enable-phase-aware  启用阶段感知机制
"""

from __future__ import annotations

import re
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Set
from urllib.parse import urlparse, parse_qs


# ============================================================================
# 输入类型枚举
# ============================================================================

class InputType(Enum):
    """输入类型枚举"""
    IP_ADDRESS = "ip_address"           # 192.168.1.1
    DOMAIN_ONLY = "domain_only"         # example.com
    SITE_ROOT = "site_root"             # http://example.com/
    WEB_PAGE = "web_page"               # http://example.com/app/page.php
    URL_WITH_PARAMS = "url_with_params" # http://example.com/search.php?q=test
    API_ENDPOINT = "api_endpoint"       # http://example.com/api/v1/users


# ============================================================================
# 渗透阶段枚举
# ============================================================================

class PentestPhase(Enum):
    """渗透测试阶段"""
    RECON = "recon"                           # 信息收集
    DISCOVERY = "discovery"                   # 页面/端点发现
    PARAMETER_ANALYSIS = "parameter_analysis" # 参数分析
    VULNERABILITY_SCAN = "vulnerability_scan" # 漏洞扫描
    EXPLOITATION = "exploitation"             # 漏洞利用
    POST_EXPLOITATION = "post_exploitation"   # 后渗透


# ============================================================================
# 动态上下文数据结构
# ============================================================================

@dataclass
class WebPentestContext:
    """Web渗透测试动态上下文"""
    
    # ========== 基础信息 ==========
    target_url: str                              # 目标URL
    target_domain: str = ""                      # 目标域名
    target_ip: str = ""                          # 目标IP
    input_type: InputType = InputType.WEB_PAGE   # 输入类型
    
    # ========== 阶段控制 ==========
    current_phase: str = "discovery"             # 当前阶段
    phase_history: List[str] = field(default_factory=list)  # 阶段历史
    
    # ========== Phase 1: RECON 输出 ==========
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technology_stack: List[str] = field(default_factory=list)
    cms_detected: str = ""
    waf_detected: str = ""
    
    # ========== Phase 2: DISCOVERY 输出 ==========
    discovered_urls: List[str] = field(default_factory=list)
    discovered_forms: List[Dict] = field(default_factory=list)
    discovered_endpoints: List[Dict] = field(default_factory=list)
    has_login_page: bool = False
    has_file_upload: bool = False
    has_search_function: bool = False
    has_user_input: bool = False
    sensitive_files: List[str] = field(default_factory=list)
    
    # ========== Phase 3: PARAMETER_ANALYSIS 输出 ==========
    injectable_params: List[Dict] = field(default_factory=list)
    hidden_params: List[Dict] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers_of_interest: List[str] = field(default_factory=list)
    
    # ========== Phase 4: VULNERABILITY_SCAN 输出 ==========
    suspected_vulns: List[Dict] = field(default_factory=list)
    
    # ========== Phase 5: EXPLOITATION 输出 ==========
    confirmed_vulns: List[Dict] = field(default_factory=list)
    extracted_data: List[Dict] = field(default_factory=list)
    credentials_found: List[Dict] = field(default_factory=list)
    
    # ========== Phase 6: POST_EXPLOITATION 输出 ==========
    shell_access: bool = False
    privilege_level: str = ""
    
    # ========== 认证状态 ==========
    is_authenticated: bool = False
    session_cookies: Dict[str, str] = field(default_factory=dict)
    auth_user: str = ""
    
    # ========== 漏洞测试状态 ==========
    # 格式: {"sqli": "found", "xss": "not_found", "lfi": "pending"}
    # pending: 未测试, testing: 测试中, found: 已发现, not_found: 已测试未发现
    vuln_test_status: Dict[str, str] = field(default_factory=dict)


# ============================================================================
# 输入类型识别器
# ============================================================================

class InputTypeDetector:
    """输入类型识别器"""
    
    @staticmethod
    def detect(user_input: str) -> Tuple[InputType, str]:
        """识别输入类型，返回(类型, 起始阶段)"""
        
        input_clean = user_input.strip()
        input_lower = input_clean.lower()
        
        # 1. 纯IP地址
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, input_clean):
            return InputType.IP_ADDRESS, "recon"
        
        # 2. 纯域名（无协议）
        domain_pattern = r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,}$'
        if re.match(domain_pattern, input_clean) and not input_lower.startswith('http'):
            return InputType.DOMAIN_ONLY, "recon"
        
        # 3. HTTP(S) URL
        if input_lower.startswith(('http://', 'https://')):
            try:
                parsed = urlparse(input_clean)
                path = parsed.path or ""
                query = parsed.query or ""
                
                # 3.1 带参数的URL → 直接参数分析
                if query:
                    return InputType.URL_WITH_PARAMS, "parameter_analysis"
                
                # 3.2 API端点
                if '/api/' in path or '/v1/' in path or '/v2/' in path or '/graphql' in path:
                    return InputType.API_ENDPOINT, "parameter_analysis"
                
                # 3.3 站点根目录
                root_paths = ['', '/', '/index.php', '/index.html', '/index.asp', 
                             '/index.aspx', '/default.aspx', '/home']
                if path in root_paths:
                    return InputType.SITE_ROOT, "discovery"
                
                # 3.4 具体页面（有路径和文件扩展名）
                if path:
                    last_segment = path.split('/')[-1]
                    if '.' in last_segment:
                        return InputType.WEB_PAGE, "discovery"
                
                # 3.5 目录路径
                if path.endswith('/'):
                    return InputType.SITE_ROOT, "discovery"
                
                # 默认当作Web页面
                return InputType.WEB_PAGE, "discovery"
                
            except Exception:
                return InputType.WEB_PAGE, "discovery"
        
        # 4. 默认：当作域名处理
        return InputType.DOMAIN_ONLY, "recon"


# ============================================================================
# 阶段意图映射（Phase-Aware 只输出意图，不指定具体工具）
# ============================================================================

PHASE_INTENT_MAPPING = {
    "recon": {
        "intent": "信息收集",
        "scenarios": [
            "port_scan", "service_detection", "subdomain_enum", 
            "tech_fingerprint", "dns_enum", "whois_lookup"
        ],
        "description": "收集目标的基础信息：端口、服务、子域名、技术栈"
    },
    "discovery": {
        "intent": "端点发现",
        "scenarios": [
            "page_crawl", "directory_bruteforce", "api_discovery", 
            "form_detection", "endpoint_enum", "sitemap_parse",
            "js_analysis", "comment_extraction"
        ],
        "description": "发现目标的页面、目录、API端点、表单"
    },
    "parameter_analysis": {
        "intent": "参数分析",
        "scenarios": [
            "param_discovery", "hidden_param", "input_analysis",
            "form_analysis", "api_param_enum", "cookie_analysis"
        ],
        "description": "分析可注入的参数、隐藏参数、输入点"
    },
    "vulnerability_scan": {
        "intent": "漏洞检测",
        "scenarios": [
            "sqli_test", "xss_test", "lfi_test", "rfi_test",
            "rce_test", "ssrf_test", "xxe_test", "ssti_test",
            "auth_test", "idor_test", "upload_test", "csrf_test",
            "cors_test", "jwt_test", "deserialization_test",
            "open_redirect_test", "header_injection_test"
        ],
        "description": "检测各类Web漏洞（OWASP Top 10覆盖）"
    },
    "exploitation": {
        "intent": "漏洞利用",
        "scenarios": [
            "sqli_exploit", "xss_exploit", "rce_exploit",
            "lfi_exploit", "upload_exploit", "auth_bypass",
            "shell_upload", "data_extraction"
        ],
        "description": "利用已发现的漏洞进行深度测试"
    },
    "post_exploitation": {
        "intent": "后渗透",
        "scenarios": [
            "data_dump", "privilege_escalation", "persistence",
            "lateral_movement", "credential_harvest"
        ],
        "description": "数据提取、权限提升、横向移动"
    }
}

# ============================================================================
# 上下文特征 → 场景映射（供 GraphRAG 使用）
# ============================================================================

CONTEXT_TO_SCENARIO = {
    # ========== 表单相关 ==========
    "has_forms": ["form_analysis", "param_injection", "sqli_test", "xss_test"],
    "has_login_form": ["auth_test", "sqli_test", "bruteforce", "default_creds"],
    "has_file_upload": ["upload_test", "rce_test", "webshell_upload"],
    "has_search_box": ["xss_test", "sqli_test", "ssti_test"],
    "has_comment_form": ["xss_test", "stored_xss"],
    "has_contact_form": ["xss_test", "email_injection"],
    
    # ========== 参数相关 ==========
    "has_get_params": ["param_injection", "sqli_test", "xss_test", "lfi_test"],
    "has_post_params": ["param_injection", "sqli_test", "xss_test"],
    "has_id_param": ["sqli_test", "idor_test", "insecure_direct_object"],
    "has_file_param": ["lfi_test", "rfi_test", "path_traversal"],
    "has_url_param": ["ssrf_test", "open_redirect_test"],
    "has_cmd_param": ["rce_test", "command_injection"],
    "has_template_param": ["ssti_test", "template_injection"],
    "has_xml_input": ["xxe_test", "xml_injection"],
    "has_json_input": ["json_injection", "mass_assignment"],
    
    # ========== 技术栈相关 ==========
    "php_backend": ["php_vuln", "lfi_test", "rce_test", "type_juggling"],
    "java_backend": ["deserialization_test", "ssti_test", "log4j_test"],
    "python_backend": ["ssti_test", "pickle_deserialization"],
    "nodejs_backend": ["prototype_pollution", "ssti_test", "ssrf_test"],
    "aspnet_backend": ["viewstate_test", "deserialization_test"],
    "ruby_backend": ["erb_ssti", "deserialization_test"],
    
    # ========== CMS相关 ==========
    "cms_wordpress": ["wp_vuln", "wp_plugin_vuln", "wp_theme_vuln"],
    "cms_drupal": ["drupal_vuln", "drupalgeddon"],
    "cms_joomla": ["joomla_vuln", "joomla_sqli"],
    "cms_magento": ["magento_vuln"],
    
    # ========== API相关 ==========
    "is_api": ["api_test", "auth_bypass", "rate_limit_test", "mass_assignment"],
    "has_graphql": ["graphql_introspection", "graphql_injection"],
    "has_rest_api": ["api_enum", "broken_auth", "bola_test"],
    "has_swagger": ["swagger_leak", "api_doc_exposure"],
    
    # ========== 认证相关 ==========
    "is_authenticated": ["post_auth_test", "privilege_test", "idor_test"],
    "has_jwt": ["jwt_attack", "jwt_none_alg", "jwt_weak_secret"],
    "has_session": ["session_fixation", "session_hijack"],
    "has_oauth": ["oauth_misconfiguration", "token_leak"],
    "has_remember_me": ["persistent_auth_test"],
    
    # ========== 敏感信息相关 ==========
    "has_sensitive_files": ["info_disclosure", "backup_file", "config_exposure"],
    "has_git_exposed": ["git_dump", "source_code_leak"],
    "has_debug_enabled": ["debug_info_leak", "stack_trace_leak"],
    "has_error_messages": ["error_based_sqli", "info_disclosure"],
    
    # ========== 安全头相关 ==========
    "missing_csp": ["xss_test", "clickjacking"],
    "missing_hsts": ["ssl_strip", "mitm_test"],
    "cors_misconfigured": ["cors_test", "credential_theft"],
}

# 参数名称 → 漏洞类型映射（用于快速提示）

# 参数名称 → 漏洞类型映射
PARAM_VULN_HINTS = {
    # SQL注入相关
    "id": "sqli", "uid": "sqli", "pid": "sqli", "catid": "sqli",
    "articleid": "sqli", "newsid": "sqli", "userid": "sqli",
    "productid": "sqli", "item": "sqli", "category": "sqli",
    
    # XSS相关
    "search": "xss", "q": "xss", "query": "xss", "keyword": "xss",
    "s": "xss", "term": "xss", "name": "xss", "message": "xss",
    "comment": "xss", "content": "xss", "title": "xss",
    
    # LFI/RFI相关
    "file": "lfi", "path": "lfi", "page": "lfi", "include": "lfi",
    "template": "lfi", "doc": "lfi", "document": "lfi", "folder": "lfi",
    "root": "lfi", "dir": "lfi", "load": "lfi", "read": "lfi",
    
    # SSRF相关
    "url": "ssrf", "redirect": "ssrf", "next": "ssrf", "return": "ssrf",
    "goto": "ssrf", "link": "ssrf", "target": "ssrf", "dest": "ssrf",
    "destination": "ssrf", "uri": "ssrf", "continue": "ssrf",
    
    # 命令注入相关
    "cmd": "rce", "command": "rce", "exec": "rce", "execute": "rce",
    "ping": "rce", "host": "rce", "ip": "rce",
}


# ============================================================================
# 阶段推进规则
# ============================================================================

class PhaseTransitionRules:
    """阶段推进规则"""
    
    @staticmethod
    def should_advance(context: WebPentestContext) -> Tuple[bool, str]:
        """判断是否应该推进到下一阶段，返回(是否推进, 新阶段)"""
        
        phase = context.current_phase
        
        # RECON → DISCOVERY
        if phase == "recon":
            if context.technology_stack or context.services or context.open_ports:
                return True, "discovery"
            return False, phase
        
        # DISCOVERY → PARAMETER_ANALYSIS
        elif phase == "discovery":
            if context.discovered_urls or context.discovered_forms or context.discovered_endpoints:
                return True, "parameter_analysis"
            return False, phase
        
        # PARAMETER_ANALYSIS → VULNERABILITY_SCAN
        elif phase == "parameter_analysis":
            if context.injectable_params:
                return True, "vulnerability_scan"
            # 即使没发现参数，也可以进行通用漏洞扫描
            if context.discovered_urls or context.discovered_forms:
                return True, "vulnerability_scan"
            return False, phase
        
        # VULNERABILITY_SCAN → EXPLOITATION
        elif phase == "vulnerability_scan":
            if context.suspected_vulns:
                return True, "exploitation"
            return False, phase
        
        # EXPLOITATION → POST_EXPLOITATION
        elif phase == "exploitation":
            if context.shell_access or context.confirmed_vulns:
                return True, "post_exploitation"
            return False, phase
        
        return False, phase
    
    @staticmethod
    def can_skip_to(context: WebPentestContext, target_phase: str) -> bool:
        """判断是否可以跳过到指定阶段"""
        phase_order = ["recon", "discovery", "parameter_analysis", 
                      "vulnerability_scan", "exploitation", "post_exploitation"]
        
        current_idx = phase_order.index(context.current_phase)
        target_idx = phase_order.index(target_phase)
        
        # 只能向前跳，不能向后
        return target_idx > current_idx


# ============================================================================
# 上下文更新器
# ============================================================================

class ContextUpdater:
    """上下文更新器 - 根据工具返回结果更新上下文"""
    
    @staticmethod
    def update(context: WebPentestContext, tool_name: str, result: Dict[str, Any]) -> None:
        """更新上下文"""
        
        if not result.get("success", True):
            return
        
        # ========== RECON阶段工具 ==========
        if tool_name in ["nmap_scan"]:
            ports = result.get("open_ports", [])
            if ports:
                context.open_ports.extend(ports)
            services = result.get("services", {})
            if services:
                context.services.update(services)
        
        elif tool_name in ["whatweb_scan", "wappalyzer_scan"]:
            tech = result.get("technologies", [])
            if tech:
                context.technology_stack.extend(tech)
            cms = result.get("cms", "")
            if cms:
                context.cms_detected = cms
        
        # ========== DISCOVERY阶段工具 ==========
        elif tool_name == "browser_visit_page":
            forms = result.get("forms", [])
            if forms:
                context.discovered_forms.extend(forms)
                
                # 【增强】提取表单参数到 injectable_params
                for form in forms:
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    inputs = form.get("inputs", [])
                    
                    # 构建表单URL
                    if action:
                        if action.startswith(("http://", "https://")):
                            form_url = action
                        else:
                            # 相对路径，拼接基础URL
                            from urllib.parse import urljoin
                            form_url = urljoin(context.target_url, action)
                    else:
                        form_url = context.target_url
                    
                    # 分析表单输入
                    input_names = []
                    for inp in inputs:
                        inp_name = inp.get("name", "")
                        inp_type = inp.get("type", "text").lower()
                        
                        if inp_name:
                            input_names.append(inp_name.lower())
                            
                            # 跳过提交按钮
                            if inp_type in ["submit", "button", "image", "reset"]:
                                continue
                            
                            # 添加到 injectable_params
                            context.injectable_params.append({
                                "url": form_url,
                                "param": inp_name,
                                "method": method,
                                "source": "form",
                                "input_type": inp_type,
                                "hint": PARAM_VULN_HINTS.get(inp_name.lower(), "")
                            })
                    
                    # 检测登录表单
                    login_fields = ["username", "uname", "user", "login", "email", "account"]
                    password_fields = ["password", "psw", "pwd", "pass", "passwd"]
                    if any(n in input_names for n in login_fields):
                        if any(n in input_names for n in password_fields):
                            context.has_login_page = True
                    
                    # 检测搜索表单
                    search_fields = ["search", "q", "query", "keyword", "s", "term"]
                    if any(n in input_names for n in search_fields):
                        context.has_search_function = True
                    
                    # 检测文件上传
                    if any(inp.get("type", "").lower() == "file" for inp in inputs):
                        context.has_file_upload = True
                    
                    context.has_user_input = True
            
            # 检测登录页面（通过URL）
            final_url = result.get("final_url", "").lower()
            if result.get("has_login_form") or "login" in final_url or "signin" in final_url:
                context.has_login_page = True
            
            # 提取技术栈
            tech = result.get("technology_stack", [])
            if tech:
                context.technology_stack.extend(tech)
            
            # 【新增】提取页面中的链接参数
            links = result.get("links", [])
        
        # 【新增】execute_browser_js 工具处理
        elif tool_name == "execute_browser_js":
            # JavaScript 执行结果可能包含 API 响应、数据等
            js_result = result.get("result")
            
            # 如果结果是字典（API 响应），可能包含有用信息
            if isinstance(js_result, dict):
                # 检查是否包含 flag、secret 等关键信息
                if "flag" in js_result or "secret" in js_result:
                    context.extracted_data.append({
                        "type": "js_execution",
                        "data": js_result,
                        "source": "browser_js"
                    })
                
                # 检查是否包含错误信息（可能暴露技术栈）
                if "error" in js_result or "message" in js_result:
                    error_msg = str(js_result.get("error") or js_result.get("message", ""))
                    # 从错误信息中提取技术栈
                    if "php" in error_msg.lower():
                        context.technology_stack.append("PHP")
                    elif "python" in error_msg.lower() or "django" in error_msg.lower():
                        context.technology_stack.append("Python")
                    elif "node" in error_msg.lower() or "express" in error_msg.lower():
                        context.technology_stack.append("Node.js")
            
            # 标记已使用浏览器环境
            context.has_user_input = True
        
        # 【新增】browser_get_rendered_content 工具处理
        elif tool_name == "browser_get_rendered_content":
            # 渲染后的内容可能包含动态生成的表单、链接等
            html = result.get("html", "")
            text = result.get("text", "")
            
            # 简单检测：如果文本中包含特定关键词，更新上下文
            text_lower = text.lower()
            
            # 检测登录相关
            if any(keyword in text_lower for keyword in ["login", "sign in", "username", "password"]):
                context.has_login_page = True
            
            # 检测搜索功能
            if any(keyword in text_lower for keyword in ["search", "query", "find"]):
                context.has_search_function = True
            
            # 检测文件上传
            if any(keyword in text_lower for keyword in ["upload", "file", "attach"]):
                context.has_file_upload = True
            
            # 检测 API 端点（从文本中提取）
            import re
            api_patterns = [
                r'/api/[a-zA-Z0-9_/]+',
                r'/v\d+/[a-zA-Z0-9_/]+',
                r'\.json',
                r'/graphql'
            ]
            for pattern in api_patterns:
                if re.search(pattern, text):
                    context.discovered_endpoints.append({
                        "url": result.get("url", ""),
                        "type": "api",
                        "source": "rendered_content"
                    })
                    break
            for link in links:
                if "?" in link:
                    try:
                        parsed = urlparse(link)
                        params = parse_qs(parsed.query)
                        for param_name in params.keys():
                            context.injectable_params.append({
                                "url": link,
                                "param": param_name,
                                "method": "GET",
                                "source": "link",
                                "hint": PARAM_VULN_HINTS.get(param_name.lower(), "")
                            })
                    except Exception:
                        pass
        
        elif tool_name in ["crawl_site_endpoints", "gobuster_scan", "feroxbuster_scan"]:
            urls = result.get("discovered_urls", []) or result.get("found_paths", [])
            if urls:
                context.discovered_urls.extend(urls)
            
            # 自动提取带参数的URL
            for url in urls:
                if "?" in url:
                    try:
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        for param_name in params.keys():
                            context.injectable_params.append({
                                "url": url,
                                "param": param_name,
                                "method": "GET",
                                "source": "crawl",
                                "hint": PARAM_VULN_HINTS.get(param_name.lower(), "")
                            })
                    except Exception:
                        pass
            
            # 检测敏感文件
            sensitive_patterns = [".git", ".svn", "robots.txt", ".env", 
                                 "config.php", "web.config", ".htaccess",
                                 "backup", ".bak", ".sql", "phpinfo",
                                 ".DS_Store", "wp-config", "database"]
            for url in urls:
                url_lower = url.lower()
                if any(s in url_lower for s in sensitive_patterns):
                    context.sensitive_files.append(url)
        
        # ========== PARAMETER_ANALYSIS阶段工具 ==========
        elif tool_name in ["discover_injectable_params", "arjun_scan", "param_miner"]:
            params = result.get("injectable_params", []) or result.get("params", [])
            if params:
                context.injectable_params.extend(params)
        
        # ========== VULNERABILITY_SCAN阶段工具 ==========
        elif tool_name in ["nuclei_scan", "intelligent_quick_test", "nikto_scan"]:
            vulns = result.get("vulnerabilities", [])
            
            # 处理单个漏洞结果
            if result.get("vulnerable"):
                vulns.append({
                    "type": result.get("vuln_type", "unknown"),
                    "url": result.get("url", context.target_url),
                    "param": result.get("param", ""),
                    "confidence": result.get("confidence", 0.5),
                    "evidence": result.get("evidence", ""),
                    "payload": result.get("payload", "") or result.get("successful_payload", "")
                })
            
            if vulns:
                context.suspected_vulns.extend(vulns)
        
        # ========== EXPLOITATION阶段工具 ==========
        elif tool_name == "sqlmap_scan":
            if result.get("vulnerable") or result.get("injection_found"):
                context.confirmed_vulns.append({
                    "type": "sqli",
                    "url": result.get("url", context.target_url),
                    "payload": result.get("payload", ""),
                    "dbms": result.get("dbms", "")
                })
                
                # 提取的数据
                if result.get("databases"):
                    context.extracted_data.append({
                        "type": "databases",
                        "data": result.get("databases")
                    })
        
        elif tool_name == "smart_login_attempt":
            if result.get("success"):
                context.is_authenticated = True
                context.session_cookies = result.get("cookies", {})
                context.auth_user = result.get("username", "")
                context.credentials_found.append({
                    "username": result.get("username"),
                    "password": result.get("password"),
                    "url": result.get("url", context.target_url)
                })
    
    @staticmethod
    def extract_context_features(context: WebPentestContext) -> List[str]:
        """从上下文提取特征列表（供 GraphRAG 使用）"""
        features = []
        
        # 表单相关
        if context.discovered_forms:
            features.append("has_forms")
        if context.has_login_page:
            features.append("has_login_form")
        if context.has_file_upload:
            features.append("has_file_upload")
        if context.has_search_function:
            features.append("has_search_box")
        
        # 参数相关
        if context.injectable_params:
            get_params = [p for p in context.injectable_params if p.get("method") == "GET"]
            post_params = [p for p in context.injectable_params if p.get("method") == "POST"]
            
            if get_params:
                features.append("has_get_params")
            if post_params:
                features.append("has_post_params")
            
            # 检查特定参数名
            param_names = [p.get("param", "").lower() for p in context.injectable_params]
            if any(n in param_names for n in ["id", "uid", "pid", "catid", "articleid"]):
                features.append("has_id_param")
            if any(n in param_names for n in ["file", "path", "page", "include", "doc"]):
                features.append("has_file_param")
            if any(n in param_names for n in ["url", "redirect", "next", "goto", "link"]):
                features.append("has_url_param")
            if any(n in param_names for n in ["cmd", "command", "exec", "ping"]):
                features.append("has_cmd_param")
        
        # 技术栈相关
        tech_lower = [t.lower() for t in context.technology_stack]
        if any("php" in t for t in tech_lower):
            features.append("php_backend")
        if any("java" in t or "jsp" in t or "spring" in t for t in tech_lower):
            features.append("java_backend")
        if any("python" in t or "django" in t or "flask" in t for t in tech_lower):
            features.append("python_backend")
        if any("node" in t or "express" in t for t in tech_lower):
            features.append("nodejs_backend")
        if any("asp" in t or ".net" in t for t in tech_lower):
            features.append("aspnet_backend")
        
        # CMS相关
        cms_lower = context.cms_detected.lower()
        if "wordpress" in cms_lower:
            features.append("cms_wordpress")
        if "drupal" in cms_lower:
            features.append("cms_drupal")
        if "joomla" in cms_lower:
            features.append("cms_joomla")
        
        # API相关
        if context.input_type == InputType.API_ENDPOINT:
            features.append("is_api")
        if any("/api/" in u or "/graphql" in u for u in context.discovered_urls):
            features.append("is_api")
        
        # 认证相关
        if context.is_authenticated:
            features.append("is_authenticated")
        if context.session_cookies:
            features.append("has_session")
        
        # 敏感文件
        if context.sensitive_files:
            features.append("has_sensitive_files")
            if any(".git" in f for f in context.sensitive_files):
                features.append("has_git_exposed")
        
        return features
    
    @staticmethod
    def update_vuln_test_status(context: WebPentestContext, tool_name: str, result: Dict[str, Any]) -> None:
        """更新漏洞测试状态
        
        根据工具执行结果，更新对应漏洞类型的测试状态。
        让LLM知道哪些漏洞类型已经测试过了。
        
        【关键】区分三种情况：
        1. 执行失败（error/return_code!=0）→ 不更新状态，保持pending
        2. 执行成功且发现漏洞 → 标记为found
        3. 执行成功但未发现漏洞 → 标记为not_found
        """
        
        # 【关键修复】先检查是否执行成功
        # 如果执行失败，不更新状态（保持pending，让LLM可以重试）
        if result.get("error") or result.get("return_code", 0) != 0:
            # 执行失败，不更新状态
            return
        
        # 检查是否有有效的输出（防止空结果被误判为"未发现"）
        stdout = result.get("stdout", "")
        if not stdout and not result.get("success", True):
            # 没有输出且不成功，视为执行失败
            return
        
        # 工具 → 漏洞类型映射
        TOOL_VULN_MAP = {
            # SQL注入
            "sqlmap_scan": "sqli",
            "sqli_scanner": "sqli",
            # XSS
            "dalfox_scan": "xss",
            "xss_scanner": "xss",
            # 命令注入
            "commix_scan": "rce",
            "rce_scanner": "rce",
            # 文件包含
            "lfi_scanner": "lfi",
            "rfi_scanner": "rfi",
            # SSRF
            "ssrf_scanner": "ssrf",
            # XXE
            "xxe_scanner": "xxe",
            # 模板注入
            "tplmap_scan": "ssti",
            # 认证相关
            "auth_bypass_test": "auth_bypass",
            "idor_scanner": "idor",
            "jwt_tool": "jwt",
            # 文件上传
            "upload_scanner": "file_upload",
            # 通用扫描
            "nuclei_scan": None,  # nuclei可以测多种，不标记特定类型
            "nikto_scan": None,
        }
        
        # intelligent_quick_test 根据参数确定类型
        if tool_name == "intelligent_quick_test":
            vuln_type = result.get("vuln_type", "").lower()
            if vuln_type:
                TOOL_VULN_MAP["intelligent_quick_test"] = vuln_type
        
        vuln_type = TOOL_VULN_MAP.get(tool_name)
        if not vuln_type:
            return
        
        # 【sqlmap特殊处理】检查输出中是否包含注入成功的标志
        if tool_name == "sqlmap_scan":
            # 优先检查服务端返回的结构化字段
            if result.get("vulnerable") == True:
                context.vuln_test_status[vuln_type] = "found"
                return
            
            # sqlmap成功发现注入时会输出这些关键词
            injection_indicators = [
                "is vulnerable",
                "injectable",
                "Parameter:",
                "Type: ",
                "Payload:",
                "sqlmap identified the following injection",
                "the back-end DBMS is"
            ]
            if any(indicator in stdout for indicator in injection_indicators):
                context.vuln_test_status[vuln_type] = "found"
                return
            
            # 明确没发现
            if "do not appear to be injectable" in stdout.lower():
                context.vuln_test_status[vuln_type] = "not_found"
                return
        
        if result.get("vulnerable") or result.get("injection_found"):
            # 发现漏洞
            context.vuln_test_status[vuln_type] = "found"
        else:
            # 未发现，只有pending状态才更新为not_found
            current_status = context.vuln_test_status.get(vuln_type, "pending")
            if current_status == "pending":
                context.vuln_test_status[vuln_type] = "not_found"


# ============================================================================
# 工具推荐数据类
# ============================================================================

@dataclass
class PhaseToolRecommendation:
    """阶段感知工具推荐"""
    tool_name: str
    score: float
    reasons: List[str]
    phase: str
    priority: int = 5


# ============================================================================
# 动态阶段感知工具选择器
# ============================================================================

class PhaseAwareToolSelector:
    """动态阶段感知工具选择器
    
    职责：
    1. 识别输入类型 → 确定起始阶段
    2. 维护动态上下文 → 记录发现的信息
    3. 判断阶段推进 → 控制测试流程
    4. 输出阶段意图 → 告诉 GraphRAG "当前应该做什么类型的事"
    
    不再直接推荐具体工具，而是输出阶段意图供 GraphRAG 使用
    """
    
    def __init__(self):
        self.input_detector = InputTypeDetector()
        self.phase_intent_mapping = PHASE_INTENT_MAPPING
        self.context_to_scenario = CONTEXT_TO_SCENARIO
        self.param_vuln_hints = PARAM_VULN_HINTS
    
    def initialize_context(self, user_input: str) -> WebPentestContext:
        """根据输入初始化上下文，智能确定起始阶段"""
        
        # 识别输入类型
        input_type, start_phase = self.input_detector.detect(user_input)
        
        # 解析URL获取域名
        target_domain = ""
        try:
            if user_input.startswith(('http://', 'https://')):
                parsed = urlparse(user_input)
                target_domain = parsed.netloc
        except Exception:
            pass
        
        # 创建上下文
        context = WebPentestContext(
            target_url=user_input,
            target_domain=target_domain,
            current_phase=start_phase,
            input_type=input_type
        )
        
        # 根据输入类型预填充信息
        if input_type == InputType.URL_WITH_PARAMS:
            try:
                parsed = urlparse(user_input)
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    context.injectable_params.append({
                        "url": user_input,
                        "param": param_name,
                        "method": "GET",
                        "source": "url",
                        "hint": self.param_vuln_hints.get(param_name.lower(), "")
                    })
            except Exception:
                pass
        
        return context
    
    def get_phase_intent(self, context: WebPentestContext) -> Dict[str, Any]:
        """获取当前阶段的意图（供 GraphRAG 使用）"""
        phase = context.current_phase
        intent_config = self.phase_intent_mapping.get(phase, {})
        
        # 基础场景（来自阶段配置）
        base_scenarios = intent_config.get("scenarios", [])
        
        # 上下文特征
        context_features = ContextUpdater.extract_context_features(context)
        
        # 上下文特征 → 额外场景
        extra_scenarios = []
        for feature in context_features:
            scenarios = self.context_to_scenario.get(feature, [])
            extra_scenarios.extend(scenarios)
        
        # 合并并去重
        all_scenarios = list(set(base_scenarios + extra_scenarios))
        
        return {
            "phase": phase,
            "intent": intent_config.get("intent", ""),
            "description": intent_config.get("description", ""),
            "scenarios": all_scenarios,
            "context_features": context_features,
            "injectable_params_count": len(context.injectable_params),
            "discovered_forms_count": len(context.discovered_forms),
            "suspected_vulns_count": len(context.suspected_vulns),
        }
    
    def select_tools(self, context: WebPentestContext, 
                    max_tools: int = 20) -> List[PhaseToolRecommendation]:
        """根据当前阶段和上下文选择工具
        
        【兼容旧接口】当只使用 Phase-Aware 时，提供基础工具推荐
        当与 GraphRAG 协作时，应使用 get_phase_intent() 获取意图
        """
        phase = context.current_phase
        recommendations = []
        
        # 获取阶段意图
        phase_intent = self.get_phase_intent(context)
        
        # ============================================================
        # 【关键改进】阶段优先级工具（最高分）
        # ============================================================
        PHASE_PRIORITY_TOOLS = {
            "discovery": [
                # Discovery 阶段：先访问页面，再扫目录
                ("browser_visit_page", 20.0, "Discovery首选：先访问页面查看结构"),
                ("view_source_code", 15.0, "查看页面源码"),
                ("crawl_site_endpoints", 12.0, "爬取站点端点"),
                ("gobuster_scan", 8.0, "目录扫描"),
                ("dirb_scan", 8.0, "目录扫描"),
            ],
            "vulnerability_scan": [
                ("sqlmap_scan", 20.0, "SQL注入检测首选"),
                ("intelligent_quick_test", 18.0, "智能快速测试"),
                ("nuclei_scan", 15.0, "通用漏洞扫描"),
                ("nikto_scan", 12.0, "Web漏洞扫描"),
            ],
            "parameter_analysis": [
                ("discover_injectable_params", 18.0, "参数发现"),
                ("arjun_scan", 15.0, "参数发现"),
            ],
            "exploitation": [
                ("sqlmap_scan", 20.0, "SQL注入利用"),
                ("commix_scan", 18.0, "命令注入利用"),
                ("tplmap_scan", 15.0, "模板注入利用"),
            ],
            "recon": [
                ("nmap_scan", 18.0, "端口扫描"),
                ("whatweb_scan", 15.0, "技术栈识别"),
                ("subfinder_scan", 12.0, "子域名枚举"),
            ],
            "post_exploitation": [
                ("data_extractor", 15.0, "数据提取"),
            ],
        }
        
        # 应用阶段优先级工具
        priority_tools = PHASE_PRIORITY_TOOLS.get(phase, [])
        for tool_name, score, reason in priority_tools:
            recommendations.append(PhaseToolRecommendation(
                tool_name=tool_name,
                score=score,
                reasons=[reason],
                phase=phase,
                priority=int(score)
            ))
        
        # 根据上下文特征添加工具
        context_features = phase_intent.get("context_features", [])
        
        # 特征 → 工具映射（带分数）
        FEATURE_TOOL_MAPPING = {
            "has_login_form": [
                ("sqlmap_scan", 18.0), ("hydra_scan", 12.0), ("smart_login_attempt", 15.0)
            ],
            "has_post_params": [
                ("sqlmap_scan", 18.0), ("xss_scanner", 12.0)
            ],
            "has_get_params": [
                ("sqlmap_scan", 15.0), ("xss_scanner", 12.0), ("lfi_scanner", 10.0)
            ],
            "has_forms": [
                ("sqlmap_scan", 15.0), ("xss_scanner", 12.0)
            ],
            "has_file_upload": [
                ("upload_scanner", 15.0), ("webshell_upload", 12.0)
            ],
            "has_search_box": [
                ("xss_scanner", 15.0), ("sqli_scanner", 12.0)
            ],
            "has_id_param": [
                ("sqlmap_scan", 18.0), ("idor_scanner", 12.0)
            ],
            "has_file_param": [
                ("lfi_scanner", 15.0), ("rfi_scanner", 12.0)
            ],
            "has_url_param": [
                ("ssrf_scanner", 15.0), ("redirect_scanner", 12.0)
            ],
            "cms_wordpress": [("wpscan", 18.0)],
            "cms_drupal": [("droopescan", 15.0)],
            "cms_joomla": [("joomscan", 15.0)],
            "php_backend": [("lfi_scanner", 12.0), ("rce_scanner", 10.0)],
            "java_backend": [("deserialization_scanner", 12.0)],
            "is_api": [("api_scanner", 15.0), ("jwt_scanner", 12.0)],
            "has_sensitive_files": [("git_dumper", 15.0), ("backup_scanner", 12.0)],
        }
        
        for feature in context_features:
            tools = FEATURE_TOOL_MAPPING.get(feature, [])
            for tool_name, score in tools:
                recommendations.append(PhaseToolRecommendation(
                    tool_name=tool_name,
                    score=score,
                    reasons=[f"上下文特征: {feature}"],
                    phase=phase,
                    priority=int(score)
                ))
        
        # 去重并排序
        seen = set()
        unique_recommendations = []
        for rec in sorted(recommendations, key=lambda x: -x.score):
            if rec.tool_name not in seen:
                seen.add(rec.tool_name)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:max_tools]
    
    def get_phase_info(self, context: WebPentestContext) -> Dict[str, Any]:
        """获取当前阶段信息（用于显示）"""
        phase_intent = self.get_phase_intent(context)
        return {
            "current_phase": context.current_phase,
            "input_type": context.input_type.value,
            "phase_history": context.phase_history,
            "phase_intent": phase_intent.get("intent", ""),
            "scenarios": phase_intent.get("scenarios", [])[:10],
            "context_features": phase_intent.get("context_features", []),
            "discovered_urls_count": len(context.discovered_urls),
            "discovered_forms_count": len(context.discovered_forms),
            "injectable_params_count": len(context.injectable_params),
            "suspected_vulns_count": len(context.suspected_vulns),
            "confirmed_vulns_count": len(context.confirmed_vulns),
            "is_authenticated": context.is_authenticated,
        }


# ============================================================================
# 便捷函数
# ============================================================================

_global_phase_selector: Optional[PhaseAwareToolSelector] = None


def get_phase_selector() -> PhaseAwareToolSelector:
    """获取全局阶段感知选择器实例"""
    global _global_phase_selector
    if _global_phase_selector is None:
        _global_phase_selector = PhaseAwareToolSelector()
    return _global_phase_selector


def create_pentest_context(target: str) -> WebPentestContext:
    """创建渗透测试上下文"""
    selector = get_phase_selector()
    return selector.initialize_context(target)


def select_phase_tools(context: WebPentestContext, 
                      max_tools: int = 20) -> List[PhaseToolRecommendation]:
    """为当前阶段选择工具（独立模式）"""
    selector = get_phase_selector()
    return selector.select_tools(context, max_tools)


def get_phase_intent(context: WebPentestContext) -> Dict[str, Any]:
    """获取当前阶段意图（供 GraphRAG 协作使用）"""
    selector = get_phase_selector()
    return selector.get_phase_intent(context)


def extract_context_features(context: WebPentestContext) -> List[str]:
    """从上下文提取特征列表"""
    return ContextUpdater.extract_context_features(context)


def update_context(context: WebPentestContext, 
                  tool_name: str, result: Dict[str, Any]) -> None:
    """更新上下文"""
    ContextUpdater.update(context, tool_name, result)


def check_phase_transition(context: WebPentestContext) -> Tuple[bool, str]:
    """检查是否需要阶段推进"""
    return PhaseTransitionRules.should_advance(context)


def advance_phase(context: WebPentestContext, new_phase: str) -> None:
    """推进到新阶段"""
    context.phase_history.append(context.current_phase)
    context.current_phase = new_phase


def filter_tools_by_phase_recommendations(
    tools: List[Dict[str, Any]], 
    recommendations: List[PhaseToolRecommendation]
) -> List[Dict[str, Any]]:
    """根据阶段推荐过滤OpenAI格式工具列表"""
    recommended_names = {r.tool_name for r in recommendations}
    
    filtered = []
    for tool in tools:
        func = tool.get('function', {})
        name = func.get('name', '')
        if name in recommended_names:
            filtered.append(tool)
    
    # 按推荐分数排序
    name_to_score = {r.tool_name: r.score for r in recommendations}
    filtered.sort(key=lambda t: -name_to_score.get(
        t.get('function', {}).get('name', ''), 0
    ))
    
    return filtered
