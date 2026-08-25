"""
HexStrike GraphRAG - 完整的工具知识图谱

包含160+安全工具的完整映射，建立工具与场景、目标、阶段之间的详细关系。
用于智能工具选择和推荐。
"""

from __future__ import annotations

from .graph_schema import (
    ToolGraph, ToolNode, ScenarioNode, TargetNode, PhaseNode, ToolEdge,
    RelationType, Phase, TargetType, Scenario
)


def build_hexstrike_tool_graph() -> ToolGraph:
    """构建完整的HexStrike工具知识图谱"""
    graph = ToolGraph()
    
    # ========================================================================
    # 1. 添加阶段节点
    # ========================================================================
    _add_phases(graph)
    
    # ========================================================================
    # 2. 添加目标类型节点
    # ========================================================================
    _add_targets(graph)
    
    # ========================================================================
    # 3. 添加场景节点
    # ========================================================================
    _add_scenarios(graph)
    
    # ========================================================================
    # 4. 添加所有工具节点
    # ========================================================================
    _add_all_tools(graph)
    
    # ========================================================================
    # 5. 建立工具-场景关系
    # ========================================================================
    _add_tool_scenario_edges(graph)
    
    # ========================================================================
    # 6. 建立工具-目标关系
    # ========================================================================
    _add_tool_target_edges(graph)
    
    # ========================================================================
    # 7. 建立工具-阶段关系
    # ========================================================================
    _add_tool_phase_edges(graph)
    
    # ========================================================================
    # 8. 建立工具执行顺序关系
    # ========================================================================
    _add_tool_flow_edges(graph)
    
    # ========================================================================
    # 9. 建立工具替代关系
    # ========================================================================
    _add_tool_alternative_edges(graph)
    
    return graph


def _add_phases(graph: ToolGraph) -> None:
    """添加渗透测试阶段"""
    phases = [
        PhaseNode("recon", 1, "侦察阶段 - 收集目标信息、子域名、技术栈等"),
        PhaseNode("discovery", 2, "发现阶段 - 目录扫描、参数发现、端点枚举"),
        PhaseNode("vuln_scan", 3, "漏洞扫描 - 自动化漏洞检测和验证"),
        PhaseNode("exploitation", 4, "利用阶段 - 漏洞利用和攻击执行"),
        PhaseNode("post_exploit", 5, "后渗透 - 权限维持、横向移动、数据提取"),
        PhaseNode("reporting", 6, "报告阶段 - 结果汇总和报告生成"),
    ]
    for phase in phases:
        graph.add_phase(phase)


def _add_targets(graph: ToolGraph) -> None:
    """添加目标类型"""
    targets = [
        TargetNode("web_application", "Web应用程序", {"http", "https", "html", "php", "asp", "jsp"}),
        TargetNode("api_endpoint", "API接口", {"api", "rest", "json", "xml", "endpoint"}),
        TargetNode("network_host", "网络主机", {"ip", "host", "server", "port"}),
        TargetNode("database", "数据库", {"mysql", "postgresql", "mssql", "oracle", "mongodb"}),
        TargetNode("cloud_service", "云服务", {"aws", "azure", "gcp", "cloud", "s3", "ec2"}),
        TargetNode("container", "容器", {"docker", "container", "image"}),
        TargetNode("kubernetes", "Kubernetes集群", {"k8s", "kubernetes", "pod", "cluster"}),
        TargetNode("binary_executable", "二进制程序", {"elf", "exe", "binary", "executable"}),
        TargetNode("memory_dump", "内存转储", {"memory", "dump", "forensics", "ram"}),
        TargetNode("smb_share", "SMB共享", {"smb", "cifs", "share", "445"}),
        TargetNode("dns_server", "DNS服务器", {"dns", "domain", "nameserver"}),
        TargetNode("wordpress_site", "WordPress站点", {"wordpress", "wp-", "wp-admin"}),
        TargetNode("login_page", "登录页面", {"login", "signin", "auth", "password"}),
        TargetNode("file_system", "文件系统", {"file", "directory", "path"}),
        TargetNode("graphql_api", "GraphQL API", {"graphql", "query", "mutation"}),
        TargetNode("jwt_token", "JWT令牌", {"jwt", "token", "bearer"}),
    ]
    for target in targets:
        graph.add_target(target)


def _add_scenarios(graph: ToolGraph) -> None:
    """添加攻击场景"""
    scenarios = [
        # Web漏洞场景
        ScenarioNode("sql_injection", "SQL注入攻击", 
                    {"sqli", "sql", "injection", "database", "query", "union", "select"},
                    ["discovery", "vuln_scan", "exploitation"], "critical"),
        ScenarioNode("xss_attack", "跨站脚本攻击",
                    {"xss", "script", "alert", "javascript", "dom", "reflected", "stored"},
                    ["discovery", "vuln_scan"], "high"),
        ScenarioNode("lfi_rfi", "本地/远程文件包含",
                    {"lfi", "rfi", "include", "file", "path", "traversal", "../"},
                    ["discovery", "vuln_scan", "exploitation"], "critical"),
        ScenarioNode("command_injection", "命令注入",
                    {"cmd", "command", "injection", "rce", "shell", "exec", "system"},
                    ["vuln_scan", "exploitation"], "critical"),
        ScenarioNode("ssrf", "服务端请求伪造",
                    {"ssrf", "request", "forgery", "internal", "localhost"},
                    ["vuln_scan", "exploitation"], "high"),
        ScenarioNode("xxe", "XML外部实体注入",
                    {"xxe", "xml", "entity", "dtd", "external"},
                    ["vuln_scan", "exploitation"], "high"),
        ScenarioNode("ssti", "服务端模板注入",
                    {"ssti", "template", "jinja", "twig", "freemarker"},
                    ["vuln_scan", "exploitation"], "critical"),
        ScenarioNode("open_redirect", "开放重定向",
                    {"redirect", "url", "open", "location"},
                    ["discovery", "vuln_scan"], "medium"),
        ScenarioNode("file_upload", "文件上传漏洞",
                    {"upload", "file", "webshell", "extension"},
                    ["vuln_scan", "exploitation"], "critical"),
        ScenarioNode("path_traversal", "路径遍历",
                    {"traversal", "path", "../", "directory"},
                    ["discovery", "vuln_scan"], "high"),
        
        # 认证场景
        ScenarioNode("auth_bypass", "认证绕过",
                    {"auth", "bypass", "login", "authentication", "session"},
                    ["discovery", "exploitation"], "critical"),
        ScenarioNode("brute_force", "暴力破解",
                    {"brute", "force", "password", "crack", "dictionary"},
                    ["exploitation"], "medium"),
        ScenarioNode("session_hijack", "会话劫持",
                    {"session", "cookie", "hijack", "token"},
                    ["exploitation"], "high"),
        ScenarioNode("jwt_attack", "JWT攻击",
                    {"jwt", "token", "algorithm", "none", "hs256", "rs256"},
                    ["vuln_scan", "exploitation"], "high"),
        ScenarioNode("password_crack", "密码破解",
                    {"password", "hash", "crack", "rainbow", "wordlist"},
                    ["exploitation"], "medium"),
        
        # 网络场景
        ScenarioNode("port_scan", "端口扫描",
                    {"port", "scan", "nmap", "tcp", "udp", "service"},
                    ["recon"], "low"),
        ScenarioNode("service_enum", "服务枚举",
                    {"service", "enum", "version", "banner"},
                    ["recon", "discovery"], "low"),
        ScenarioNode("smb_attack", "SMB攻击",
                    {"smb", "445", "share", "netbios", "cifs"},
                    ["discovery", "exploitation"], "high"),
        ScenarioNode("dns_enum", "DNS枚举",
                    {"dns", "zone", "transfer", "subdomain"},
                    ["recon"], "low"),
        ScenarioNode("network_recon", "网络侦察",
                    {"network", "recon", "arp", "discovery"},
                    ["recon"], "low"),
        
        # 发现场景
        ScenarioNode("subdomain_enum", "子域名枚举",
                    {"subdomain", "domain", "dns", "enum"},
                    ["recon"], "low"),
        ScenarioNode("directory_discovery", "目录发现",
                    {"directory", "dir", "path", "fuzz", "brute"},
                    ["discovery"], "low"),
        ScenarioNode("parameter_discovery", "参数发现",
                    {"param", "parameter", "query", "input"},
                    ["discovery"], "low"),
        ScenarioNode("endpoint_discovery", "端点发现",
                    {"endpoint", "api", "route", "url"},
                    ["discovery"], "low"),
        ScenarioNode("technology_detection", "技术栈检测",
                    {"tech", "stack", "framework", "cms", "version"},
                    ["recon"], "low"),
        
        # 云/容器场景
        ScenarioNode("cloud_misconfiguration", "云配置错误",
                    {"cloud", "aws", "azure", "gcp", "s3", "bucket", "iam"},
                    ["vuln_scan"], "high"),
        ScenarioNode("container_escape", "容器逃逸",
                    {"container", "docker", "escape", "breakout"},
                    ["exploitation"], "critical"),
        ScenarioNode("k8s_attack", "Kubernetes攻击",
                    {"k8s", "kubernetes", "pod", "rbac", "secret"},
                    ["vuln_scan", "exploitation"], "critical"),
        ScenarioNode("iac_security", "基础设施即代码安全",
                    {"iac", "terraform", "cloudformation", "ansible"},
                    ["vuln_scan"], "medium"),
        
        # 二进制/逆向场景
        ScenarioNode("binary_exploitation", "二进制利用",
                    {"binary", "exploit", "buffer", "overflow", "pwn"},
                    ["exploitation"], "critical"),
        ScenarioNode("memory_forensics", "内存取证",
                    {"memory", "forensics", "volatility", "dump"},
                    ["post_exploit"], "medium"),
        ScenarioNode("reverse_engineering", "逆向工程",
                    {"reverse", "disassemble", "decompile", "analysis"},
                    ["discovery"], "medium"),
        ScenarioNode("rop_chain", "ROP链构造",
                    {"rop", "gadget", "chain", "return"},
                    ["exploitation"], "critical"),
        
        # API场景
        ScenarioNode("api_testing", "API安全测试",
                    {"api", "rest", "endpoint", "swagger", "openapi"},
                    ["discovery", "vuln_scan"], "medium"),
        ScenarioNode("graphql_attack", "GraphQL攻击",
                    {"graphql", "introspection", "query", "mutation"},
                    ["vuln_scan", "exploitation"], "high"),
        
        # 综合场景
        ScenarioNode("bug_bounty", "漏洞赏金",
                    {"bounty", "bug", "hackerone", "bugcrowd"},
                    ["recon", "discovery", "vuln_scan"], "medium"),
        ScenarioNode("ctf_challenge", "CTF挑战",
                    {"ctf", "challenge", "flag", "pwn", "crypto"},
                    ["discovery", "exploitation"], "medium"),
        ScenarioNode("vulnerability_assessment", "漏洞评估",
                    {"assessment", "audit", "scan", "vulnerability"},
                    ["vuln_scan"], "medium"),
        ScenarioNode("osint", "开源情报收集",
                    {"osint", "intelligence", "recon", "passive"},
                    ["recon"], "low"),
        ScenarioNode("waf_bypass", "WAF绕过",
                    {"waf", "bypass", "firewall", "filter"},
                    ["exploitation"], "high"),
    ]
    for scenario in scenarios:
        graph.add_scenario(scenario)


def _add_all_tools(graph: ToolGraph) -> None:
    """添加所有160+工具节点"""
    
    # ========================================================================
    # 网络扫描工具 (Network Scanning)
    # ========================================================================
    network_scan_tools = [
        ToolNode("nmap_scan", "network_scan", "recon",
                "端口扫描与服务识别，适合初步摸清目标暴露面",
                {"web_application", "network_host", "api_endpoint"},
                {"port_scan", "service_enum", "network_recon"},
                {"tcp", "udp", "service-detect", "nse", "port"},
                priority=9, execution_time="medium"),
        
        ToolNode("nmap_advanced_scan", "network_scan", "recon",
                "高级Nmap扫描，支持NSE脚本、OS检测、版本检测",
                {"web_application", "network_host"},
                {"port_scan", "service_enum", "vulnerability_assessment"},
                {"nse", "os-detect", "version", "aggressive"},
                priority=8, execution_time="slow"),
        
        ToolNode("rustscan_fast_scan", "network_scan", "recon",
                "高速端口扫描器，适合快速找出开放端口",
                {"network_host", "web_application"},
                {"port_scan", "network_recon"},
                {"fast", "port-scan", "rust"},
                priority=8, execution_time="fast"),
        
        ToolNode("masscan_high_speed", "network_scan", "recon",
                "超高速端口扫描，适合大规模网络扫描",
                {"network_host"},
                {"port_scan", "network_recon"},
                {"fast", "mass-scan", "large-scale"},
                priority=7, execution_time="fast"),
        
        ToolNode("autorecon_comprehensive", "network_scan", "recon",
                "综合自动化侦察工具，自动执行多种扫描",
                {"network_host", "web_application"},
                {"port_scan", "service_enum", "vulnerability_assessment"},
                {"auto", "comprehensive", "enum"},
                priority=7, execution_time="slow"),
        
        ToolNode("autorecon_scan", "network_scan", "recon",
                "AutoRecon全参数扫描，支持完整配置",
                {"network_host", "web_application"},
                {"port_scan", "service_enum"},
                {"auto", "full-config"},
                priority=6, execution_time="slow"),
        
        ToolNode("nbtscan_netbios", "network_scan", "recon",
                "NetBIOS名称扫描，发现Windows主机",
                {"network_host", "smb_share"},
                {"network_recon", "smb_attack"},
                {"netbios", "windows", "name"},
                priority=5, execution_time="fast"),
        
        ToolNode("arp_scan_discovery", "network_scan", "recon",
                "ARP扫描，发现本地网络主机",
                {"network_host"},
                {"network_recon"},
                {"arp", "local", "discovery"},
                priority=5, execution_time="fast"),
    ]
    
    # ========================================================================
    # Web目录发现工具 (Web Discovery)
    # ========================================================================
    web_discovery_tools = [
        ToolNode("gobuster_scan", "web_discovery", "discovery",
                "目录/文件枚举，适合发现隐藏路径、备份文件",
                {"web_application"},
                {"directory_discovery", "endpoint_discovery"},
                {"dir", "fuzz", "brute"},
                priority=9, execution_time="medium"),
        
        ToolNode("feroxbuster_scan", "web_discovery", "discovery",
                "递归内容发现工具，适合大站点的深度目录遍历",
                {"web_application"},
                {"directory_discovery", "endpoint_discovery"},
                {"dir", "recursive", "fast"},
                priority=9, execution_time="medium"),
        
        ToolNode("ffuf_scan", "web_discovery", "discovery",
                "高性能模糊测试/目录爆破工具，可用于参数fuzz",
                {"web_application", "api_endpoint"},
                {"directory_discovery", "parameter_discovery", "endpoint_discovery"},
                {"fuzz", "dir", "param", "fast"},
                priority=9, execution_time="fast"),
        
        ToolNode("dirsearch_scan", "web_discovery", "discovery",
                "经典目录扫描器，支持多种扩展名",
                {"web_application"},
                {"directory_discovery"},
                {"dir", "extension"},
                priority=8, execution_time="medium"),
        
        ToolNode("dirb_scan", "web_discovery", "discovery",
                "传统目录暴力破解工具",
                {"web_application"},
                {"directory_discovery"},
                {"dir", "brute"},
                priority=6, execution_time="slow"),
        
        ToolNode("wfuzz_scan", "web_discovery", "discovery",
                "Web应用模糊测试工具",
                {"web_application", "api_endpoint"},
                {"directory_discovery", "parameter_discovery"},
                {"fuzz", "param"},
                priority=7, execution_time="medium"),
        
        ToolNode("katana_crawl", "web_discovery", "discovery",
                "下一代爬虫工具，支持JS渲染和表单提取",
                {"web_application"},
                {"endpoint_discovery", "parameter_discovery"},
                {"crawl", "js", "form"},
                priority=8, execution_time="medium"),
    ]
    
    # ========================================================================
    # 参数发现工具 (Parameter Discovery)
    # ========================================================================
    param_discovery_tools = [
        ToolNode("arjun_parameter_discovery", "param_discovery", "discovery",
                "HTTP参数发现工具，适合API/表单参数挖掘",
                {"web_application", "api_endpoint"},
                {"parameter_discovery", "api_testing"},
                {"param", "api", "hidden"},
                priority=9, execution_time="medium"),
        
        ToolNode("arjun_scan", "param_discovery", "discovery",
                "Arjun参数发现（简化版）",
                {"web_application", "api_endpoint"},
                {"parameter_discovery"},
                {"param"},
                priority=8, execution_time="medium"),
        
        ToolNode("paramspider_mining", "param_discovery", "discovery",
                "从历史URL中挖掘参数，配合XSS/SQLi测试",
                {"web_application"},
                {"parameter_discovery", "osint"},
                {"param", "archive", "wayback"},
                priority=8, execution_time="fast"),
        
        ToolNode("x8_parameter_discovery", "param_discovery", "discovery",
                "隐藏参数发现工具",
                {"web_application", "api_endpoint"},
                {"parameter_discovery"},
                {"param", "hidden"},
                priority=7, execution_time="medium"),
    ]
    
    # ========================================================================
    # 漏洞扫描工具 (Vulnerability Scanning)
    # ========================================================================
    vuln_scan_tools = [
        ToolNode("nuclei_scan", "vuln_scan", "vuln_scan",
                "模板化漏洞扫描，覆盖常见Web漏洞与配置问题",
                {"web_application", "api_endpoint", "network_host"},
                {"vulnerability_assessment", "sql_injection", "xss_attack", "lfi_rfi"},
                {"template", "cve", "web-vuln", "fast"},
                priority=10, execution_time="medium"),
        
        ToolNode("nikto_scan", "vuln_scan", "vuln_scan",
                "Web服务器漏洞扫描器",
                {"web_application"},
                {"vulnerability_assessment", "technology_detection"},
                {"web", "server", "config"},
                priority=7, execution_time="slow"),
        
        ToolNode("zap_scan", "vuln_scan", "vuln_scan",
                "OWASP ZAP安全扫描",
                {"web_application"},
                {"vulnerability_assessment", "xss_attack", "sql_injection"},
                {"owasp", "proxy", "scan"},
                priority=8, execution_time="slow"),
        
        ToolNode("jaeles_vulnerability_scan", "vuln_scan", "vuln_scan",
                "自定义签名漏洞扫描",
                {"web_application", "api_endpoint"},
                {"vulnerability_assessment"},
                {"signature", "custom"},
                priority=7, execution_time="medium"),
    ]
    
    # ========================================================================
    # SQL注入工具 (SQL Injection)
    # ========================================================================
    sqli_tools = [
        ToolNode("sqlmap_scan", "sqli", "exploitation",
                "自动化SQL注入检测与利用工具",
                {"web_application", "api_endpoint", "database"},
                {"sql_injection"},
                {"sqli", "db", "auto", "dump"},
                priority=10, is_aggressive=True, execution_time="slow"),
    ]
    
    # ========================================================================
    # XSS工具 (Cross-Site Scripting)
    # ========================================================================
    xss_tools = [
        ToolNode("dalfox_xss_scan", "xss", "vuln_scan",
                "高级XSS漏洞自动化检测工具",
                {"web_application"},
                {"xss_attack", "waf_bypass"},
                {"xss", "dom", "reflected", "stored"},
                priority=10, execution_time="medium"),
        
        ToolNode("xsser_scan", "xss", "vuln_scan",
                "XSS漏洞测试工具",
                {"web_application"},
                {"xss_attack"},
                {"xss"},
                priority=7, execution_time="medium"),
    ]
    
    # ========================================================================
    # 子域名枚举工具 (Subdomain Enumeration)
    # ========================================================================
    subdomain_tools = [
        ToolNode("amass_scan", "subdomain", "recon",
                "域名与子域名枚举，适合BugBounty/外网资产梳理",
                {"web_application", "dns_server"},
                {"subdomain_enum", "osint", "bug_bounty"},
                {"subdomain", "osint", "dns"},
                priority=9, execution_time="slow"),
        
        ToolNode("subfinder_scan", "subdomain", "recon",
                "被动子域枚举，与amass搭配提升覆盖率",
                {"web_application", "dns_server"},
                {"subdomain_enum", "osint"},
                {"subdomain", "passive", "fast"},
                priority=9, execution_time="fast"),
        
        ToolNode("fierce_scan", "subdomain", "recon",
                "DNS侦察工具",
                {"dns_server"},
                {"dns_enum", "subdomain_enum"},
                {"dns", "zone"},
                priority=6, execution_time="medium"),
        
        ToolNode("dnsenum_scan", "subdomain", "recon",
                "DNS枚举工具",
                {"dns_server"},
                {"dns_enum", "subdomain_enum"},
                {"dns", "enum"},
                priority=6, execution_time="medium"),
    ]
    
    # ========================================================================
    # HTTP探测工具 (HTTP Probing)
    # ========================================================================
    http_probe_tools = [
        ToolNode("httpx_probe", "http_probe", "recon",
                "HTTP探活与技术栈识别，适合筛选出存活Web服务",
                {"web_application", "api_endpoint"},
                {"technology_detection", "endpoint_discovery"},
                {"http", "tech-detect", "probe", "fast"},
                priority=9, execution_time="fast"),
    ]
    
    # ========================================================================
    # OSINT工具 (Open Source Intelligence)
    # ========================================================================
    osint_tools = [
        ToolNode("gau_discovery", "osint", "recon",
                "从各种数据源聚合历史URL，适合挖参数和老接口",
                {"web_application"},
                {"osint", "parameter_discovery", "endpoint_discovery"},
                {"url", "archive", "wayback"},
                priority=8, execution_time="fast"),
        
        ToolNode("waybackurls_discovery", "osint", "recon",
                "从Wayback Machine抓取历史URL",
                {"web_application"},
                {"osint", "endpoint_discovery"},
                {"url", "archive", "wayback"},
                priority=8, execution_time="fast"),
    ]
    
    # ========================================================================
    # SMB/Windows工具 (SMB/Windows)
    # ========================================================================
    smb_tools = [
        ToolNode("enum4linux_scan", "smb", "discovery",
                "SMB枚举工具，获取用户、共享、策略信息",
                {"smb_share", "network_host"},
                {"smb_attack", "service_enum"},
                {"smb", "enum", "windows"},
                priority=8, execution_time="medium"),
        
        ToolNode("enum4linux_ng_advanced", "smb", "discovery",
                "增强版SMB枚举",
                {"smb_share", "network_host"},
                {"smb_attack", "service_enum"},
                {"smb", "enum", "advanced"},
                priority=8, execution_time="medium"),
        
        ToolNode("smbmap_scan", "smb", "discovery",
                "SMB共享枚举和访问测试",
                {"smb_share"},
                {"smb_attack"},
                {"smb", "share", "access"},
                priority=8, execution_time="fast"),
        
        ToolNode("netexec_scan", "smb", "exploitation",
                "网络执行工具（原CrackMapExec）",
                {"smb_share", "network_host"},
                {"smb_attack", "brute_force", "auth_bypass"},
                {"smb", "wmi", "winrm", "lateral"},
                priority=9, is_aggressive=True, execution_time="medium"),
        
        ToolNode("rpcclient_enumeration", "smb", "discovery",
                "RPC客户端枚举",
                {"smb_share", "network_host"},
                {"smb_attack", "service_enum"},
                {"rpc", "enum"},
                priority=6, execution_time="fast"),
        
        ToolNode("responder_credential_harvest", "smb", "exploitation",
                "凭据收集工具",
                {"network_host", "smb_share"},
                {"auth_bypass", "session_hijack"},
                {"credential", "harvest", "mitm"},
                priority=7, is_aggressive=True, execution_time="slow"),
    ]
    
    # ========================================================================
    # 密码破解工具 (Password Cracking)
    # ========================================================================
    password_tools = [
        ToolNode("hydra_attack", "password", "exploitation",
                "在线密码暴力破解工具",
                {"login_page", "network_host"},
                {"brute_force", "auth_bypass"},
                {"brute", "online", "multi-protocol"},
                priority=8, is_aggressive=True, execution_time="slow"),
        
        ToolNode("john_crack", "password", "exploitation",
                "John the Ripper密码破解",
                {"file_system"},
                {"password_crack"},
                {"hash", "crack", "offline"},
                priority=8, execution_time="slow"),
        
        ToolNode("hashcat_crack", "password", "exploitation",
                "高级GPU密码破解",
                {"file_system"},
                {"password_crack"},
                {"hash", "crack", "gpu", "fast"},
                priority=9, execution_time="slow"),
    ]
    
    # ========================================================================
    # WordPress工具 (WordPress)
    # ========================================================================
    wordpress_tools = [
        ToolNode("wpscan_analyze", "wordpress", "vuln_scan",
                "专门针对WordPress的安全扫描器",
                {"wordpress_site", "web_application"},
                {"vulnerability_assessment", "technology_detection"},
                {"wordpress", "cms", "plugin", "theme"},
                priority=10, execution_time="medium"),
    ]
    
    # ========================================================================
    # 云安全工具 (Cloud Security)
    # ========================================================================
    cloud_tools = [
        ToolNode("prowler_scan", "cloud", "vuln_scan",
                "AWS/Azure/GCP云安全评估",
                {"cloud_service"},
                {"cloud_misconfiguration", "vulnerability_assessment"},
                {"aws", "azure", "gcp", "cis"},
                priority=9, execution_time="slow"),
        
        ToolNode("scout_suite_assessment", "cloud", "vuln_scan",
                "多云安全评估工具",
                {"cloud_service"},
                {"cloud_misconfiguration"},
                {"aws", "azure", "gcp", "multi-cloud"},
                priority=8, execution_time="slow"),
        
        ToolNode("cloudmapper_analysis", "cloud", "discovery",
                "AWS网络可视化和安全分析",
                {"cloud_service"},
                {"cloud_misconfiguration", "network_recon"},
                {"aws", "network", "visualization"},
                priority=7, execution_time="slow"),
        
        ToolNode("pacu_exploitation", "cloud", "exploitation",
                "AWS利用框架",
                {"cloud_service"},
                {"cloud_misconfiguration"},
                {"aws", "exploit", "enum"},
                priority=8, is_aggressive=True, execution_time="medium"),
        
        ToolNode("trivy_scan", "cloud", "vuln_scan",
                "容器和文件系统漏洞扫描",
                {"container", "file_system", "cloud_service"},
                {"vulnerability_assessment", "container_escape"},
                {"container", "image", "cve"},
                priority=9, execution_time="fast"),
    ]
    
    # ========================================================================
    # Kubernetes工具 (Kubernetes)
    # ========================================================================
    k8s_tools = [
        ToolNode("kube_hunter_scan", "kubernetes", "vuln_scan",
                "Kubernetes渗透测试工具",
                {"kubernetes"},
                {"k8s_attack", "vulnerability_assessment"},
                {"k8s", "pentest", "cluster"},
                priority=9, execution_time="medium"),
        
        ToolNode("kube_bench_cis", "kubernetes", "vuln_scan",
                "CIS Kubernetes基准检查",
                {"kubernetes"},
                {"k8s_attack", "vulnerability_assessment"},
                {"k8s", "cis", "benchmark"},
                priority=8, execution_time="fast"),
    ]
    
    # ========================================================================
    # Docker工具 (Docker)
    # ========================================================================
    docker_tools = [
        ToolNode("docker_bench_security_scan", "docker", "vuln_scan",
                "Docker安全基准检查",
                {"container"},
                {"container_escape", "vulnerability_assessment"},
                {"docker", "cis", "benchmark"},
                priority=8, execution_time="fast"),
        
        ToolNode("clair_vulnerability_scan", "docker", "vuln_scan",
                "容器镜像漏洞分析",
                {"container"},
                {"vulnerability_assessment"},
                {"container", "image", "cve"},
                priority=7, execution_time="medium"),
        
        ToolNode("falco_runtime_monitoring", "docker", "post_exploit",
                "运行时安全监控",
                {"container", "kubernetes"},
                {"container_escape"},
                {"runtime", "monitor", "detect"},
                priority=6, execution_time="slow"),
    ]
    
    # ========================================================================
    # IaC安全工具 (Infrastructure as Code)
    # ========================================================================
    iac_tools = [
        ToolNode("checkov_iac_scan", "iac", "vuln_scan",
                "基础设施即代码安全扫描",
                {"file_system", "cloud_service"},
                {"iac_security", "cloud_misconfiguration"},
                {"terraform", "cloudformation", "k8s"},
                priority=8, execution_time="fast"),
        
        ToolNode("terrascan_iac_scan", "iac", "vuln_scan",
                "Terraform安全扫描",
                {"file_system", "cloud_service"},
                {"iac_security"},
                {"terraform", "policy"},
                priority=7, execution_time="fast"),
    ]
    
    # 添加所有工具到图谱
    all_tools = (network_scan_tools + web_discovery_tools + param_discovery_tools +
                vuln_scan_tools + sqli_tools + xss_tools + subdomain_tools +
                http_probe_tools + osint_tools + smb_tools + password_tools +
                wordpress_tools + cloud_tools + k8s_tools + docker_tools + iac_tools)
    
    for tool in all_tools:
        graph.add_tool(tool)
    
    # 继续添加更多工具...
    _add_binary_tools(graph)
    _add_exploit_tools(graph)
    _add_api_tools(graph)
    _add_ai_tools(graph)
    _add_page_awareness_tools(graph)
    _add_bugbounty_tools(graph)
    _add_utility_tools(graph)
    _add_forensics_tools(graph)


def _add_binary_tools(graph: ToolGraph) -> None:
    """添加二进制分析和逆向工程工具"""
    binary_tools = [
        ToolNode("gdb_analyze", "binary", "exploitation",
                "GDB调试器，用于二进制分析和调试",
                {"binary_executable"},
                {"binary_exploitation", "reverse_engineering"},
                {"debug", "breakpoint", "memory"},
                priority=9, execution_time="medium"),
        
        ToolNode("gdb_peda_debug", "binary", "exploitation",
                "GDB PEDA增强调试",
                {"binary_executable"},
                {"binary_exploitation", "rop_chain"},
                {"debug", "peda", "exploit"},
                priority=9, execution_time="medium"),
        
        ToolNode("radare2_analyze", "binary", "discovery",
                "Radare2逆向工程框架",
                {"binary_executable"},
                {"reverse_engineering", "binary_exploitation"},
                {"disassemble", "analyze", "r2"},
                priority=8, execution_time="medium"),
        
        ToolNode("ghidra_analysis", "binary", "discovery",
                "Ghidra高级逆向分析",
                {"binary_executable"},
                {"reverse_engineering"},
                {"decompile", "analyze", "nsa"},
                priority=9, execution_time="slow"),
        
        ToolNode("binwalk_analyze", "binary", "discovery",
                "固件和文件分析工具",
                {"binary_executable", "file_system"},
                {"reverse_engineering"},
                {"firmware", "extract", "signature"},
                priority=7, execution_time="fast"),
        
        ToolNode("ropgadget_search", "binary", "exploitation",
                "ROP gadget搜索工具",
                {"binary_executable"},
                {"rop_chain", "binary_exploitation"},
                {"rop", "gadget", "chain"},
                priority=8, execution_time="fast"),
        
        ToolNode("ropper_gadget_search", "binary", "exploitation",
                "高级ROP/JOP gadget搜索",
                {"binary_executable"},
                {"rop_chain", "binary_exploitation"},
                {"rop", "jop", "gadget"},
                priority=8, execution_time="fast"),
        
        ToolNode("checksec_analyze", "binary", "discovery",
                "检查二进制安全特性",
                {"binary_executable"},
                {"binary_exploitation", "reverse_engineering"},
                {"nx", "pie", "canary", "relro"},
                priority=9, execution_time="fast"),
        
        ToolNode("one_gadget_search", "binary", "exploitation",
                "libc中的one-shot RCE gadget搜索",
                {"binary_executable"},
                {"binary_exploitation", "rop_chain"},
                {"libc", "one-gadget", "rce"},
                priority=8, execution_time="fast"),
        
        ToolNode("pwntools_exploit", "binary", "exploitation",
                "Pwntools利用开发框架",
                {"binary_executable"},
                {"binary_exploitation", "ctf_challenge"},
                {"pwn", "exploit", "python"},
                priority=10, is_aggressive=True, execution_time="medium"),
        
        ToolNode("pwninit_setup", "binary", "exploitation",
                "CTF二进制利用环境设置",
                {"binary_executable"},
                {"ctf_challenge", "binary_exploitation"},
                {"ctf", "setup", "libc"},
                priority=7, execution_time="fast"),
        
        ToolNode("angr_symbolic_execution", "binary", "exploitation",
                "符号执行和二进制分析",
                {"binary_executable"},
                {"binary_exploitation", "reverse_engineering"},
                {"symbolic", "analysis", "constraint"},
                priority=7, execution_time="slow"),
        
        ToolNode("libc_database_lookup", "binary", "exploitation",
                "libc数据库查询",
                {"binary_executable"},
                {"binary_exploitation"},
                {"libc", "offset", "database"},
                priority=7, execution_time="fast"),
        
        ToolNode("xxd_hexdump", "binary", "discovery",
                "十六进制转储工具",
                {"binary_executable", "file_system"},
                {"reverse_engineering"},
                {"hex", "dump"},
                priority=5, execution_time="fast"),
        
        ToolNode("strings_extract", "binary", "discovery",
                "提取二进制中的字符串",
                {"binary_executable", "file_system"},
                {"reverse_engineering"},
                {"strings", "extract"},
                priority=6, execution_time="fast"),
        
        ToolNode("objdump_analyze", "binary", "discovery",
                "目标文件分析工具",
                {"binary_executable"},
                {"reverse_engineering"},
                {"disassemble", "section"},
                priority=6, execution_time="fast"),
    ]
    
    for tool in binary_tools:
        graph.add_tool(tool)


def _add_exploit_tools(graph: ToolGraph) -> None:
    """添加利用框架和Payload生成工具"""
    exploit_tools = [
        ToolNode("metasploit_run", "exploit", "exploitation",
                "Metasploit利用框架",
                {"network_host", "web_application"},
                {"binary_exploitation", "vulnerability_assessment"},
                {"msf", "exploit", "payload"},
                priority=9, is_aggressive=True, execution_time="medium"),
        
        ToolNode("msfvenom_generate", "exploit", "exploitation",
                "MSFVenom Payload生成",
                {"binary_executable"},
                {"binary_exploitation"},
                {"payload", "shellcode", "encoder"},
                priority=8, execution_time="fast"),
        
        ToolNode("dotdotpwn_scan", "exploit", "vuln_scan",
                "目录遍历测试工具",
                {"web_application"},
                {"path_traversal", "lfi_rfi"},
                {"traversal", "lfi"},
                priority=7, execution_time="medium"),
    ]
    
    for tool in exploit_tools:
        graph.add_tool(tool)


def _add_api_tools(graph: ToolGraph) -> None:
    """添加API安全测试工具"""
    api_tools = [
        ToolNode("api_fuzzer", "api", "vuln_scan",
                "API端点模糊测试",
                {"api_endpoint"},
                {"api_testing", "parameter_discovery"},
                {"api", "fuzz", "endpoint"},
                priority=8, execution_time="medium"),
        
        ToolNode("graphql_scanner", "api", "vuln_scan",
                "GraphQL安全扫描",
                {"graphql_api", "api_endpoint"},
                {"graphql_attack", "api_testing"},
                {"graphql", "introspection", "query"},
                priority=9, execution_time="medium"),
        
        ToolNode("jwt_analyzer", "api", "vuln_scan",
                "JWT令牌分析和攻击",
                {"jwt_token", "api_endpoint"},
                {"jwt_attack", "auth_bypass"},
                {"jwt", "token", "algorithm"},
                priority=9, execution_time="fast"),
        
        ToolNode("api_schema_analyzer", "api", "discovery",
                "API Schema分析",
                {"api_endpoint"},
                {"api_testing", "endpoint_discovery"},
                {"openapi", "swagger", "schema"},
                priority=7, execution_time="fast"),
        
        ToolNode("comprehensive_api_audit", "api", "vuln_scan",
                "综合API安全审计",
                {"api_endpoint", "graphql_api", "jwt_token"},
                {"api_testing", "vulnerability_assessment"},
                {"api", "audit", "comprehensive"},
                priority=8, execution_time="slow"),
    ]
    
    for tool in api_tools:
        graph.add_tool(tool)


def _add_ai_tools(graph: ToolGraph) -> None:
    """添加AI增强工具"""
    ai_tools = [
        ToolNode("ai_generate_payload", "ai", "exploitation",
                "AI生成上下文感知Payload",
                {"web_application", "api_endpoint"},
                {"sql_injection", "xss_attack", "command_injection", "waf_bypass"},
                {"ai", "payload", "context"},
                priority=8, execution_time="fast"),
        
        ToolNode("ai_test_payload", "ai", "exploitation",
                "AI测试Payload有效性",
                {"web_application"},
                {"vulnerability_assessment"},
                {"ai", "test", "validate"},
                priority=7, execution_time="fast"),
        
        ToolNode("ai_generate_attack_suite", "ai", "exploitation",
                "AI生成综合攻击套件",
                {"web_application"},
                {"vulnerability_assessment", "bug_bounty"},
                {"ai", "suite", "comprehensive"},
                priority=7, execution_time="medium"),
        
        ToolNode("intelligent_quick_test", "ai", "vuln_scan",
                "LLM驱动的智能快速测试",
                {"web_application", "api_endpoint"},
                {"sql_injection", "xss_attack", "command_injection", "lfi_rfi"},
                {"ai", "quick", "smart", "llm"},
                priority=10, execution_time="fast"),
        
        ToolNode("analyze_target_intelligence", "ai", "recon",
                "AI目标情报分析",
                {"web_application", "network_host"},
                {"technology_detection", "vulnerability_assessment"},
                {"ai", "intelligence", "profile"},
                priority=8, execution_time="fast"),
        
        ToolNode("select_optimal_tools_ai", "ai", "recon",
                "AI选择最优工具",
                {"web_application", "network_host"},
                {"vulnerability_assessment"},
                {"ai", "select", "optimal"},
                priority=8, execution_time="fast"),
        
        ToolNode("optimize_tool_parameters_ai", "ai", "recon",
                "AI优化工具参数",
                {"web_application", "network_host"},
                {"vulnerability_assessment"},
                {"ai", "optimize", "params"},
                priority=7, execution_time="fast"),
        
        ToolNode("create_attack_chain_ai", "ai", "exploitation",
                "AI创建攻击链",
                {"web_application", "network_host"},
                {"vulnerability_assessment", "bug_bounty"},
                {"ai", "chain", "attack"},
                priority=8, execution_time="fast"),
        
        ToolNode("intelligent_smart_scan", "ai", "vuln_scan",
                "AI驱动的智能扫描",
                {"web_application", "network_host"},
                {"vulnerability_assessment"},
                {"ai", "smart", "scan"},
                priority=9, execution_time="medium"),
        
        ToolNode("detect_technologies_ai", "ai", "recon",
                "AI技术栈检测",
                {"web_application"},
                {"technology_detection"},
                {"ai", "tech", "detect"},
                priority=8, execution_time="fast"),
        
        ToolNode("ai_reconnaissance_workflow", "ai", "recon",
                "AI侦察工作流",
                {"web_application", "network_host"},
                {"osint", "subdomain_enum", "technology_detection"},
                {"ai", "recon", "workflow"},
                priority=8, execution_time="medium"),
        
        ToolNode("ai_vulnerability_assessment", "ai", "vuln_scan",
                "AI漏洞评估",
                {"web_application", "network_host"},
                {"vulnerability_assessment"},
                {"ai", "assessment", "vuln"},
                priority=8, execution_time="medium"),
    ]
    
    for tool in ai_tools:
        graph.add_tool(tool)


def _add_page_awareness_tools(graph: ToolGraph) -> None:
    """添加页面感知工具"""
    page_tools = [
        ToolNode("browser_visit_page", "page_awareness", "discovery",
                "访问URL并解析页面结构，发现表单、输入框、链接",
                {"web_application", "login_page"},
                {"parameter_discovery", "endpoint_discovery", "auth_bypass"},
                {"page", "form", "input", "link"},
                priority=10, execution_time="fast"),
        
        ToolNode("execute_browser_js", "page_awareness", "exploitation",
                "在浏览器Console执行JavaScript代码，支持fetch/DOM操作/localStorage等",
                {"web_application", "api_endpoint"},
                {"api_testing", "xss_attack", "auth_bypass", "client_side_attack"},
                {"browser", "javascript", "console", "fetch", "dom", "client"},
                priority=10, execution_time="fast"),
        
        ToolNode("browser_get_rendered_content", "page_awareness", "discovery",
                "获取完整渲染后的页面内容（包括JavaScript动态生成的内容）",
                {"web_application"},
                {"endpoint_discovery", "parameter_discovery", "technology_detection"},
                {"browser", "render", "javascript", "dynamic", "spa"},
                priority=9, execution_time="fast"),
        
        ToolNode("crawl_site_endpoints", "page_awareness", "discovery",
                "爬取站点发现所有端点，优先返回带参数的URL",
                {"web_application"},
                {"endpoint_discovery", "parameter_discovery"},
                {"crawl", "spider", "url"},
                priority=9, execution_time="medium"),
        
        ToolNode("discover_injectable_params", "page_awareness", "discovery",
                "深度分析URL，发现所有可注入参数",
                {"web_application", "api_endpoint"},
                {"parameter_discovery", "sql_injection", "xss_attack"},
                {"param", "inject", "deep"},
                priority=9, execution_time="fast"),
        
        ToolNode("smart_login_attempt", "page_awareness", "exploitation",
                "智能登录工具，自动处理CSRF和表单",
                {"login_page", "web_application"},
                {"auth_bypass", "brute_force"},
                {"login", "csrf", "auth"},
                priority=9, requires_auth=False, execution_time="fast"),
        
        ToolNode("view_source_code", "page_awareness", "discovery",
                "查看后端源码",
                {"web_application"},
                {"reverse_engineering", "vulnerability_assessment"},
                {"source", "code", "view"},
                priority=8, requires_auth=True, execution_time="fast"),
        
        ToolNode("analyze_source_code", "page_awareness", "vuln_scan",
                "分析源码识别潜在漏洞",
                {"web_application"},
                {"sql_injection", "xss_attack", "command_injection"},
                {"source", "analyze", "vuln"},
                priority=9, execution_time="fast"),
        
        ToolNode("http_framework_test", "page_awareness", "vuln_scan",
                "HTTP测试框架（Burp替代）",
                {"web_application", "api_endpoint"},
                {"vulnerability_assessment", "parameter_discovery"},
                {"http", "burp", "proxy"},
                priority=8, execution_time="medium"),
    ]
    
    for tool in page_tools:
        graph.add_tool(tool)


def _add_bugbounty_tools(graph: ToolGraph) -> None:
    """添加Bug Bounty专用工具"""
    bb_tools = [
        ToolNode("bugbounty_reconnaissance_workflow", "bugbounty", "recon",
                "Bug Bounty侦察工作流",
                {"web_application"},
                {"bug_bounty", "subdomain_enum", "osint"},
                {"bounty", "recon", "workflow"},
                priority=8, execution_time="slow"),
        
        ToolNode("bugbounty_vulnerability_hunting", "bugbounty", "vuln_scan",
                "漏洞猎取工作流",
                {"web_application"},
                {"bug_bounty", "vulnerability_assessment"},
                {"bounty", "hunt", "vuln"},
                priority=8, execution_time="medium"),
        
        ToolNode("bugbounty_business_logic_testing", "bugbounty", "vuln_scan",
                "业务逻辑测试工作流",
                {"web_application"},
                {"bug_bounty", "auth_bypass"},
                {"bounty", "logic", "business"},
                priority=7, execution_time="medium"),
        
        ToolNode("bugbounty_osint_gathering", "bugbounty", "recon",
                "OSINT情报收集工作流",
                {"web_application"},
                {"osint", "bug_bounty"},
                {"bounty", "osint", "intel"},
                priority=7, execution_time="medium"),
        
        ToolNode("bugbounty_file_upload_testing", "bugbounty", "vuln_scan",
                "文件上传漏洞测试",
                {"web_application"},
                {"file_upload", "bug_bounty"},
                {"upload", "bypass", "shell"},
                priority=8, execution_time="medium"),
        
        ToolNode("bugbounty_comprehensive_assessment", "bugbounty", "vuln_scan",
                "综合Bug Bounty评估",
                {"web_application"},
                {"bug_bounty", "vulnerability_assessment"},
                {"bounty", "comprehensive", "full"},
                priority=8, execution_time="slow"),
        
        ToolNode("bugbounty_authentication_bypass_testing", "bugbounty", "exploitation",
                "认证绕过测试",
                {"login_page", "web_application"},
                {"auth_bypass", "jwt_attack", "bug_bounty"},
                {"auth", "bypass", "jwt"},
                priority=8, execution_time="medium"),
    ]
    
    for tool in bb_tools:
        graph.add_tool(tool)


def _add_utility_tools(graph: ToolGraph) -> None:
    """添加实用工具"""
    utility_tools = [
        ToolNode("wafw00f_scan", "utility", "recon",
                "WAF检测和指纹识别",
                {"web_application"},
                {"waf_bypass", "technology_detection"},
                {"waf", "detect", "fingerprint"},
                priority=8, execution_time="fast"),
        
        ToolNode("create_file", "utility", "post_exploit",
                "创建文件",
                {"file_system"},
                set(),
                {"file", "create"},
                priority=3, execution_time="fast"),
        
        ToolNode("modify_file", "utility", "post_exploit",
                "修改文件",
                {"file_system"},
                set(),
                {"file", "modify"},
                priority=3, execution_time="fast"),
        
        ToolNode("delete_file", "utility", "post_exploit",
                "删除文件",
                {"file_system"},
                set(),
                {"file", "delete"},
                priority=3, execution_time="fast"),
        
        ToolNode("list_files", "utility", "discovery",
                "列出文件",
                {"file_system"},
                set(),
                {"file", "list"},
                priority=3, execution_time="fast"),
        
        ToolNode("list_directory", "utility", "discovery",
                "列出目录",
                {"file_system"},
                set(),
                {"dir", "list"},
                priority=3, execution_time="fast"),
        
        ToolNode("read_file", "utility", "discovery",
                "读取文件",
                {"file_system"},
                set(),
                {"file", "read"},
                priority=3, execution_time="fast"),
        
        ToolNode("generate_payload", "utility", "exploitation",
                "生成测试Payload",
                {"binary_executable"},
                {"binary_exploitation"},
                {"payload", "buffer"},
                priority=5, execution_time="fast"),
        
        ToolNode("execute_command", "utility", "exploitation",
                "执行系统命令",
                {"network_host", "file_system"},
                {"command_injection"},
                {"cmd", "exec"},
                priority=6, is_aggressive=True, execution_time="fast"),
        
        ToolNode("install_python_package", "utility", "post_exploit",
                "安装Python包",
                {"file_system"},
                set(),
                {"python", "pip"},
                priority=2, execution_time="medium"),
        
        ToolNode("execute_python_script", "utility", "exploitation",
                "执行Python脚本",
                {"file_system"},
                {"command_injection"},
                {"python", "script"},
                priority=5, execution_time="medium"),
        
        ToolNode("server_health", "utility", "reporting",
                "检查服务器健康状态",
                set(),
                set(),
                {"health", "status"},
                priority=2, execution_time="fast"),
        
        ToolNode("get_cache_stats", "utility", "reporting",
                "获取缓存统计",
                set(),
                set(),
                {"cache", "stats"},
                priority=1, execution_time="fast"),
        
        ToolNode("clear_cache", "utility", "reporting",
                "清除缓存",
                set(),
                set(),
                {"cache", "clear"},
                priority=1, execution_time="fast"),
        
        ToolNode("get_telemetry", "utility", "reporting",
                "获取遥测数据",
                set(),
                set(),
                {"telemetry", "metrics"},
                priority=1, execution_time="fast"),
        
        ToolNode("list_active_processes", "utility", "reporting",
                "列出活动进程",
                set(),
                set(),
                {"process", "list"},
                priority=2, execution_time="fast"),
        
        ToolNode("get_process_status", "utility", "reporting",
                "获取进程状态",
                set(),
                set(),
                {"process", "status"},
                priority=2, execution_time="fast"),
        
        ToolNode("terminate_process", "utility", "post_exploit",
                "终止进程",
                set(),
                set(),
                {"process", "kill"},
                priority=2, execution_time="fast"),
        
        ToolNode("pause_process", "utility", "post_exploit",
                "暂停进程",
                set(),
                set(),
                {"process", "pause"},
                priority=2, execution_time="fast"),
        
        ToolNode("resume_process", "utility", "post_exploit",
                "恢复进程",
                set(),
                set(),
                {"process", "resume"},
                priority=2, execution_time="fast"),
        
        ToolNode("get_process_dashboard", "utility", "reporting",
                "获取进程仪表板",
                set(),
                set(),
                {"process", "dashboard"},
                priority=2, execution_time="fast"),
        
        ToolNode("list_processes", "utility", "discovery",
                "列出系统进程",
                {"network_host"},
                set(),
                {"process", "system"},
                priority=3, execution_time="fast"),
        
        ToolNode("anew_data_processing", "utility", "reporting",
                "数据去重处理",
                set(),
                set(),
                {"data", "unique"},
                priority=3, execution_time="fast"),
        
        ToolNode("qsreplace_parameter_replacement", "utility", "discovery",
                "查询字符串参数替换",
                {"web_application"},
                {"parameter_discovery"},
                {"param", "replace"},
                priority=4, execution_time="fast"),
        
        ToolNode("uro_url_filtering", "utility", "discovery",
                "URL过滤去重",
                {"web_application"},
                {"endpoint_discovery"},
                {"url", "filter"},
                priority=4, execution_time="fast"),
        
        ToolNode("format_tool_output", "utility", "reporting",
                "格式化工具输出",
                set(),
                set(),
                {"format", "output"},
                priority=2, execution_time="fast"),
        
        ToolNode("create_scan_summary", "utility", "reporting",
                "创建扫描摘要",
                set(),
                set(),
                {"summary", "report"},
                priority=3, execution_time="fast"),
        
        ToolNode("display_system_metrics", "utility", "reporting",
                "显示系统指标",
                set(),
                set(),
                {"metrics", "system"},
                priority=2, execution_time="fast"),
    ]
    
    for tool in utility_tools:
        graph.add_tool(tool)


def _add_forensics_tools(graph: ToolGraph) -> None:
    """添加取证和威胁情报工具"""
    forensics_tools = [
        ToolNode("volatility_analyze", "forensics", "post_exploit",
                "Volatility内存取证分析",
                {"memory_dump"},
                {"memory_forensics"},
                {"memory", "forensics", "malware"},
                priority=8, execution_time="slow"),
        
        ToolNode("volatility3_analyze", "forensics", "post_exploit",
                "Volatility3高级内存取证",
                {"memory_dump"},
                {"memory_forensics"},
                {"memory", "forensics", "v3"},
                priority=8, execution_time="slow"),
        
        ToolNode("foremost_carving", "forensics", "post_exploit",
                "文件雕刻恢复",
                {"file_system", "memory_dump"},
                {"memory_forensics"},
                {"carve", "recover", "file"},
                priority=6, execution_time="slow"),
        
        ToolNode("monitor_cve_feeds", "threat_intel", "recon",
                "监控CVE数据源",
                set(),
                {"vulnerability_assessment"},
                {"cve", "feed", "monitor"},
                priority=6, execution_time="medium"),
        
        ToolNode("generate_exploit_from_cve", "threat_intel", "exploitation",
                "从CVE生成利用代码",
                {"web_application", "network_host"},
                {"vulnerability_assessment"},
                {"cve", "exploit", "generate"},
                priority=7, is_aggressive=True, execution_time="medium"),
        
        ToolNode("discover_attack_chains", "threat_intel", "exploitation",
                "发现攻击链",
                {"web_application", "network_host"},
                {"vulnerability_assessment"},
                {"attack", "chain", "discover"},
                priority=7, execution_time="medium"),
        
        ToolNode("research_zero_day_opportunities", "threat_intel", "recon",
                "零日漏洞研究",
                {"web_application", "binary_executable"},
                {"vulnerability_assessment"},
                {"zero-day", "research"},
                priority=6, execution_time="slow"),
        
        ToolNode("correlate_threat_intelligence", "threat_intel", "recon",
                "威胁情报关联",
                set(),
                {"osint"},
                {"threat", "intel", "correlate"},
                priority=6, execution_time="medium"),
        
        ToolNode("advanced_payload_generation", "threat_intel", "exploitation",
                "高级Payload生成",
                {"web_application", "binary_executable"},
                {"waf_bypass", "binary_exploitation"},
                {"payload", "advanced", "evasion"},
                priority=7, is_aggressive=True, execution_time="medium"),
        
        ToolNode("vulnerability_intelligence_dashboard", "threat_intel", "reporting",
                "漏洞情报仪表板",
                set(),
                {"vulnerability_assessment"},
                {"dashboard", "intel"},
                priority=5, execution_time="fast"),
    ]
    
    for tool in forensics_tools:
        graph.add_tool(tool)


def _add_tool_scenario_edges(graph: ToolGraph) -> None:
    """建立工具-场景关系边"""
    
    # SQL注入场景
    sql_injection_tools = [
        ("sqlmap_scan", 1.0),
        ("intelligent_quick_test", 0.9),
        ("nuclei_scan", 0.7),
        ("browser_visit", 0.6),
        ("discover_injectable_params", 0.8),
        ("analyze_source_code", 0.7),
        ("ai_generate_payload", 0.6),
    ]
    
    # XSS场景
    xss_tools = [
        ("dalfox_xss_scan", 1.0),
        ("xsser_scan", 0.8),
        ("intelligent_quick_test", 0.9),
        ("nuclei_scan", 0.7),
        ("browser_visit", 0.6),
        ("discover_injectable_params", 0.7),
        ("ai_generate_payload", 0.6),
    ]
    
    # LFI/RFI场景
    lfi_tools = [
        ("dotdotpwn_scan", 0.9),
        ("intelligent_quick_test", 0.9),
        ("nuclei_scan", 0.8),
        ("ffuf_scan", 0.7),
        ("ai_generate_payload", 0.6),
    ]
    
    # 命令注入场景
    cmd_injection_tools = [
        ("intelligent_quick_test", 0.9),
        ("nuclei_scan", 0.8),
        ("ai_generate_payload", 0.7),
        ("analyze_source_code", 0.7),
    ]
    
    # 端口扫描场景
    port_scan_tools = [
        ("nmap_scan", 1.0),
        ("nmap_advanced_scan", 0.9),
        ("rustscan_fast_scan", 0.9),
        ("masscan_high_speed", 0.8),
        ("autorecon_comprehensive", 0.7),
    ]
    
    # 子域名枚举场景
    subdomain_tools = [
        ("amass_scan", 1.0),
        ("subfinder_scan", 0.9),
        ("fierce_scan", 0.7),
        ("dnsenum_scan", 0.7),
    ]
    
    # 目录发现场景
    dir_discovery_tools = [
        ("gobuster_scan", 1.0),
        ("feroxbuster_scan", 0.95),
        ("ffuf_scan", 0.9),
        ("dirsearch_scan", 0.85),
        ("dirb_scan", 0.7),
        ("katana_crawl", 0.8),
    ]
    
    # 参数发现场景
    param_discovery_tools = [
        ("arjun_parameter_discovery", 1.0),
        ("arjun_scan", 0.9),
        ("paramspider_mining", 0.85),
        ("x8_parameter_discovery", 0.8),
        ("discover_injectable_params", 0.9),
        ("browser_visit", 0.7),
        ("ffuf_scan", 0.6),
    ]
    
    # 认证绕过场景
    auth_bypass_tools = [
        ("smart_login_attempt", 0.9),
        ("hydra_attack", 0.8),
        ("bugbounty_authentication_bypass_testing", 0.85),
        ("jwt_analyzer", 0.8),
        ("browser_visit", 0.7),
    ]
    
    # SMB攻击场景
    smb_tools = [
        ("enum4linux_scan", 0.9),
        ("enum4linux_ng_advanced", 0.9),
        ("smbmap_scan", 0.85),
        ("netexec_scan", 0.9),
        ("rpcclient_enumeration", 0.7),
        ("responder_credential_harvest", 0.8),
    ]
    
    # 云配置错误场景
    cloud_tools = [
        ("prowler_scan", 1.0),
        ("scout_suite_assessment", 0.9),
        ("cloudmapper_analysis", 0.8),
        ("pacu_exploitation", 0.85),
        ("trivy_scan", 0.7),
        ("checkov_iac_scan", 0.8),
    ]
    
    # K8s攻击场景
    k8s_tools = [
        ("kube_hunter_scan", 1.0),
        ("kube_bench_cis", 0.9),
        ("trivy_scan", 0.7),
    ]
    
    # 容器逃逸场景
    container_tools = [
        ("docker_bench_security_scan", 0.9),
        ("trivy_scan", 0.8),
        ("clair_vulnerability_scan", 0.8),
        ("kube_hunter_scan", 0.7),
    ]
    
    # 二进制利用场景
    binary_tools = [
        ("gdb_analyze", 0.9),
        ("gdb_peda_debug", 0.95),
        ("pwntools_exploit", 1.0),
        ("checksec_analyze", 0.8),
        ("ropgadget_search", 0.85),
        ("ropper_gadget_search", 0.85),
        ("one_gadget_search", 0.8),
        ("ghidra_analysis", 0.8),
        ("radare2_analyze", 0.8),
        ("angr_symbolic_execution", 0.7),
    ]
    
    # ROP链场景
    rop_tools = [
        ("ropgadget_search", 1.0),
        ("ropper_gadget_search", 0.95),
        ("one_gadget_search", 0.9),
        ("pwntools_exploit", 0.9),
        ("gdb_peda_debug", 0.8),
    ]
    
    # API测试场景
    api_tools = [
        ("api_fuzzer", 0.9),
        ("graphql_scanner", 0.8),
        ("jwt_analyzer", 0.8),
        ("api_schema_analyzer", 0.85),
        ("comprehensive_api_audit", 0.9),
        ("arjun_parameter_discovery", 0.7),
        ("httpx_probe", 0.6),
    ]
    
    # GraphQL攻击场景
    graphql_tools = [
        ("graphql_scanner", 1.0),
        ("api_fuzzer", 0.7),
        ("nuclei_scan", 0.6),
    ]
    
    # JWT攻击场景
    jwt_tools = [
        ("jwt_analyzer", 1.0),
        ("bugbounty_authentication_bypass_testing", 0.8),
    ]
    
    # Bug Bounty场景
    bugbounty_tools = [
        ("bugbounty_reconnaissance_workflow", 0.9),
        ("bugbounty_vulnerability_hunting", 0.9),
        ("bugbounty_comprehensive_assessment", 0.95),
        ("bugbounty_osint_gathering", 0.8),
        ("amass_scan", 0.8),
        ("subfinder_scan", 0.8),
        ("nuclei_scan", 0.85),
        ("httpx_probe", 0.7),
    ]
    
    # CTF场景
    ctf_tools = [
        ("pwntools_exploit", 0.95),
        ("pwninit_setup", 0.9),
        ("gdb_peda_debug", 0.9),
        ("checksec_analyze", 0.85),
        ("ropgadget_search", 0.8),
        ("ghidra_analysis", 0.8),
        ("binwalk_analyze", 0.7),
    ]
    
    # 内存取证场景
    forensics_tools = [
        ("volatility_analyze", 1.0),
        ("volatility3_analyze", 0.95),
        ("foremost_carving", 0.7),
        ("strings_extract", 0.6),
    ]
    
    # 逆向工程场景
    reverse_tools = [
        ("ghidra_analysis", 1.0),
        ("radare2_analyze", 0.9),
        ("binwalk_analyze", 0.8),
        ("strings_extract", 0.7),
        ("objdump_analyze", 0.7),
        ("checksec_analyze", 0.6),
    ]
    
    # 技术检测场景
    tech_detect_tools = [
        ("httpx_probe", 0.9),
        ("wafw00f_scan", 0.85),
        ("wpscan_analyze", 0.8),
        ("nikto_scan", 0.7),
        ("detect_technologies_ai", 0.85),
    ]
    
    # OSINT场景
    osint_tools = [
        ("gau_discovery", 0.9),
        ("waybackurls_discovery", 0.9),
        ("paramspider_mining", 0.8),
        ("amass_scan", 0.8),
        ("subfinder_scan", 0.8),
        ("bugbounty_osint_gathering", 0.85),
    ]
    
    # WAF绕过场景
    waf_bypass_tools = [
        ("ai_generate_payload", 0.9),
        ("advanced_payload_generation", 0.95),
        ("dalfox_xss_scan", 0.7),
        ("wafw00f_scan", 0.8),
    ]
    
    # 漏洞评估场景
    vuln_assessment_tools = [
        ("nuclei_scan", 0.95),
        ("nikto_scan", 0.8),
        ("zap_scan", 0.85),
        ("intelligent_smart_scan", 0.9),
        ("ai_vulnerability_assessment", 0.85),
        ("vulnerability_intelligence_dashboard", 0.7),
    ]
    
    # 密码破解场景
    password_tools = [
        ("hashcat_crack", 1.0),
        ("john_crack", 0.9),
    ]
    
    # 暴力破解场景
    brute_force_tools = [
        ("hydra_attack", 1.0),
        ("netexec_scan", 0.8),
        ("smart_login_attempt", 0.7),
    ]
    
    # 建立所有场景边
    scenario_tool_mapping = {
        "sql_injection": sql_injection_tools,
        "xss_attack": xss_tools,
        "lfi_rfi": lfi_tools,
        "command_injection": cmd_injection_tools,
        "port_scan": port_scan_tools,
        "subdomain_enum": subdomain_tools,
        "directory_discovery": dir_discovery_tools,
        "parameter_discovery": param_discovery_tools,
        "auth_bypass": auth_bypass_tools,
        "smb_attack": smb_tools,
        "cloud_misconfiguration": cloud_tools,
        "k8s_attack": k8s_tools,
        "container_escape": container_tools,
        "binary_exploitation": binary_tools,
        "rop_chain": rop_tools,
        "api_testing": api_tools,
        "graphql_attack": graphql_tools,
        "jwt_attack": jwt_tools,
        "bug_bounty": bugbounty_tools,
        "ctf_challenge": ctf_tools,
        "memory_forensics": forensics_tools,
        "reverse_engineering": reverse_tools,
        "technology_detection": tech_detect_tools,
        "osint": osint_tools,
        "waf_bypass": waf_bypass_tools,
        "vulnerability_assessment": vuln_assessment_tools,
        "password_crack": password_tools,
        "brute_force": brute_force_tools,
    }
    
    for scenario, tools in scenario_tool_mapping.items():
        for tool_name, weight in tools:
            if graph.get_tool(tool_name):
                graph.add_edge(ToolEdge(
                    source=tool_name,
                    target=scenario,
                    relation=RelationType.SUITABLE_FOR.value,
                    weight=weight
                ))


def _add_tool_target_edges(graph: ToolGraph) -> None:
    """建立工具-目标类型关系边"""
    
    # 遍历所有工具，根据其target_types建立边
    for tool_name, tool in graph.tool_nodes.items():
        for target in tool.target_types:
            graph.add_edge(ToolEdge(
                source=tool_name,
                target=target,
                relation=RelationType.TARGETS.value,
                weight=1.0
            ))


def _add_tool_phase_edges(graph: ToolGraph) -> None:
    """建立工具-阶段关系边"""
    
    # 遍历所有工具，根据其phase建立边
    for tool_name, tool in graph.tool_nodes.items():
        graph.add_edge(ToolEdge(
            source=tool_name,
            target=tool.phase,
            relation=RelationType.BELONGS_TO.value,
            weight=1.0
        ))


def _add_tool_flow_edges(graph: ToolGraph) -> None:
    """建立工具执行顺序关系边"""
    
    # 侦察 -> 发现流程
    recon_to_discovery = [
        ("amass_scan", "httpx_probe", 0.9),
        ("subfinder_scan", "httpx_probe", 0.9),
        ("httpx_probe", "gobuster_scan", 0.8),
        ("httpx_probe", "feroxbuster_scan", 0.8),
        ("httpx_probe", "ffuf_scan", 0.8),
        ("httpx_probe", "nuclei_scan", 0.7),
        ("httpx_probe", "browser_visit", 0.9),
    ]
    
    # 页面感知流程
    page_awareness_flow = [
        ("browser_visit", "discover_injectable_params", 0.9),
        ("browser_visit", "crawl_site_endpoints", 0.8),
        ("browser_visit", "smart_login_attempt", 0.85),
        ("crawl_site_endpoints", "discover_injectable_params", 0.9),
        ("discover_injectable_params", "sqlmap_scan", 0.9),
        ("discover_injectable_params", "dalfox_xss_scan", 0.9),
        ("discover_injectable_params", "intelligent_quick_test", 0.95),
    ]
    
    # 目录发现 -> 漏洞扫描
    discovery_to_vuln = [
        ("gobuster_scan", "nuclei_scan", 0.8),
        ("feroxbuster_scan", "nuclei_scan", 0.8),
        ("ffuf_scan", "nuclei_scan", 0.8),
        ("dirsearch_scan", "nuclei_scan", 0.7),
        ("katana_crawl", "nuclei_scan", 0.8),
    ]
    
    # 参数发现 -> 漏洞测试
    param_to_vuln = [
        ("arjun_parameter_discovery", "sqlmap_scan", 0.9),
        ("arjun_parameter_discovery", "dalfox_xss_scan", 0.9),
        ("paramspider_mining", "sqlmap_scan", 0.8),
        ("paramspider_mining", "dalfox_xss_scan", 0.8),
        ("x8_parameter_discovery", "intelligent_quick_test", 0.85),
    ]
    
    # 端口扫描流程
    port_scan_flow = [
        ("rustscan_fast_scan", "nmap_scan", 0.9),
        ("masscan_high_speed", "nmap_scan", 0.85),
        ("nmap_scan", "nmap_advanced_scan", 0.7),
        ("nmap_scan", "enum4linux_scan", 0.8),
        ("nmap_scan", "smbmap_scan", 0.8),
    ]
    
    # OSINT流程
    osint_flow = [
        ("gau_discovery", "ffuf_scan", 0.8),
        ("waybackurls_discovery", "ffuf_scan", 0.8),
        ("gau_discovery", "paramspider_mining", 0.7),
    ]
    
    # 二进制分析流程
    binary_flow = [
        ("checksec_analyze", "gdb_analyze", 0.9),
        ("checksec_analyze", "gdb_peda_debug", 0.9),
        ("checksec_analyze", "ghidra_analysis", 0.8),
        ("ghidra_analysis", "ropgadget_search", 0.8),
        ("ropgadget_search", "pwntools_exploit", 0.9),
        ("one_gadget_search", "pwntools_exploit", 0.9),
    ]
    
    # 云安全流程
    cloud_flow = [
        ("prowler_scan", "pacu_exploitation", 0.7),
        ("scout_suite_assessment", "cloudmapper_analysis", 0.7),
    ]
    
    # 认证流程
    auth_flow = [
        ("browser_visit", "smart_login_attempt", 0.9),
        ("smart_login_attempt", "discover_injectable_params", 0.85),
    ]
    
    # 源码分析流程
    source_flow = [
        ("view_source_code", "analyze_source_code", 0.95),
        ("analyze_source_code", "intelligent_quick_test", 0.9),
    ]
    
    # 合并所有流程
    all_flows = (recon_to_discovery + page_awareness_flow + discovery_to_vuln +
                param_to_vuln + port_scan_flow + osint_flow + binary_flow +
                cloud_flow + auth_flow + source_flow)
    
    for source, target, weight in all_flows:
        if graph.get_tool(source) and graph.get_tool(target):
            graph.add_edge(ToolEdge(
                source=source,
                target=target,
                relation=RelationType.FOLLOWS.value,
                weight=weight
            ))


def _add_tool_alternative_edges(graph: ToolGraph) -> None:
    """建立工具替代关系边"""
    
    alternatives = [
        # 目录扫描替代
        ("gobuster_scan", "feroxbuster_scan"),
        ("gobuster_scan", "ffuf_scan"),
        ("gobuster_scan", "dirsearch_scan"),
        ("gobuster_scan", "dirb_scan"),
        ("feroxbuster_scan", "ffuf_scan"),
        
        # 端口扫描替代
        ("nmap_scan", "rustscan_fast_scan"),
        ("nmap_scan", "masscan_high_speed"),
        ("rustscan_fast_scan", "masscan_high_speed"),
        
        # 子域名枚举替代
        ("amass_scan", "subfinder_scan"),
        
        # SMB枚举替代
        ("enum4linux_scan", "enum4linux_ng_advanced"),
        ("enum4linux_scan", "smbmap_scan"),
        
        # XSS扫描替代
        ("dalfox_xss_scan", "xsser_scan"),
        
        # 参数发现替代
        ("arjun_parameter_discovery", "arjun_scan"),
        ("arjun_parameter_discovery", "x8_parameter_discovery"),
        
        # 二进制分析替代
        ("ghidra_analysis", "radare2_analyze"),
        ("gdb_analyze", "gdb_peda_debug"),
        ("ropgadget_search", "ropper_gadget_search"),
        
        # 内存取证替代
        ("volatility_analyze", "volatility3_analyze"),
        
        # 云安全替代
        ("prowler_scan", "scout_suite_assessment"),
        
        # 密码破解替代
        ("hashcat_crack", "john_crack"),
    ]
    
    for source, target in alternatives:
        if graph.get_tool(source) and graph.get_tool(target):
            # 双向替代关系
            graph.add_edge(ToolEdge(
                source=source,
                target=target,
                relation=RelationType.ALTERNATIVE_TO.value,
                weight=0.8
            ))
            graph.add_edge(ToolEdge(
                source=target,
                target=source,
                relation=RelationType.ALTERNATIVE_TO.value,
                weight=0.8
            ))


# ============================================================================
# 便捷函数
# ============================================================================

def build_default_hexstrike_tool_graph() -> ToolGraph:
    """构建默认的HexStrike工具图谱（兼容旧接口）"""
    return build_hexstrike_tool_graph()


def get_tools_for_url(graph: ToolGraph, url: str) -> list:
    """根据URL智能推荐工具
    
    Args:
        graph: 工具图谱
        url: 目标URL
        
    Returns:
        推荐的工具列表
    """
    url_lower = url.lower()
    
    # 识别场景
    scenarios = []
    targets = []
    
    # URL特征识别
    if "sqli" in url_lower or "sql" in url_lower:
        scenarios.append("sql_injection")
    if "xss" in url_lower:
        scenarios.append("xss_attack")
    if "lfi" in url_lower or "rfi" in url_lower or "file" in url_lower:
        scenarios.append("lfi_rfi")
    if "login" in url_lower or "auth" in url_lower or "signin" in url_lower:
        scenarios.append("auth_bypass")
        targets.append("login_page")
    if "api" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower:
        scenarios.append("api_testing")
        targets.append("api_endpoint")
    if "graphql" in url_lower:
        scenarios.append("graphql_attack")
        targets.append("graphql_api")
    if "wp-" in url_lower or "wordpress" in url_lower:
        targets.append("wordpress_site")
    
    # 默认Web应用
    if url_lower.startswith("http"):
        targets.append("web_application")
        if not scenarios:
            scenarios.append("vulnerability_assessment")
    
    # 查询工具
    all_tools = set()
    for scenario in scenarios:
        tools = graph.get_tools_for_scenario(scenario)
        all_tools.update(t.name for t in tools[:10])
    
    for target in targets:
        tools = graph.get_tools_for_target(target)
        all_tools.update(t.name for t in tools[:10])
    
    # 按优先级排序
    result = []
    for tool_name in all_tools:
        tool = graph.get_tool(tool_name)
        if tool:
            result.append(tool)
    
    result.sort(key=lambda x: -x.priority)
    return result[:30]
