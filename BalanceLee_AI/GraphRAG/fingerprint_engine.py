"""
HexStrike Fingerprint Engine - 网页指纹提取和分析

基于HTTP响应头、HTML特征、CMS检测等进行指纹识别，
为工具选择提供上下文信息。
"""

from __future__ import annotations

import re
import hashlib
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse
import json


@dataclass
class WebFingerprint:
    """网页指纹信息"""
    
    # 基础信息
    url: str
    domain: str
    
    # 服务器信息
    server: Optional[str] = None
    powered_by: Optional[str] = None
    
    # 技术栈
    technologies: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    cms: Optional[str] = None
    
    # 安全特征
    waf_detected: Optional[str] = None
    security_headers: List[str] = field(default_factory=list)
    
    # 页面特征
    has_login_form: bool = False
    has_search_box: bool = False
    has_file_upload: bool = False
    has_forms: bool = False
    
    # 参数特征
    has_get_params: bool = False
    has_post_params: bool = False
    param_types: Set[str] = field(default_factory=set)
    
    # 内容特征
    page_title: Optional[str] = None
    meta_generator: Optional[str] = None
    javascript_libraries: List[str] = field(default_factory=list)
    
    # 置信度
    confidence: float = 0.0


class WebFingerprintExtractor:
    """网页指纹提取器"""
    
    def __init__(self):
        # CMS指纹规则
        self.cms_patterns = {
            "WordPress": [
                r"wp-content",
                r"wp-includes",
                r"wp-admin",
                r"wordpress",
                r"<meta name=\"generator\" content=\"WordPress",
            ],
            "Drupal": [
                r"sites/default/files",
                r"misc/drupal\.js",
                r"<meta name=\"generator\" content=\"Drupal",
                r"Drupal\.settings",
            ],
            "Joomla": [
                r"media/system/js",
                r"templates/system",
                r"<meta name=\"generator\" content=\"Joomla",
                r"option=com_",
            ],
            "Laravel": [
                r"laravel_session",
                r"_token",
                r"csrf-token",
                r"Laravel",
            ],
            "Django": [
                r"csrfmiddlewaretoken",
                r"django",
                r"__admin_media_prefix__",
            ],
            "Flask": [
                r"session=\.",
                r"flask",
            ],
            "Spring": [
                r"JSESSIONID",
                r"spring",
                r"j_spring_security",
            ],
        }
        
        # WAF指纹规则
        self.waf_patterns = {
            "Cloudflare": [
                r"cloudflare",
                r"cf-ray",
                r"__cfduid",
            ],
            "AWS WAF": [
                r"aws",
                r"x-amzn-",
                r"x-amz-",
            ],
            "ModSecurity": [
                r"mod_security",
                r"modsecurity",
            ],
            "F5 BIG-IP": [
                r"bigip",
                r"f5-bigip",
                r"BIGipServer",
            ],
            "Akamai": [
                r"akamai",
                r"ak-bmsc",
            ],
        }
        
        # 技术栈指纹
        self.tech_patterns = {
            "PHP": [
                r"\.php",
                r"PHPSESSID",
                r"X-Powered-By.*PHP",
            ],
            "ASP.NET": [
                r"\.aspx",
                r"ASP\.NET",
                r"__VIEWSTATE",
                r"__EVENTVALIDATION",
            ],
            "Java": [
                r"\.jsp",
                r"JSESSIONID",
                r"j_security_check",
            ],
            "Node.js": [
                r"express",
                r"connect\.sid",
                r"X-Powered-By.*Express",
            ],
            "Python": [
                r"\.py",
                r"django",
                r"flask",
            ],
            "Ruby": [
                r"\.rb",
                r"rails",
                r"_session_id",
            ],
        }
        
        # JavaScript库指纹
        self.js_library_patterns = {
            "jQuery": [r"jquery", r"\$\("],
            "React": [r"react", r"ReactDOM"],
            "Vue.js": [r"vue\.js", r"Vue\."],
            "Angular": [r"angular", r"ng-"],
            "Bootstrap": [r"bootstrap"],
            "D3.js": [r"d3\.js", r"d3\."],
        }
        
        # 参数类型模式
        self.param_type_patterns = {
            "id": r"\b(id|uid|pid|user_id|post_id)\b",
            "file": r"\b(file|path|filename|document)\b",
            "url": r"\b(url|link|redirect|callback)\b",
            "cmd": r"\b(cmd|command|exec|system)\b",
            "search": r"\b(search|query|q|keyword)\b",
            "email": r"\b(email|mail|e-mail)\b",
            "password": r"\b(password|passwd|pwd|pass)\b",
            "token": r"\b(token|csrf|auth|api_key)\b",
        }
    
    def extract_fingerprint(
        self,
        url: str,
        html: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> WebFingerprint:
        """
        提取网页指纹
        
        Args:
            url: 目标URL
            html: HTML内容
            headers: HTTP响应头
            params: URL参数
            
        Returns:
            WebFingerprint: 提取的指纹信息
        """
        parsed_url = urlparse(url)
        fingerprint = WebFingerprint(
            url=url,
            domain=parsed_url.netloc
        )
        
        # 分析HTTP头
        if headers:
            self._analyze_headers(fingerprint, headers)
        
        # 分析HTML内容
        if html:
            self._analyze_html(fingerprint, html)
        
        # 分析URL参数
        if params:
            self._analyze_params(fingerprint, params)
        
        # 计算置信度
        fingerprint.confidence = self._calculate_confidence(fingerprint)
        
        return fingerprint
    
    def _analyze_headers(self, fingerprint: WebFingerprint, headers: Dict[str, str]) -> None:
        """分析HTTP响应头"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # 服务器信息
        if "server" in headers_lower:
            fingerprint.server = headers_lower["server"]
        
        if "x-powered-by" in headers_lower:
            fingerprint.powered_by = headers_lower["x-powered-by"]
        
        # 安全头检测
        security_headers = [
            "x-frame-options", "x-xss-protection", "x-content-type-options",
            "strict-transport-security", "content-security-policy",
            "x-csrf-token", "x-requested-with"
        ]
        
        for header in security_headers:
            if header in headers_lower:
                fingerprint.security_headers.append(header)
        
        # 技术栈检测
        all_headers = " ".join(headers.values()).lower()
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, all_headers, re.IGNORECASE):
                    if tech not in fingerprint.technologies:
                        fingerprint.technologies.append(tech)
                    break
        
        # WAF检测
        for waf, patterns in self.waf_patterns.items():
            for pattern in patterns:
                if re.search(pattern, all_headers, re.IGNORECASE):
                    fingerprint.waf_detected = waf
                    break
            if fingerprint.waf_detected:
                break
    
    def _analyze_html(self, fingerprint: WebFingerprint, html: str) -> None:
        """分析HTML内容"""
        html_lower = html.lower()
        
        # 页面标题
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if title_match:
            fingerprint.page_title = title_match.group(1).strip()
        
        # Meta generator
        generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if generator_match:
            fingerprint.meta_generator = generator_match.group(1)
        
        # CMS检测
        for cms, patterns in self.cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    fingerprint.cms = cms
                    break
            if fingerprint.cms:
                break
        
        # 表单特征检测
        fingerprint.has_forms = bool(re.search(r"<form", html, re.IGNORECASE))
        fingerprint.has_login_form = bool(re.search(r'type=["\']password["\']', html, re.IGNORECASE))
        fingerprint.has_search_box = bool(re.search(r'(type=["\']search["\']|name=["\']search["\']|name=["\']q["\'])', html, re.IGNORECASE))
        fingerprint.has_file_upload = bool(re.search(r'type=["\']file["\']', html, re.IGNORECASE))
        
        # POST参数检测
        fingerprint.has_post_params = bool(re.search(r'method=["\']post["\']', html, re.IGNORECASE))
        
        # JavaScript库检测
        for lib, patterns in self.js_library_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    fingerprint.javascript_libraries.append(lib)
                    break
    
    def _analyze_params(self, fingerprint: WebFingerprint, params: Dict[str, Any]) -> None:
        """分析URL参数"""
        if params:
            fingerprint.has_get_params = True
            
            # 参数类型分析
            for param_name in params.keys():
                param_lower = param_name.lower()
                for param_type, pattern in self.param_type_patterns.items():
                    if re.search(pattern, param_lower, re.IGNORECASE):
                        fingerprint.param_types.add(param_type)
    
    def _calculate_confidence(self, fingerprint: WebFingerprint) -> float:
        """计算指纹置信度"""
        confidence = 0.0
        
        # 基础信息权重
        if fingerprint.server:
            confidence += 0.1
        if fingerprint.powered_by:
            confidence += 0.1
        
        # 技术栈权重
        confidence += len(fingerprint.technologies) * 0.15
        
        # CMS检测权重
        if fingerprint.cms:
            confidence += 0.2
        
        # 安全特征权重
        confidence += len(fingerprint.security_headers) * 0.05
        if fingerprint.waf_detected:
            confidence += 0.1
        
        # 页面特征权重
        feature_count = sum([
            fingerprint.has_login_form,
            fingerprint.has_search_box,
            fingerprint.has_file_upload,
            fingerprint.has_forms,
            fingerprint.has_get_params,
            fingerprint.has_post_params,
        ])
        confidence += feature_count * 0.05
        
        # 参数类型权重
        confidence += len(fingerprint.param_types) * 0.03
        
        return min(1.0, confidence)
    
    def fingerprint_to_context_features(self, fingerprint: WebFingerprint) -> List[str]:
        """将指纹转换为上下文特征列表"""
        features = []
        
        # 表单特征
        if fingerprint.has_login_form:
            features.append("has_login_form")
        if fingerprint.has_search_box:
            features.append("has_search_box")
        if fingerprint.has_file_upload:
            features.append("has_file_upload")
        if fingerprint.has_forms:
            features.append("has_forms")
        
        # 参数特征
        if fingerprint.has_get_params:
            features.append("has_get_params")
        if fingerprint.has_post_params:
            features.append("has_post_params")
        
        # 参数类型特征
        for param_type in fingerprint.param_types:
            features.append(f"has_{param_type}_param")
        
        # CMS特征
        if fingerprint.cms:
            features.append(f"cms_{fingerprint.cms.lower()}")
        
        # 技术栈特征
        for tech in fingerprint.technologies:
            features.append(f"{tech.lower()}_backend")
        
        # WAF特征
        if fingerprint.waf_detected:
            features.append(f"waf_{fingerprint.waf_detected.lower().replace(' ', '_')}")
        
        # 安全特征
        if fingerprint.security_headers:
            features.append("has_security_headers")
        
        return features


# 便捷函数
def extract_web_fingerprint(
    url: str,
    html: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None
) -> WebFingerprint:
    """便捷函数：提取网页指纹"""
    extractor = WebFingerprintExtractor()
    return extractor.extract_fingerprint(url, html, headers, params)


def fingerprint_to_features(fingerprint: WebFingerprint) -> List[str]:
    """便捷函数：将指纹转换为特征列表"""
    extractor = WebFingerprintExtractor()
    return extractor.fingerprint_to_context_features(fingerprint)