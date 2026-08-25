"""Dedicated parsers for the first high-value tool families.

Parsers are deliberately conservative: they only create suspected/validated
findings when positive evidence is present. Raw results are always retained.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from .base import ToolResultAdapter, text_value, unwrap_result
from ..models import Evidence, Finding, FindingStatus, ToolExecutionRequest, ToolExecutionResult


def blob(data: Any) -> str:
    return text_value(data).lower()


def add_evidence(result: ToolExecutionResult, kind: str, summary: str, value: Any) -> Evidence:
    evidence = Evidence(kind=kind, summary=summary, value=value)
    result.evidence.append(evidence)
    return evidence


class NmapAdapter(ToolResultAdapter):
    tool_names = {"nmap_scan", "run_nmap", "nmap"}

    def normalize(self, request, raw_result, started_at, duration_ms):
        data = unwrap_result(raw_result)
        result = self.base_result(request, raw_result, started_at, duration_ms)
        text = result.stdout or text_value(data)
        ports = []
        for match in re.finditer(r"(?m)^(\d+)/(tcp|udp)\s+open\s+([^\s]+)(?:\s+(.*))?$", text):
            ports.append({"port": int(match.group(1)), "protocol": match.group(2), "service": match.group(3), "version": (match.group(4) or "").strip()})
        result.extensions["nmap"] = {"open_ports": ports}
        result.metrics.update({"adapter": "nmap", "open_port_count": len(ports)})
        result.summary = f"Nmap completed, {len(ports)} open ports parsed" if result.success else "Nmap failed"
        if ports:
            ev = add_evidence(result, "network_services", f"Discovered {len(ports)} open ports", ports)
        return result


class HttpxAdapter(ToolResultAdapter):
    tool_names = {"httpx_probe", "httpx_scan", "httpx"}

    def normalize(self, request, raw_result, started_at, duration_ms):
        data = unwrap_result(raw_result)
        result = self.base_result(request, raw_result, started_at, duration_ms)
        result.metrics["adapter"] = "httpx"
        result.extensions["httpx"] = data if isinstance(data, dict) else {"output": result.stdout}
        result.summary = "HTTP probing completed" if result.success else "HTTP probing failed"
        return result


class NucleiAdapter(ToolResultAdapter):
    tool_names = {"nuclei_scan", "run_nuclei", "nuclei"}
    severity_re = re.compile(r"\[(critical|high|medium|low|info)\]", re.I)

    def normalize(self, request, raw_result, started_at, duration_ms):
        data = unwrap_result(raw_result)
        result = self.base_result(request, raw_result, started_at, duration_ms)
        text = result.stdout or text_value(data)
        findings: List[Finding] = []
        for line in text.splitlines():
            severity_match = self.severity_re.search(line)
            if not severity_match:
                continue
            severity = severity_match.group(1).lower()
            # Nuclei output lines with a severity tag are evidence of a template match,
            # but remain suspected until a dedicated validation step confirms impact.
            ev = add_evidence(result, "nuclei_match", line[:300], line)
            template = line.split()[0].strip("[]") if line.split() else "nuclei_template"
            findings.append(Finding(
                type="nuclei_template_match",
                title=f"Nuclei match: {template}",
                target=request.target,
                severity=severity,
                confidence=0.75 if severity in {"critical", "high"} else 0.6,
                status=FindingStatus.SUSPECTED,
                description=line[:1000],
                evidence_refs=[ev.evidence_id],
                source_tools=[request.tool_name],
                extensions={"template": template},
            ))
        result.findings = findings
        result.metrics.update({"adapter": "nuclei", "finding_count": len(findings)})
        result.summary = f"Nuclei completed, {len(findings)} template matches parsed" if result.success else "Nuclei failed"
        return result


class SqlmapAdapter(ToolResultAdapter):
    tool_names = {"sqlmap_scan", "run_sqlmap", "sqlmap"}

    positive_patterns = [
        re.compile(r"parameter\s+['\"]?([\w.-]+)['\"]?\s+is\s+vulnerable", re.I),
        re.compile(r"identified the following injection point", re.I),
        re.compile(r"is vulnerable\. do you want to keep testing", re.I),
    ]

    def normalize(self, request, raw_result, started_at, duration_ms):
        data = unwrap_result(raw_result)
        result = self.base_result(request, raw_result, started_at, duration_ms)
        text = result.stdout or text_value(data)
        positive = any(pattern.search(text) for pattern in self.positive_patterns)
        # Structured booleans must be explicitly true; "vulnerable": false is not a hit.
        if isinstance(data, dict):
            positive = positive or data.get("vulnerable") is True or data.get("injectable") is True
        parameter = None
        match = self.positive_patterns[0].search(text)
        if match:
            parameter = match.group(1)
        dbms_match = re.search(r"back-end DBMS:\s*([^\r\n]+)", text, re.I)
        dbms = dbms_match.group(1).strip() if dbms_match else None
        result.extensions["sqlmap"] = {"vulnerable": positive, "parameter": parameter, "dbms": dbms}
        if positive:
            ev = add_evidence(result, "sqlmap_injection", "SQLMap reported an injection point", text[-4000:])
            result.findings.append(Finding(
                type="sql_injection",
                title="SQL injection",
                target=request.target,
                severity="high",
                confidence=0.9,
                status=FindingStatus.VALIDATED,
                parameter=parameter,
                description="SQLMap produced positive injection evidence.",
                evidence_refs=[ev.evidence_id],
                source_tools=[request.tool_name],
                extensions={"dbms": dbms},
            ))
        result.metrics.update({"adapter": "sqlmap", "finding_count": len(result.findings)})
        result.summary = "SQLMap confirmed an injection point" if positive else ("SQLMap completed without confirmed injection" if result.success else "SQLMap failed")
        return result


class DalfoxAdapter(ToolResultAdapter):
    tool_names = {"dalfox_scan", "run_dalfox", "dalfox"}

    def normalize(self, request, raw_result, started_at, duration_ms):
        data = unwrap_result(raw_result)
        result = self.base_result(request, raw_result, started_at, duration_ms)
        text = result.stdout or text_value(data)
        positive_lines = [line for line in text.splitlines() if re.search(r"\b(POC|VULN|VULNERABLE)\b", line, re.I)]
        if isinstance(data, dict) and data.get("vulnerable") is True and not positive_lines:
            positive_lines = [text_value(data.get("evidence") or data.get("payload") or data, 2000)]
        if positive_lines:
            ev = add_evidence(result, "dalfox_poc", "Dalfox reported an XSS proof", positive_lines[:20])
            result.findings.append(Finding(
                type="cross_site_scripting",
                title="Cross-site scripting",
                target=request.target,
                severity="medium",
                confidence=0.9,
                status=FindingStatus.VALIDATED,
                description="Dalfox produced a positive PoC line.",
                evidence_refs=[ev.evidence_id],
                source_tools=[request.tool_name],
            ))
        result.metrics.update({"adapter": "dalfox", "finding_count": len(result.findings)})
        result.summary = f"Dalfox completed, {len(result.findings)} validated findings" if result.success else "Dalfox failed"
        return result


class BrowserAdapter(ToolResultAdapter):
    tool_names = {"browser_visit", "browser_visit_page", "browser_agent_inspect", "browser_get_rendered_content"}

    def normalize(self, request, raw_result, started_at, duration_ms):
        data = unwrap_result(raw_result)
        result = self.base_result(request, raw_result, started_at, duration_ms)
        page_info = data.get("page_info", data) if isinstance(data, dict) else {}
        forms = page_info.get("forms", []) if isinstance(page_info, dict) else []
        links = page_info.get("links", []) if isinstance(page_info, dict) else []
        result.extensions["browser"] = {"form_count": len(forms), "link_count": len(links), "url": page_info.get("url") if isinstance(page_info, dict) else None}
        if forms:
            add_evidence(result, "forms", f"Browser found {len(forms)} forms", forms)
        result.metrics.update({"adapter": "browser", "form_count": len(forms), "link_count": len(links)})
        result.summary = f"Browser inspection completed: {len(forms)} forms, {len(links)} links" if result.success else "Browser inspection failed"
        return result


class WebSkillAdapter(ToolResultAdapter):
    tool_names = {"run_web_skill"}

    def normalize(self, request, raw_result, started_at, duration_ms):
        data = unwrap_result(raw_result)
        result = self.base_result(request, raw_result, started_at, duration_ms)
        if isinstance(data, dict):
            result.summary = text_value(data.get("summary"), 1000) or result.summary
            result.extensions["web_skill"] = {
                "skill_id": data.get("skill_id"),
                "run_id": data.get("run_id"),
                "timeline": data.get("timeline", []),
                "risk_score": data.get("risk_score"),
            }
            for item in data.get("findings", []) or []:
                if not isinstance(item, dict):
                    continue
                ev = add_evidence(result, "web_skill_finding", text_value(item.get("title") or item.get("type"), 300), item)
                result.findings.append(Finding(
                    type=str(item.get("type") or "web_finding"),
                    title=str(item.get("title") or item.get("type") or "Web finding"),
                    target=request.target,
                    severity=str(item.get("severity") or "medium").lower(),
                    confidence=float(item.get("confidence", 0.7)),
                    status=FindingStatus.SUSPECTED,
                    description=text_value(item.get("description") or item.get("evidence"), 1000),
                    evidence_refs=[ev.evidence_id],
                    source_tools=[request.tool_name],
                ))
        result.metrics.update({"adapter": "web_skill", "finding_count": len(result.findings)})
        return result
