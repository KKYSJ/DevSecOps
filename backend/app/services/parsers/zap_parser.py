"""
OWASP ZAP JSON 출력 파서

ZAP 실행 명령 (자동 스캔):
    docker run -t owasp/zap2docker-stable zap-baseline.py \
        -t http://target -J zap-results.json

ZAP JSON 출력 구조 (전통적 리포트 포맷):
    {
      "@version": "2.14.0",
      "site": [
        {
          "@name": "http://localhost:3000",
          "@host": "localhost",
          "@port": "3000",
          "alerts": [
            {
              "pluginid": "40012",
              "alertRef": "40012-1",
              "name": "Cross Site Scripting (Reflected)",
              "riskcode": "3",    // 3=High, 2=Medium, 1=Low, 0=Informational
              "confidence": "2",  // 3=High, 2=Medium, 1=Low, 0=False Positive
              "riskdesc": "High (Medium)",
              "desc": "Cross-site Scripting (XSS) ...",
              "solution": "Phase: Architecture and Design ...",
              "reference": "https://owasp.org/...",
              "cweid": "79",
              "wascid": "8",
              "instances": [
                {
                  "uri": "http://localhost:3000/search?q=test",
                  "method": "GET",
                  "param": "q",
                  "attack": "<script>alert(1)</script>",
                  "evidence": ""
                }
              ],
              "count": "2"
            }
          ]
        }
      ]
    }

ZAP riskcode → 공통 severity 매핑:
    3 (High)          → HIGH
    2 (Medium)        → MEDIUM
    1 (Low)           → LOW
    0 (Informational) → INFO
"""

import hashlib
from datetime import datetime, timezone


_RISK_SEVERITY_MAP = {
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO",
}


def _normalize_severity(riskcode: str) -> str:
    return _RISK_SEVERITY_MAP.get(str(riskcode), "MEDIUM")


def _make_finding_id(plugin_id: str, uri: str, param: str) -> str:
    raw = f"zap:{plugin_id}:{uri}:{param}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _parse_alert(alert: dict, site_name: str) -> list[dict]:
    """
    ZAP alert 1개는 여러 instances를 가질 수 있음.
    각 instance를 별도 finding으로 변환 (더 정확한 추적을 위해).
    instances가 없으면 alert 자체를 1개 finding으로 처리.
    """
    plugin_id: str = str(alert.get("pluginid", "unknown"))
    name: str = alert.get("name", alert.get("alert", "Unknown Alert"))
    riskcode: str = str(alert.get("riskcode", "0"))
    desc: str = alert.get("desc", "")
    solution: str = alert.get("solution", "")
    reference: str = alert.get("reference", "")
    cwe_raw: str = alert.get("cweid", "")

    cwe_id = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw != "-1" else None
    refs = [r.strip() for r in reference.split("\n") if r.strip()] if reference else []

    severity = _normalize_severity(riskcode)

    instances: list[dict] = alert.get("instances", [])
    if not instances:
        # instance 없이 alert만 있는 경우
        instances = [{"uri": site_name, "method": "", "param": "", "attack": "", "evidence": ""}]

    findings = []
    for inst in instances:
        uri: str = inst.get("uri", site_name)
        method: str = inst.get("method", "")
        param: str = inst.get("param", "")

        findings.append({
            "id": _make_finding_id(plugin_id, uri, param),
            "tool": "zap",
            "category": "DAST",
            "severity": severity,
            "title": name,
            "description": desc,
            "rule_id": plugin_id,
            "cwe_id": cwe_id,
            "cve_id": None,
            "file_path": None,
            "line_number": None,
            "url": uri,
            "http_method": method or None,
            "parameter": param or None,
            "package_name": None,
            "package_version": None,
            "fixed_version": None,
            "cvss_score": None,
            "remediation": solution or None,
            "references": refs,
        })

    return findings


def _build_summary(findings: list[dict]) -> dict:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f["severity"].lower()
        if key in summary:
            summary[key] += 1
    return summary


class ZapParser:
    """OWASP ZAP JSON 출력을 공통 스키마로 변환"""

    def parse(self, raw: dict) -> dict:
        """
        Args:
            raw: ZAP JSON 리포트 딕셔너리 (site[] 포함)
        Returns:
            공통 스키마 딕셔너리
        """
        sites: list[dict] = raw.get("site", [])

        findings = []
        target = None

        for site in sites:
            site_name: str = site.get("@name", "")
            if not target:
                target = site_name

            for alert in site.get("alerts", []):
                findings.extend(_parse_alert(alert, site_name))

        return {
            "tool": "zap",
            "category": "DAST",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "findings": findings,
            "summary": _build_summary(findings),
        }
