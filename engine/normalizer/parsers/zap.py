"""
OWASP ZAP JSON 출력을 공통 finding 포맷으로 파싱합니다.
DAST 카테고리: 각 alert/instance가 하나의 finding입니다.
심각도: riskcode 3→HIGH, 2→MEDIUM, 1→LOW, 0→INFO
"""

import hashlib
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_RISKCODE_MAP = {
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO",
    3: "HIGH",
    2: "MEDIUM",
    1: "LOW",
    0: "INFO",
}

_RISK_NAME_MAP = {
    "HIGH": "HIGH",
    "HIGH (CONFIRMED)": "HIGH",
    "MEDIUM": "MEDIUM",
    "MEDIUM (CONFIRMED)": "MEDIUM",
    "LOW": "LOW",
    "LOW (CONFIRMED)": "LOW",
    "INFORMATIONAL": "INFO",
    "INFO": "INFO",
    "FALSE POSITIVE": None,  # 제외
}


def _normalize_severity(riskcode, risk_str: str = "") -> str | None:
    """ZAP riskcode 또는 risk 문자열을 공통 심각도로 변환합니다."""
    # riskcode 우선 처리
    if riskcode is not None:
        sev = _RISKCODE_MAP.get(riskcode)
        if sev:
            return sev
        # 문자열로도 시도
        sev = _RISKCODE_MAP.get(str(riskcode))
        if sev:
            return sev

    # risk 문자열 처리
    if risk_str:
        upper = risk_str.upper().strip()
        sev = _RISK_NAME_MAP.get(upper)
        if sev is None and upper == "FALSE POSITIVE":
            return None  # 명시적 제외 신호
        if sev:
            return sev

    return "INFO"


def _make_id(tool: str, alert_ref: str, url: str, param: str) -> str:
    """finding 고유 ID를 생성합니다 (md5 16자리 hex)."""
    raw = f"{tool}:{alert_ref}:{url}:{param}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _extract_cwe(cwe_id_str: str) -> str | None:
    """CWE ID 문자열을 정규화합니다."""
    if not cwe_id_str:
        return None
    cwe_str = str(cwe_id_str).strip()
    if cwe_str == "0" or cwe_str == "":
        return None
    if cwe_str.upper().startswith("CWE-"):
        return cwe_str.upper()
    if cwe_str.isdigit():
        return f"CWE-{cwe_str}"
    return cwe_str


def _parse_alert(alert: dict) -> list[dict]:
    """ZAP alert 항목을 finding 목록으로 변환합니다.
    각 instance를 별도 finding으로 생성합니다.
    """
    findings = []

    alert_name = alert.get("name") or alert.get("alert") or ""
    alert_ref = alert.get("alertRef") or alert.get("pluginid") or ""
    riskcode = alert.get("riskcode")
    risk_str = alert.get("risk") or ""
    description = alert.get("desc") or alert.get("description") or ""
    solution = alert.get("solution") or ""
    reference = alert.get("reference") or ""
    cwe_raw = alert.get("cweid") or alert.get("cwe") or ""
    wascid = alert.get("wascid") or ""

    # 심각도 결정
    severity = _normalize_severity(riskcode, risk_str)
    if severity is None:
        # FALSE POSITIVE로 명시된 경우 제외
        return []

    # CWE
    cwe_id = _extract_cwe(str(cwe_raw))

    # 참고 링크
    references = []
    if reference:
        for line in reference.split("\n"):
            line = line.strip()
            if line.startswith("http"):
                references.append(line)

    # instances 처리
    instances = alert.get("instances") or []

    if not instances:
        # instance가 없으면 alert 자체를 finding으로 생성
        url = alert.get("url") or alert.get("uri") or ""
        method = alert.get("method") or ""
        param = alert.get("param") or alert.get("parameter") or ""
        evidence = alert.get("evidence") or alert.get("attack") or ""

        finding_id = _make_id("zap", str(alert_ref), url, param)

        findings.append({
            "id": finding_id,
            "tool": "zap",
            "category": "DAST",
            "severity": severity,
            "title": alert_name,
            "description": description,
            "rule_id": str(alert_ref),
            "cwe_id": cwe_id,
            "cve_id": None,
            "file_path": None,
            "line_number": None,
            "url": url if url else None,
            "http_method": method.upper() if method else None,
            "parameter": param if param else None,
            "package_name": None,
            "package_version": None,
            "fixed_version": None,
            "cvss_score": None,
            "remediation": solution if solution else None,
            "references": references,
            "_evidence": evidence,
            "_wascid": wascid,
        })
    else:
        for instance in instances:
            try:
                url = instance.get("uri") or instance.get("url") or alert.get("url") or ""
                method = instance.get("method") or alert.get("method") or ""
                param = instance.get("param") or alert.get("param") or ""
                evidence = instance.get("evidence") or instance.get("attack") or ""

                finding_id = _make_id("zap", str(alert_ref), url, param)

                findings.append({
                    "id": finding_id,
                    "tool": "zap",
                    "category": "DAST",
                    "severity": severity,
                    "title": alert_name,
                    "description": description,
                    "rule_id": str(alert_ref),
                    "cwe_id": cwe_id,
                    "cve_id": None,
                    "file_path": None,
                    "line_number": None,
                    "url": url if url else None,
                    "http_method": method.upper() if method else None,
                    "parameter": param if param else None,
                    "package_name": None,
                    "package_version": None,
                    "fixed_version": None,
                    "cvss_score": None,
                    "remediation": solution if solution else None,
                    "references": references,
                    "_evidence": evidence,
                    "_wascid": wascid,
                })
            except Exception as e:
                logger.warning("ZAP instance 파싱 실패, 건너뜀: %s", e)
                continue

    return findings


def parse(raw: dict) -> dict:
    """OWASP ZAP JSON 출력을 공통 finding 포맷으로 변환합니다.

    Args:
        raw: ZAP JSON 출력 dict

    Returns:
        공통 finding 포맷 dict
    """
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings = []

    target_url = None

    # ZAP 출력 형식은 site 배열 또는 alerts 배열입니다
    sites = raw.get("site") or []

    if sites:
        # 사이트별 alerts 처리
        for site in (sites if isinstance(sites, list) else [sites]):
            site_name = site.get("@name") or site.get("name") or ""
            if not target_url:
                target_url = site_name

            alerts = site.get("alerts") or site.get("alert") or []
            for alert in (alerts if isinstance(alerts, list) else [alerts]):
                try:
                    site_findings = _parse_alert(alert)
                    findings.extend(site_findings)
                except Exception as e:
                    logger.warning("ZAP alert 파싱 실패, 건너뜀: %s", e)
                    continue
    else:
        # 최상위 alerts 배열 처리
        alerts = raw.get("alerts") or raw.get("alert") or []
        for alert in (alerts if isinstance(alerts, list) else [alerts]):
            try:
                site_findings = _parse_alert(alert)
                findings.extend(site_findings)
            except Exception as e:
                logger.warning("ZAP alert 파싱 실패, 건너뜀: %s", e)
                continue

    # 중복 finding 제거 (동일 ID)
    seen_ids = set()
    unique_findings = []
    for f in findings:
        if f["id"] not in seen_ids:
            seen_ids.add(f["id"])
            unique_findings.append(f)
    findings = unique_findings

    summary = _make_summary(findings)

    return {
        "tool": "zap",
        "category": "DAST",
        "scanned_at": scanned_at,
        "target": target_url,
        "findings": findings,
        "summary": summary,
    }


def _make_summary(findings: list) -> dict:
    """findings 목록에서 severity별 카운트를 집계합니다."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    return {
        "total": len(findings),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "info": counts["INFO"],
    }
