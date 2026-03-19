"""
여러 도구의 정규화된 결과를 카테고리별로 그룹화하고,
도구 쌍 간의 finding을 매칭하여 matched_pair 목록을 생성합니다.

교차 검증 쌍:
  SAST: sonarqube ↔ semgrep
  SCA:  trivy ↔ depcheck
  IaC:  tfsec ↔ checkov
  DAST: zap (단독)
"""

import hashlib
import logging
from typing import Optional

from engine.matcher.cwe_matcher import match_by_cwe
from engine.matcher.file_line_matcher import match_by_file_line

logger = logging.getLogger(__name__)

# 카테고리별 도구 쌍 정의
_CATEGORY_PAIRS = {
    "SAST": ("sonarqube", "semgrep"),
    "SCA": ("trivy", "depcheck"),
    "IaC": ("tfsec", "checkov"),
    "DAST": ("zap", None),  # DAST는 단독
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _max_severity(sev_a: Optional[str], sev_b: Optional[str]) -> str:
    """두 심각도 중 더 높은 값을 반환합니다."""
    order = _SEVERITY_ORDER
    idx_a = order.index(sev_a) if sev_a in order else len(order) - 1
    idx_b = order.index(sev_b) if sev_b in order else len(order) - 1
    return order[min(idx_a, idx_b)]


def _make_correlation_key(category: str, finding_a: Optional[dict], finding_b: Optional[dict]) -> str:
    """correlation_key를 생성합니다."""
    if category == "SAST":
        fa = finding_a or finding_b
        fb = finding_b or finding_a
        file_path = (fa or {}).get("file_path") or ""
        cwe_id = (fa or {}).get("cwe_id") or (fb or {}).get("cwe_id") or ""
        line = (fa or {}).get("line_number") or ""
        if cwe_id:
            return f"sast:{file_path}:{cwe_id}"
        return f"sast:{file_path}:{line}"

    elif category == "SCA":
        fa = finding_a or finding_b
        fb = finding_b or finding_a
        cve_id = (fa or {}).get("cve_id") or (fb or {}).get("cve_id") or ""
        pkg_name = (fa or {}).get("package_name") or ""
        pkg_ver = (fa or {}).get("package_version") or ""
        if cve_id:
            return f"sca:{cve_id}"
        return f"sca:{pkg_name}:{pkg_ver}"

    elif category == "IaC":
        fa = finding_a or finding_b
        fb = finding_b or finding_a
        file_path = (fa or {}).get("file_path") or ""
        resource = (fa or {}).get("_resource") or (fb or {}).get("_resource") or ""
        rule_id = (fa or {}).get("rule_id") or ""
        if resource:
            return f"iac:{file_path}:{resource}"
        return f"iac:{rule_id}"

    elif category == "DAST":
        fa = finding_a or {}
        url = fa.get("url") or ""
        rule_id = fa.get("rule_id") or ""
        return f"dast:{url}:{rule_id}"

    else:
        fa = finding_a or finding_b or {}
        return f"{category.lower()}:{fa.get('id', '')}"


def _match_sast(findings_a: list[dict], findings_b: list[dict]) -> list[dict]:
    """SAST 도구 쌍을 매칭합니다."""
    pairs = []
    matched_a = set()
    matched_b = set()

    # 1단계: CWE ID 기반 매칭
    cwe_matches = match_by_cwe(findings_a, findings_b)
    for fa, fb, corr_key in cwe_matches:
        if fa["id"] in matched_a or fb["id"] in matched_b:
            continue
        matched_a.add(fa["id"])
        matched_b.add(fb["id"])
        pairs.append({
            "category": "SAST",
            "correlation_key": corr_key,
            "confidence": "HIGH",
            "severity": _max_severity(fa.get("severity"), fb.get("severity")),
            "finding_a": fa,
            "finding_b": fb,
        })

    # 2단계: 파일+라인 기반 매칭 (아직 매칭 안 된 것들)
    remaining_a = [f for f in findings_a if f["id"] not in matched_a]
    remaining_b = [f for f in findings_b if f["id"] not in matched_b]
    line_matches = match_by_file_line(remaining_a, remaining_b, "SAST")
    for fa, fb, corr_key in line_matches:
        if fa["id"] in matched_a or fb["id"] in matched_b:
            continue
        matched_a.add(fa["id"])
        matched_b.add(fb["id"])
        pairs.append({
            "category": "SAST",
            "correlation_key": corr_key,
            "confidence": "HIGH",
            "severity": _max_severity(fa.get("severity"), fb.get("severity")),
            "finding_a": fa,
            "finding_b": fb,
        })

    # 3단계: 단독 finding (MEDIUM confidence)
    for fa in findings_a:
        if fa["id"] in matched_a:
            continue
        corr_key = _make_correlation_key("SAST", fa, None)
        pairs.append({
            "category": "SAST",
            "correlation_key": corr_key,
            "confidence": "MED",
            "severity": fa.get("severity", "MEDIUM"),
            "finding_a": fa,
            "finding_b": None,
        })

    for fb in findings_b:
        if fb["id"] in matched_b:
            continue
        corr_key = _make_correlation_key("SAST", None, fb)
        pairs.append({
            "category": "SAST",
            "correlation_key": corr_key,
            "confidence": "MED",
            "severity": fb.get("severity", "MEDIUM"),
            "finding_a": None,
            "finding_b": fb,
        })

    return pairs


def _match_sca(findings_a: list[dict], findings_b: list[dict]) -> list[dict]:
    """SCA 도구 쌍을 매칭합니다."""
    pairs = []
    matched_a = set()
    matched_b = set()

    # 인덱스 구축
    b_by_cve: dict[str, list[dict]] = {}
    b_by_pkg: dict[str, list[dict]] = {}
    for fb in findings_b:
        cve = fb.get("cve_id")
        if cve:
            b_by_cve.setdefault(cve, []).append(fb)
        pkg_key = f"{fb.get('package_name', '')}:{fb.get('package_version', '')}"
        b_by_pkg.setdefault(pkg_key, []).append(fb)

    for fa in findings_a:
        if fa["id"] in matched_a:
            continue

        matched_fb = None
        corr_key = None

        # CVE ID 매칭 우선
        cve = fa.get("cve_id")
        if cve and cve in b_by_cve:
            for fb in b_by_cve[cve]:
                if fb["id"] not in matched_b:
                    matched_fb = fb
                    corr_key = f"sca:{cve}"
                    break

        # 패키지명 + 버전 매칭
        if not matched_fb:
            pkg_key = f"{fa.get('package_name', '')}:{fa.get('package_version', '')}"
            if pkg_key != ":" and pkg_key in b_by_pkg:
                for fb in b_by_pkg[pkg_key]:
                    if fb["id"] not in matched_b:
                        matched_fb = fb
                        corr_key = f"sca:{fa.get('package_name', '')}:{fa.get('package_version', '')}"
                        break

        if matched_fb:
            matched_a.add(fa["id"])
            matched_b.add(matched_fb["id"])
            pairs.append({
                "category": "SCA",
                "correlation_key": corr_key,
                "confidence": "HIGH",
                "severity": _max_severity(fa.get("severity"), matched_fb.get("severity")),
                "finding_a": fa,
                "finding_b": matched_fb,
            })
        else:
            corr_key = _make_correlation_key("SCA", fa, None)
            pairs.append({
                "category": "SCA",
                "correlation_key": corr_key,
                "confidence": "MED",
                "severity": fa.get("severity", "MEDIUM"),
                "finding_a": fa,
                "finding_b": None,
            })

    for fb in findings_b:
        if fb["id"] in matched_b:
            continue
        corr_key = _make_correlation_key("SCA", None, fb)
        pairs.append({
            "category": "SCA",
            "correlation_key": corr_key,
            "confidence": "MED",
            "severity": fb.get("severity", "MEDIUM"),
            "finding_a": None,
            "finding_b": fb,
        })

    return pairs


def _match_iac(findings_a: list[dict], findings_b: list[dict]) -> list[dict]:
    """IaC 도구 쌍을 매칭합니다."""
    pairs = []
    matched_a = set()
    matched_b = set()

    # 리소스 식별자 인덱스 구축
    b_by_resource: dict[str, list[dict]] = {}
    b_by_file_line: dict[str, list[dict]] = {}

    for fb in findings_b:
        resource = fb.get("_resource") or fb.get("resource") or ""
        if resource:
            # 속성 경로 포함 리소스를 기본 리소스로도 인덱싱
            parts = resource.split(".")
            base_resource = ".".join(parts[:2]) if len(parts) >= 2 else resource
            b_by_resource.setdefault(base_resource, []).append(fb)
            if base_resource != resource:
                b_by_resource.setdefault(resource, []).append(fb)

        # 파일+라인 인덱스
        file_path = _normalize_path(fb.get("file_path") or "")
        line = fb.get("line_number")
        if file_path and line is not None:
            for bucket in range(int(line) - 10, int(line) + 11, 1):
                file_line_key = f"{file_path}:{bucket}"
                b_by_file_line.setdefault(file_line_key, []).append(fb)

    for fa in findings_a:
        if fa["id"] in matched_a:
            continue

        matched_fb = None
        corr_key = None

        # 리소스 기반 매칭
        resource_a = fa.get("_resource") or fa.get("resource") or ""
        if resource_a:
            parts = resource_a.split(".")
            base_resource_a = ".".join(parts[:2]) if len(parts) >= 2 else resource_a
            candidates = b_by_resource.get(base_resource_a, [])
            for fb in candidates:
                if fb["id"] not in matched_b:
                    matched_fb = fb
                    file_path = fa.get("file_path") or ""
                    corr_key = f"iac:{file_path}:{base_resource_a}"
                    break

        # 파일+라인 기반 매칭
        if not matched_fb:
            file_path_a = _normalize_path(fa.get("file_path") or "")
            line_a = fa.get("line_number")
            if file_path_a and line_a is not None:
                key = f"{file_path_a}:{int(line_a)}"
                candidates = b_by_file_line.get(key, [])
                for fb in candidates:
                    if fb["id"] not in matched_b:
                        normalized_line = (int(line_a) // 10) * 10
                        matched_fb = fb
                        corr_key = f"iac:{file_path_a}:{normalized_line}"
                        break

        if matched_fb:
            matched_a.add(fa["id"])
            matched_b.add(matched_fb["id"])
            pairs.append({
                "category": "IaC",
                "correlation_key": corr_key,
                "confidence": "HIGH",
                "severity": _max_severity(fa.get("severity"), matched_fb.get("severity")),
                "finding_a": fa,
                "finding_b": matched_fb,
            })
        else:
            corr_key = _make_correlation_key("IaC", fa, None)
            pairs.append({
                "category": "IaC",
                "correlation_key": corr_key,
                "confidence": "MED",
                "severity": fa.get("severity", "MEDIUM"),
                "finding_a": fa,
                "finding_b": None,
            })

    for fb in findings_b:
        if fb["id"] in matched_b:
            continue
        corr_key = _make_correlation_key("IaC", None, fb)
        pairs.append({
            "category": "IaC",
            "correlation_key": corr_key,
            "confidence": "MED",
            "severity": fb.get("severity", "MEDIUM"),
            "finding_a": None,
            "finding_b": fb,
        })

    return pairs


def _match_dast(findings: list[dict]) -> list[dict]:
    """DAST 단독 결과를 matched_pair 형식으로 변환합니다."""
    pairs = []
    for f in findings:
        corr_key = _make_correlation_key("DAST", f, None)
        pairs.append({
            "category": "DAST",
            "correlation_key": corr_key,
            "confidence": "MED",
            "severity": f.get("severity", "MEDIUM"),
            "finding_a": f,
            "finding_b": None,
        })
    return pairs


def _normalize_path(path: str) -> str:
    """파일 경로를 정규화합니다."""
    if not path:
        return ""
    p = path.strip()
    while p.startswith("/"):
        p = p[1:]
    while p.startswith("./"):
        p = p[2:]
    return p


def run(tool_results: list[dict]) -> list[dict]:
    """여러 도구의 정규화된 결과를 받아 matched_pair 목록을 생성합니다.

    Args:
        tool_results: 정규화된 도구 결과 목록 (각각 'tool', 'category', 'findings' 포함)

    Returns:
        matched_pair dict 목록:
        {
            "category": "SAST",
            "tool_a": "sonarqube",
            "tool_b": "semgrep",
            "correlation_key": "sast:backend/app/main.py:CWE-78",
            "confidence": "HIGH",
            "severity": "HIGH",
            "finding_a": {...} or None,
            "finding_b": {...} or None,
        }
    """
    # 카테고리와 도구별로 findings 수집
    findings_by_tool: dict[str, list[dict]] = {}
    for result in tool_results:
        tool = result.get("tool", "").lower()
        findings_by_tool[tool] = result.get("findings", [])

    all_pairs = []

    # SAST 매칭
    sonarqube_findings = findings_by_tool.get("sonarqube", [])
    semgrep_findings = findings_by_tool.get("semgrep", [])
    if sonarqube_findings or semgrep_findings:
        sast_pairs = _match_sast(sonarqube_findings, semgrep_findings)
        for pair in sast_pairs:
            pair["tool_a"] = "sonarqube"
            pair["tool_b"] = "semgrep"
        all_pairs.extend(sast_pairs)
        logger.info("SAST 매칭 완료: %d 쌍", len(sast_pairs))

    # SCA 매칭
    trivy_findings = findings_by_tool.get("trivy", [])
    depcheck_findings = (
        findings_by_tool.get("depcheck", [])
        or findings_by_tool.get("dependency-check", [])
    )
    if trivy_findings or depcheck_findings:
        sca_pairs = _match_sca(trivy_findings, depcheck_findings)
        for pair in sca_pairs:
            pair["tool_a"] = "trivy"
            pair["tool_b"] = "depcheck"
        all_pairs.extend(sca_pairs)
        logger.info("SCA 매칭 완료: %d 쌍", len(sca_pairs))

    # IaC 매칭
    tfsec_findings = findings_by_tool.get("tfsec", [])
    checkov_findings = findings_by_tool.get("checkov", [])
    if tfsec_findings or checkov_findings:
        iac_pairs = _match_iac(tfsec_findings, checkov_findings)
        for pair in iac_pairs:
            pair["tool_a"] = "tfsec"
            pair["tool_b"] = "checkov"
        all_pairs.extend(iac_pairs)
        logger.info("IaC 매칭 완료: %d 쌍", len(iac_pairs))

    # DAST 단독 처리
    zap_findings = (
        findings_by_tool.get("zap", [])
        or findings_by_tool.get("owasp-zap", [])
    )
    if zap_findings:
        dast_pairs = _match_dast(zap_findings)
        for pair in dast_pairs:
            pair["tool_a"] = "zap"
            pair["tool_b"] = None
        all_pairs.extend(dast_pairs)
        logger.info("DAST 처리 완료: %d 항목", len(dast_pairs))

    logger.info("전체 매칭 완료: %d 쌍", len(all_pairs))
    return all_pairs
