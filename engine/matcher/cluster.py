"""
여러 도구의 정규화된 결과를 카테고리별로 그룹화하고,
도구 쌍 간의 finding을 매칭하여 matched_pair 목록을 생성합니다.

교차 검증 쌍:
  SAST: sonarqube ↔ semgrep
  SCA:  trivy ↔ depcheck
  IaC:  tfsec ↔ checkov
  DAST: zap (단독)
"""

import logging
import re
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


def _normalize_path(path: Optional[str]) -> str:
    """도구별 차이를 줄이기 위해 파일 경로를 정규화합니다."""
    if not path:
        return ""

    p = str(path).strip().replace("\\", "/")

    while p.startswith("/"):
        p = p[1:]
    while p.startswith("./"):
        p = p[2:]

    # SonarQube component 예: backend:app/api/users.py
    if ":" in p and "/" in p:
        left, right = p.split(":", 1)
        if left and right:
            if not right.startswith(left + "/"):
                p = f"{left}/{right}"
            else:
                p = right

    p = re.sub(r"/+", "/", p)
    return p


def _normalize_text(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


def _normalize_pkg_key(name: Optional[str], version: Optional[str]) -> str:
    return f"{str(name or '').strip().lower()}:{str(version or '').strip().lower()}"


def _normalize_cve(cve: Optional[str]) -> str:
    return str(cve or "").strip().upper()


def _extract_base_resource(resource: Optional[str]) -> str:
    resource = str(resource or "").strip()
    if not resource:
        return ""
    parts = resource.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else resource


def _iac_issue_family(f: dict) -> str:
    """
    IaC finding의 '취약점 종류'를 느슨하지만 일관되게 식별하기 위한 키.
    normalized_type이 있으면 가장 우선 사용하고,
    없으면 rule/check/title/description에서 키워드를 추론합니다.
    """
    normalized_type = str(f.get("normalized_type") or "").strip().upper()
    if normalized_type:
        return normalized_type

    rule_id = str(f.get("rule_id") or f.get("check_id") or "").strip().upper()
    title = _normalize_text(
        f.get("title")
        or f.get("check_name")
        or f.get("rule_description")
        or f.get("description")
    )

    text = f"{rule_id} {title}"

    if "logging" in text:
        return "MISSING_BUCKET_LOGGING"
    if "public ingress" in text or "0.0.0.0/0" in text or "publicly accessible" in text:
        return "PUBLIC_INGRESS"
    if "encrypt" in text or "encryption" in text or "storage_encrypted" in text:
        return "STORAGE_ENCRYPTION"
    if "description" in text and "security group" in text:
        return "SECURITY_GROUP_DESCRIPTION"
    if "versioning" in text:
        return "MISSING_VERSIONING"
    if "public access" in text:
        return "PUBLIC_ACCESS"
    if "kms" in text:
        return "KMS_ENCRYPTION"

    return rule_id or "UNKNOWN"


def _make_correlation_key(category: str, finding_a: Optional[dict], finding_b: Optional[dict]) -> str:
    """correlation_key를 생성합니다."""
    if category == "SAST":
        fa = finding_a or finding_b or {}
        fb = finding_b or finding_a or {}

        file_path = _normalize_path(fa.get("file_path") or fb.get("file_path"))
        cwe_id = (fa.get("cwe_id") or fb.get("cwe_id") or "").strip().upper()
        line = fa.get("line_number") or fb.get("line_number") or ""

        if file_path and cwe_id:
            return f"sast:{file_path}:{cwe_id}"
        if file_path:
            return f"sast:{file_path}:{line}"
        if cwe_id:
            return f"sast:cwe:{cwe_id}"
        return f"sast:{fa.get('id', '') or fb.get('id', '')}"

    elif category == "SCA":
        fa = finding_a or finding_b or {}
        fb = finding_b or finding_a or {}

        cve_id = _normalize_cve(fa.get("cve_id") or fb.get("cve_id"))
        pkg_name = fa.get("package_name") or fb.get("package_name") or ""
        pkg_ver = fa.get("package_version") or fb.get("package_version") or ""

        if cve_id:
            return f"sca:{cve_id}"
        return f"sca:{_normalize_pkg_key(pkg_name, pkg_ver)}"

    elif category == "IaC":
        fa = finding_a or finding_b or {}
        fb = finding_b or finding_a or {}

        file_path = _normalize_path(fa.get("file_path") or fb.get("file_path"))
        resource = fa.get("_resource") or fa.get("resource") or fb.get("_resource") or fb.get("resource") or ""
        base_resource = _extract_base_resource(resource)
        family = _iac_issue_family(fa if fa else fb)

        if file_path and base_resource:
            return f"iac:{file_path}:{base_resource}:{family}"
        if base_resource:
            return f"iac:{base_resource}:{family}"
        return f"iac:{family}"

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

    # 1단계: CWE + 동일 파일 기준 매칭
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

    # 2단계: 같은 파일 + 라인 허용범위 기준 매칭
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

    # 3단계: 단독 finding
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

    b_by_cve: dict[str, list[dict]] = {}
    b_by_pkg: dict[str, list[dict]] = {}

    for fb in findings_b:
        cve = _normalize_cve(fb.get("cve_id"))
        if cve:
            b_by_cve.setdefault(cve, []).append(fb)

        pkg_key = _normalize_pkg_key(fb.get("package_name"), fb.get("package_version"))
        if pkg_key != ":":
            b_by_pkg.setdefault(pkg_key, []).append(fb)

    for fa in findings_a:
        if fa["id"] in matched_a:
            continue

        matched_fb = None
        corr_key = None

        cve = _normalize_cve(fa.get("cve_id"))
        if cve and cve in b_by_cve:
            for fb in b_by_cve[cve]:
                if fb["id"] not in matched_b:
                    matched_fb = fb
                    corr_key = f"sca:{cve}"
                    break

        if not matched_fb:
            pkg_key = _normalize_pkg_key(fa.get("package_name"), fa.get("package_version"))
            if pkg_key != ":" and pkg_key in b_by_pkg:
                for fb in b_by_pkg[pkg_key]:
                    if fb["id"] not in matched_b:
                        matched_fb = fb
                        corr_key = f"sca:{pkg_key}"
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

    # resource + issue_family 인덱스
    b_by_resource_family: dict[str, list[dict]] = {}

    for fb in findings_b:
        resource = fb.get("_resource") or fb.get("resource") or ""
        base_resource = _extract_base_resource(resource)
        family = _iac_issue_family(fb)

        if base_resource:
            b_by_resource_family.setdefault(f"{base_resource}|{family}", []).append(fb)

    for fa in findings_a:
        if fa["id"] in matched_a:
            continue

        matched_fb = None
        corr_key = None

        # 1차: 같은 resource + 같은 issue family
        resource_a = fa.get("_resource") or fa.get("resource") or ""
        base_resource_a = _extract_base_resource(resource_a)
        family_a = _iac_issue_family(fa)

        if base_resource_a:
            candidates = b_by_resource_family.get(f"{base_resource_a}|{family_a}", [])
            for fb in candidates:
                if fb["id"] in matched_b:
                    continue
                matched_fb = fb
                file_path = _normalize_path(fa.get("file_path") or fb.get("file_path"))
                corr_key = f"iac:{file_path}:{base_resource_a}:{family_a}"
                break

        # 2차: 같은 파일 + 라인 ±10 + 같은 issue family
        if not matched_fb:
            remaining_b = [fb for fb in findings_b if fb["id"] not in matched_b and _iac_issue_family(fb) == family_a]
            line_matches = match_by_file_line([fa], remaining_b, "IaC", line_tolerance=10)
            if line_matches:
                _, fb, line_corr_key = line_matches[0]
                matched_fb = fb
                corr_key = f"{line_corr_key}:{family_a}"

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


def run(tool_results: list[dict]) -> list[dict]:
    """여러 도구의 정규화된 결과를 받아 matched_pair 목록을 생성합니다."""
    findings_by_tool: dict[str, list[dict]] = {}
    for result in tool_results:
        tool = result.get("tool", "").lower()
        findings_by_tool[tool] = result.get("findings", [])

    all_pairs = []

    # SAST
    sonarqube_findings = findings_by_tool.get("sonarqube", [])
    semgrep_findings = findings_by_tool.get("semgrep", [])
    if sonarqube_findings or semgrep_findings:
        sast_pairs = _match_sast(sonarqube_findings, semgrep_findings)
        for pair in sast_pairs:
            pair["tool_a"] = "sonarqube"
            pair["tool_b"] = "semgrep"
        all_pairs.extend(sast_pairs)
        logger.info("SAST 매칭 완료: %d 쌍", len(sast_pairs))

    # SCA
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

    # IaC
    tfsec_findings = findings_by_tool.get("tfsec", [])
    checkov_findings = findings_by_tool.get("checkov", [])
    if tfsec_findings or checkov_findings:
        iac_pairs = _match_iac(tfsec_findings, checkov_findings)
        for pair in iac_pairs:
            pair["tool_a"] = "tfsec"
            pair["tool_b"] = "checkov"
        all_pairs.extend(iac_pairs)
        logger.info("IaC 매칭 완료: %d 쌍", len(iac_pairs))

    # DAST
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