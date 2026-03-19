"""
CWE ID 기반으로 두 도구의 findings를 매칭합니다.
동일한 CWE ID를 가진 finding 쌍을 찾습니다.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def match_by_cwe(
    findings_a: list[dict],
    findings_b: list[dict],
) -> list[tuple[dict, dict, str]]:
    """CWE ID가 동일한 finding 쌍을 찾습니다.

    Args:
        findings_a: 도구 A의 finding 목록
        findings_b: 도구 B의 finding 목록

    Returns:
        (finding_a, finding_b, correlation_key) 튜플 목록
    """
    matches = []

    # 도구 B의 findings를 CWE ID로 인덱싱
    b_by_cwe: dict[str, list[dict]] = {}
    for fb in findings_b:
        cwe = _normalize_cwe(fb.get("cwe_id"))
        if cwe:
            b_by_cwe.setdefault(cwe, []).append(fb)

    matched_b_ids = set()

    for fa in findings_a:
        cwe = _normalize_cwe(fa.get("cwe_id"))
        if not cwe:
            continue

        candidates = b_by_cwe.get(cwe, [])
        for fb in candidates:
            if fb["id"] in matched_b_ids:
                continue

            # 파일 경로도 같으면 더 강한 매치
            file_a = fa.get("file_path") or ""
            file_b = fb.get("file_path") or ""

            if file_a and file_b and file_a == file_b:
                correlation_key = f"sast:{file_a}:{cwe}"
            else:
                correlation_key = f"sast:cwe:{cwe}"

            matched_b_ids.add(fb["id"])
            matches.append((fa, fb, correlation_key))
            break  # 하나만 매칭

    return matches


def _normalize_cwe(cwe_id: Optional[str]) -> Optional[str]:
    """CWE ID를 정규화합니다 (예: "CWE-79" → "CWE-79")."""
    if not cwe_id:
        return None
    cwe_str = str(cwe_id).strip().upper()
    if cwe_str.startswith("CWE-"):
        return cwe_str
    if cwe_str.isdigit():
        return f"CWE-{cwe_str}"
    return None
