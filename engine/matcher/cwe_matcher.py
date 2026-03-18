"""
CWE ID 기반으로 두 도구의 findings를 매칭합니다.
기본 원칙:
- 같은 CWE라고 해도 파일이 다르면 바로 매칭하지 않습니다.
- 같은 파일 내에서 가장 가까운 라인 후보를 우선 선택합니다.
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


def match_by_cwe(
    findings_a: list[dict],
    findings_b: list[dict],
) -> list[tuple[dict, dict, str]]:
    """CWE ID가 동일하고, 같은 파일에 위치한 finding 쌍을 찾습니다."""
    matches = []

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

        file_a = _normalize_path(fa.get("file_path"))
        line_a = fa.get("line_number")

        candidates = b_by_cwe.get(cwe, [])
        best = None
        best_dist = None

        for fb in candidates:
            if fb["id"] in matched_b_ids:
                continue

            file_b = _normalize_path(fb.get("file_path"))
            line_b = fb.get("line_number")

            # 같은 CWE여도 파일이 다르면 바로 매칭하지 않음
            if not file_a or not file_b or file_a != file_b:
                continue

            dist = 999999
            if line_a is not None and line_b is not None:
                dist = abs(int(line_a) - int(line_b))

            if best is None or dist < best_dist:
                best = fb
                best_dist = dist

        if best is not None:
            normalized_line = (int(line_a) // 5) * 5 if line_a is not None else "noline"
            correlation_key = f"sast:{file_a}:{cwe}:{normalized_line}"
            matched_b_ids.add(best["id"])
            matches.append((fa, best, correlation_key))

    return matches


def _normalize_cwe(cwe_id: Optional[str]) -> Optional[str]:
    """CWE ID를 정규화합니다."""
    if not cwe_id:
        return None

    cwe_str = str(cwe_id).strip().upper()
    if cwe_str.startswith("CWE-"):
        return cwe_str
    if cwe_str.isdigit():
        return f"CWE-{cwe_str}"

    match = re.search(r"CWE-(\d+)", cwe_str)
    if match:
        return f"CWE-{match.group(1)}"

    return None


def _normalize_path(path: Optional[str]) -> Optional[str]:
    """도구별 차이를 줄이기 위해 파일 경로를 정규화합니다."""
    if not path:
        return None

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
    return p if p else None