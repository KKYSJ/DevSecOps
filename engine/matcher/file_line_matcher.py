"""
파일 경로와 라인 번호 기반으로 두 도구의 findings를 매칭합니다.
같은 파일 경로이고 라인 번호가 허용 범위 내에 있는 finding 쌍을 찾습니다.

변경점:
- 첫 번째 후보가 아니라 가장 가까운 라인 후보를 선택
- SAST/IaC 모두 category prefix를 올바르게 반영
- 경로 정규화 강화
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

_LINE_TOLERANCE = {
    "SAST": 5,
    "IaC": 10,
    "default": 5,
}


def match_by_file_line(
    findings_a: list[dict],
    findings_b: list[dict],
    category: str = "SAST",
    line_tolerance: Optional[int] = None,
) -> list[tuple[dict, dict, str]]:
    """같은 파일에서 라인 번호가 허용 범위 내인 finding 쌍을 찾습니다."""
    if line_tolerance is None:
        line_tolerance = _LINE_TOLERANCE.get(category, _LINE_TOLERANCE["default"])

    matches = []
    prefix = category.lower()

    b_by_file: dict[str, list[dict]] = {}
    for fb in findings_b:
        path = _normalize_path(fb.get("file_path"))
        if path:
            b_by_file.setdefault(path, []).append(fb)

    matched_b_ids = set()

    for fa in findings_a:
        path_a = _normalize_path(fa.get("file_path"))
        if not path_a:
            continue

        line_a = fa.get("line_number")
        candidates = b_by_file.get(path_a, [])

        best = None
        best_dist = None

        for fb in candidates:
            if fb["id"] in matched_b_ids:
                continue

            line_b = fb.get("line_number")

            if line_a is not None and line_b is not None:
                dist = abs(int(line_a) - int(line_b))
                if dist > line_tolerance:
                    continue
            else:
                dist = 999999

            if best is None or dist < best_dist:
                best = fb
                best_dist = dist

        if best is None:
            continue

        if line_a is not None and best.get("line_number") is not None:
            normalized_line = (int(line_a) // line_tolerance) * line_tolerance
            correlation_key = f"{prefix}:{path_a}:{normalized_line}"
        else:
            correlation_key = f"{prefix}:{path_a}:noline"

        matched_b_ids.add(best["id"])
        matches.append((fa, best, correlation_key))

    return matches


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