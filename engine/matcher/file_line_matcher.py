"""
파일 경로와 라인 번호 기반으로 두 도구의 findings를 매칭합니다.
같은 파일 경로이고 라인 번호가 허용 범위 내에 있는 finding 쌍을 찾습니다.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# 카테고리별 라인 수 허용 범위
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
    """같은 파일에서 라인 번호가 허용 범위 내인 finding 쌍을 찾습니다.

    Args:
        findings_a: 도구 A의 finding 목록
        findings_b: 도구 B의 finding 목록
        category: 카테고리 (라인 허용 범위 결정에 사용)
        line_tolerance: 라인 번호 허용 범위 (None이면 카테고리 기본값 사용)

    Returns:
        (finding_a, finding_b, correlation_key) 튜플 목록
    """
    if line_tolerance is None:
        line_tolerance = _LINE_TOLERANCE.get(category, _LINE_TOLERANCE["default"])

    matches = []

    # 도구 B의 findings를 파일 경로로 인덱싱
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

        for fb in candidates:
            if fb["id"] in matched_b_ids:
                continue

            line_b = fb.get("line_number")

            # 두 라인 번호 모두 있으면 허용 범위 비교
            if line_a is not None and line_b is not None:
                if abs(int(line_a) - int(line_b)) > line_tolerance:
                    continue
                # 정규화된 라인 번호 (5 단위 버킷)
                normalized_line = (int(line_a) // line_tolerance) * line_tolerance
                correlation_key = f"sast:{path_a}:{normalized_line}"
            else:
                # 라인 번호 없으면 파일 경로만으로 매칭
                correlation_key = f"sast:{path_a}:noline"

            matched_b_ids.add(fb["id"])
            matches.append((fa, fb, correlation_key))
            break  # 가장 가까운 하나만 매칭

    return matches


def _normalize_path(path: Optional[str]) -> Optional[str]:
    """파일 경로를 정규화합니다 (앞의 / 또는 ./ 제거)."""
    if not path:
        return None
    p = str(path).strip()
    # 앞에 "/" 제거
    while p.startswith("/"):
        p = p[1:]
    # 앞에 "./" 제거
    while p.startswith("./"):
        p = p[2:]
    return p if p else None
