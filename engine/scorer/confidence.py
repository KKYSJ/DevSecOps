"""
매칭 결과에서 최종 confidence 레벨을 결정합니다.

HIGH: 두 도구 모두 동일 finding을 탐지
MED: 한 도구만 탐지
LOW: 상충되는 결과 (예: 한 도구는 CRITICAL, 다른 도구는 INFO)
"""

import logging

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def determine(matched_pair: dict) -> str:
    """matched_pair에서 confidence 레벨을 결정합니다.

    Args:
        matched_pair: 매칭된 finding 쌍 dict

    Returns:
        "HIGH", "MED", "LOW" 중 하나
    """
    finding_a = matched_pair.get("finding_a")
    finding_b = matched_pair.get("finding_b")

    # 두 도구 모두 탐지
    if finding_a is not None and finding_b is not None:
        # 심각도가 크게 다르면 LOW confidence
        sev_a = finding_a.get("severity", "MEDIUM")
        sev_b = finding_b.get("severity", "MEDIUM")
        if _severity_gap(sev_a, sev_b) >= 3:
            return "LOW"
        return "HIGH"

    # 한 도구만 탐지
    if finding_a is not None or finding_b is not None:
        return "MED"

    # 둘 다 없음 (비정상 상태)
    return "LOW"


def _severity_gap(sev_a: str, sev_b: str) -> int:
    """두 심각도 간의 순서 차이를 반환합니다."""
    order = _SEVERITY_ORDER
    idx_a = order.index(sev_a) if sev_a in order else 2
    idx_b = order.index(sev_b) if sev_b in order else 2
    return abs(idx_a - idx_b)
