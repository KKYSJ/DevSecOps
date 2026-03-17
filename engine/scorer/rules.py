"""
matched_pair 목록에 row_score와 judgement_code를 계산합니다.

점수 공식:
  row_score = severity_base × judgement_weight × confidence_weight

심각도 기준:
  CRITICAL=100, HIGH=40, MEDIUM=15, LOW=5, INFO=0

판정 가중치:
  TRUE_POSITIVE=1.0, REVIEW_NEEDED=0.6, FALSE_POSITIVE=0.0

신뢰도 가중치:
  HIGH=1.0, MED=0.8, LOW=0.5

게이트 결정:
  BLOCK:  CRITICAL TRUE_POSITIVE >= 1, 또는 total_score >= 100, 또는 HIGH TRUE_POSITIVE >= 3
  REVIEW: total_score 40~100, 또는 HIGH REVIEW_NEEDED >= 1
  ALLOW:  total_score < 40, CRITICAL = 0, HIGH TRUE_POSITIVE = 0
"""

import logging
from engine.scorer.confidence import determine as determine_confidence

logger = logging.getLogger(__name__)

SEVERITY_BASE = {
    "CRITICAL": 100,
    "HIGH": 40,
    "MEDIUM": 15,
    "LOW": 5,
    "INFO": 0,
}

JUDGEMENT_WEIGHT = {
    "TRUE_POSITIVE": 1.0,
    "REVIEW_NEEDED": 0.6,
    "FALSE_POSITIVE": 0.0,
}

CONFIDENCE_WEIGHT = {
    "HIGH": 1.0,
    "MED": 0.8,
    "LOW": 0.5,
}


def _rule_based_judgement(matched_pair: dict) -> str:
    """규칙 기반 판정을 수행합니다 (LLM 없이).

    두 도구 모두 탐지 → TRUE_POSITIVE
    한 도구만 탐지 → REVIEW_NEEDED
    """
    finding_a = matched_pair.get("finding_a")
    finding_b = matched_pair.get("finding_b")

    if finding_a is not None and finding_b is not None:
        return "TRUE_POSITIVE"
    elif finding_a is not None or finding_b is not None:
        return "REVIEW_NEEDED"
    else:
        return "REVIEW_NEEDED"


def score_pair(matched_pair: dict) -> dict:
    """단일 matched_pair에 점수를 계산합니다.

    Args:
        matched_pair: 매칭된 finding 쌍 dict

    Returns:
        judgement_code, confidence_level, row_score가 추가된 dict
    """
    pair = dict(matched_pair)

    # judgement_code가 없으면 규칙 기반으로 결정
    if not pair.get("judgement_code"):
        pair["judgement_code"] = _rule_based_judgement(pair)

    # confidence 결정
    confidence = determine_confidence(pair)
    # 이미 설정된 confidence 유지 (LLM 또는 매처에서 설정한 경우)
    if not pair.get("confidence_level"):
        pair["confidence_level"] = confidence
    else:
        confidence = pair["confidence_level"]

    judgement = pair.get("judgement_code", "REVIEW_NEEDED")
    severity = pair.get("severity", "MEDIUM")

    # 점수 계산
    base = SEVERITY_BASE.get(severity, 0)
    j_weight = JUDGEMENT_WEIGHT.get(judgement, 0.6)
    c_weight = CONFIDENCE_WEIGHT.get(confidence, 0.8)

    row_score = round(base * j_weight * c_weight, 2)
    pair["row_score"] = row_score

    # display_label 설정
    if judgement == "TRUE_POSITIVE":
        pair["display_label"] = "취약"
    elif judgement == "REVIEW_NEEDED":
        pair["display_label"] = "확인 필요"
    else:
        pair["display_label"] = "오탐"

    return pair


def run(matched_pairs: list[dict]) -> list[dict]:
    """모든 matched_pair에 점수를 계산합니다.

    Args:
        matched_pairs: 매칭된 finding 쌍 목록

    Returns:
        점수가 추가된 matched_pair 목록
    """
    scored = []
    for pair in matched_pairs:
        try:
            scored_pair = score_pair(pair)
            scored.append(scored_pair)
        except Exception as e:
            logger.warning("점수 계산 실패, 건너뜀: %s", e)
            pair["row_score"] = 0.0
            pair.setdefault("judgement_code", "REVIEW_NEEDED")
            pair.setdefault("confidence_level", "MED")
            pair.setdefault("display_label", "확인 필요")
            scored.append(pair)

    logger.info("점수 계산 완료: %d 쌍, 총점=%.1f", len(scored), sum(p.get("row_score", 0) for p in scored))
    return scored


def compute_gate_decision(scored_pairs: list[dict]) -> str:
    """scored_pairs에서 게이트 결정을 계산합니다.

    Returns:
        "BLOCK", "REVIEW", "ALLOW" 중 하나
    """
    total_score = sum(p.get("row_score", 0) for p in scored_pairs)

    critical_tp = sum(
        1 for p in scored_pairs
        if p.get("severity") == "CRITICAL" and p.get("judgement_code") == "TRUE_POSITIVE"
    )
    high_tp = sum(
        1 for p in scored_pairs
        if p.get("severity") == "HIGH" and p.get("judgement_code") == "TRUE_POSITIVE"
    )
    high_rn = sum(
        1 for p in scored_pairs
        if p.get("severity") == "HIGH" and p.get("judgement_code") == "REVIEW_NEEDED"
    )

    # BLOCK 조건
    if critical_tp >= 1 or total_score >= 100 or high_tp >= 3:
        return "BLOCK"

    # REVIEW 조건
    if 40 <= total_score < 100 or high_rn >= 1:
        return "REVIEW"

    # ALLOW 조건
    return "ALLOW"
