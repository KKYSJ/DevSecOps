"""
보안 스캔 도구별 파서 디스패처.
도구 이름과 raw dict를 받아 공통 finding 포맷으로 변환합니다.
"""

import logging
from datetime import datetime, timezone

from engine.normalizer.parsers import sonarqube, semgrep, trivy, depcheck, tfsec, checkov, zap

logger = logging.getLogger(__name__)

# 지원하는 도구 파서 매핑
PARSERS = {
    "sonarqube": sonarqube.parse,
    "semgrep": semgrep.parse,
    "trivy": trivy.parse,
    "depcheck": depcheck.parse,
    "dependency-check": depcheck.parse,  # 별칭
    "tfsec": tfsec.parse,
    "checkov": checkov.parse,
    "zap": zap.parse,
    "owasp-zap": zap.parse,  # 별칭
}


def normalize(tool_name: str, raw: dict) -> dict:
    """도구 이름과 raw 데이터를 받아 공통 finding 포맷으로 변환합니다.

    Args:
        tool_name: 도구 이름 (예: "sonarqube", "semgrep", "trivy", ...)
        raw: 도구의 원본 JSON 출력 dict

    Returns:
        공통 finding 포맷 dict

    Raises:
        ValueError: 지원하지 않는 도구인 경우
    """
    tool_key = tool_name.lower().strip()

    parser = PARSERS.get(tool_key)
    if parser is None:
        supported = ", ".join(sorted(set(PARSERS.keys())))
        raise ValueError(
            f"지원하지 않는 도구: '{tool_name}'. 지원 도구 목록: {supported}"
        )

    try:
        result = parser(raw)
        logger.info(
            "정규화 완료: tool=%s, findings=%d",
            tool_name,
            len(result.get("findings", [])),
        )
        return result
    except Exception as e:
        logger.error("도구 '%s' 파싱 중 오류 발생: %s", tool_name, e)
        # 파싱 실패 시 빈 결과 반환 (파이프라인이 중단되지 않도록)
        return _empty_result(tool_name)


def _empty_result(tool_name: str) -> dict:
    """파싱 실패 시 반환할 빈 결과 dict를 생성합니다."""
    # 도구별 카테고리 결정
    category_map = {
        "sonarqube": "SAST",
        "semgrep": "SAST",
        "trivy": "SCA",
        "depcheck": "SCA",
        "dependency-check": "SCA",
        "tfsec": "IaC",
        "checkov": "IaC",
        "zap": "DAST",
        "owasp-zap": "DAST",
    }
    category = category_map.get(tool_name.lower(), "SAST")

    return {
        "tool": tool_name,
        "category": category,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": None,
        "findings": [],
        "summary": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
    }
