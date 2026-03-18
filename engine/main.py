"""
SecureFlow 보안 파이프라인 메인 엔트리포인트.

파이프라인 흐름:
  1. 정규화 (normalize): 각 도구의 raw 출력을 공통 포맷으로 변환
  2. 매칭 (match): 도구 쌍 간 finding 매칭
  3. 스코어링 (score): 점수 및 규칙 기반 판정 계산
  4. LLM 판정 (llm): TRUE_POSITIVE / REVIEW_NEEDED / FALSE_POSITIVE 판정
  5. 리포트 생성 (report): 대시보드 JSON 생성
"""

import json
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def run_pipeline(
    tool_results: list[dict],
    pipeline_info: dict = None,
    llm_enabled: bool = True,
) -> dict:
    """SecureFlow 보안 스캔 파이프라인 전체를 실행합니다.

    Args:
        tool_results: 도구별 raw 결과 목록
            각 항목 형식: {"tool": "semgrep", "raw": {...}}
        pipeline_info: 파이프라인 메타데이터 (report_id, target 등)
        llm_enabled: LLM 판정 활성화 여부

    Returns:
        dashboard_report JSON dict
    """
    if pipeline_info is None:
        pipeline_info = {}

    logger.info("SecureFlow 파이프라인 시작: %d개 도구 결과 처리", len(tool_results))

    # ─── 1단계: 정규화 ───────────────────────────────────────────────
    normalized_results = _step_normalize(tool_results)

    if not normalized_results:
        logger.warning("정규화된 결과가 없습니다. 빈 리포트를 생성합니다.")
        from engine.reporter import json_reporter
        return json_reporter.generate([], pipeline_info)

    # ─── 2단계: 매칭 ────────────────────────────────────────────────
    matched_pairs = _step_match(normalized_results)

    if not matched_pairs:
        logger.info("매칭된 finding이 없습니다.")
        from engine.reporter import json_reporter
        return json_reporter.generate([], pipeline_info)

    # ─── 3단계: 스코어링 (규칙 기반 초기 판정) ─────────────────────
    scored_pairs = _step_score(matched_pairs)

    # ─── 4단계: LLM 판정 ────────────────────────────────────────────
    if llm_enabled:
        scored_pairs = _step_llm(scored_pairs)
        # LLM 판정 후 점수 재계산
        scored_pairs = _step_score(scored_pairs)

    # ─── 5단계: 리포트 생성 ─────────────────────────────────────────
    report = _step_report(scored_pairs, pipeline_info)

    logger.info(
        "파이프라인 완료: gate=%s, total_score=%.1f",
        report.get("dashboard_report", {}).get("summary_cards", {}).get("gate_decision", "UNKNOWN"),
        report.get("dashboard_report", {}).get("summary_cards", {}).get("total_score", 0),
    )

    return report


def _step_normalize(tool_results: list[dict]) -> list[dict]:
    """각 도구의 raw 결과를 공통 포맷으로 정규화합니다."""
    from engine.normalizer.normalize import normalize

    normalized = []
    for item in tool_results:
        tool_name = item.get("tool", "")
        raw = item.get("raw", {})

        if not tool_name:
            logger.warning("도구 이름이 없는 항목 건너뜀: %s", item)
            continue

        if not isinstance(raw, dict):
            logger.warning("도구 '%s'의 raw 데이터가 dict가 아닙니다: %s", tool_name, type(raw))
            continue

        try:
            result = normalize(tool_name, raw)
            normalized.append(result)
            logger.info(
                "정규화 완료: tool=%s, findings=%d",
                tool_name,
                len(result.get("findings", [])),
            )
        except ValueError as e:
            logger.error("지원하지 않는 도구 '%s': %s", tool_name, e)
        except Exception as e:
            logger.error("도구 '%s' 정규화 실패: %s", tool_name, e)

    return normalized


def _step_match(normalized_results: list[dict]) -> list[dict]:
    """정규화된 결과를 도구 쌍 간 매칭합니다."""
    from engine.matcher.cluster import run as cluster_run

    try:
        matched = cluster_run(normalized_results)
        logger.info("매칭 완료: %d 쌍", len(matched))
        return matched
    except Exception as e:
        logger.error("매칭 단계 실패: %s", e)
        return []


def _step_score(matched_pairs: list[dict]) -> list[dict]:
    """matched_pair 목록에 점수와 규칙 기반 판정을 계산합니다."""
    from engine.scorer.rules import run as score_run

    try:
        scored = score_run(matched_pairs)
        logger.info(
            "스코어링 완료: %d 쌍, 총점=%.1f",
            len(scored),
            sum(p.get("row_score", 0) for p in scored),
        )
        return scored
    except Exception as e:
        logger.error("스코어링 단계 실패: %s", e)
        return matched_pairs


def _step_llm(scored_pairs: list[dict]) -> list[dict]:
    """LLM을 통해 각 카테고리별 교차 검증 판정을 수행합니다."""
    from engine.llm.client import call_llm
    from engine.llm.prompts import build_cross_validation_prompt, parse_llm_response

    # 카테고리별로 그룹화
    by_category: dict[str, list] = defaultdict(list)
    by_category_indices: dict[str, list] = defaultdict(list)

    for idx, pair in enumerate(scored_pairs):
        cat = pair.get("category", "UNKNOWN")
        by_category[cat].append(pair)
        by_category_indices[cat].append(idx)

    result_pairs = list(scored_pairs)

    for category, pairs in by_category.items():
        if not pairs:
            continue

        logger.info("LLM 판정 시작: category=%s, %d 쌍", category, len(pairs))

        try:
            # 프롬프트 생성
            prompt = build_cross_validation_prompt(category, pairs)

            # LLM 호출
            response = call_llm(prompt)

            # 응답 파싱 및 적용
            updated_pairs = parse_llm_response(response, pairs)

            # 결과를 원본 인덱스에 반영
            indices = by_category_indices[category]
            for local_idx, global_idx in enumerate(indices):
                if local_idx < len(updated_pairs):
                    result_pairs[global_idx] = updated_pairs[local_idx]

            logger.info("LLM 판정 완료: category=%s", category)

        except Exception as e:
            logger.error("LLM 판정 실패 (category=%s): %s. 규칙 기반 판정 유지", category, e)
            # 오류 시 기존 규칙 기반 판정 유지

    return result_pairs


def _step_report(scored_pairs: list[dict], pipeline_info: dict) -> dict:
    """scored_pairs에서 대시보드 JSON 리포트를 생성합니다."""
    from engine.reporter import json_reporter

    try:
        report = json_reporter.generate(scored_pairs, pipeline_info)
        logger.info("리포트 생성 완료: report_id=%s", report.get("dashboard_report", {}).get("report_id"))
        return report
    except Exception as e:
        logger.error("리포트 생성 실패: %s", e)
        # 최소한의 오류 리포트 반환
        return {
            "schema_version": "1.0.0",
            "dashboard_report": {
                "report_id": pipeline_info.get("report_id", "error-report"),
                "generated_at": _now_iso(),
                "error": str(e),
                "summary_cards": {
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "total_score": 0,
                    "gate_decision": "REVIEW",
                },
                "sections": [],
            },
        }


def _now_iso() -> str:
    """현재 UTC 시각을 ISO 8601 형식으로 반환합니다."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ─── CLI 진입점 ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="SecureFlow 보안 파이프라인")
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="도구 결과 JSON 파일 경로 (형식: [{tool, raw}, ...])",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="report.json",
        help="리포트 출력 파일 경로 (기본값: report.json)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="LLM 판정 비활성화 (규칙 기반만 사용)",
    )
    parser.add_argument(
        "--report-id",
        default=None,
        help="리포트 ID (기본값: 자동 생성)",
    )
    parser.add_argument(
        "--pdf",
        default=None,
        help="PDF 리포트 출력 경로 (옵션)",
    )

    args = parser.parse_args()

    # 입력 파일 로드
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            tool_results = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("입력 파일 로드 실패: %s", e)
        sys.exit(1)

    # 파이프라인 실행
    pipeline_info = {}
    if args.report_id:
        pipeline_info["report_id"] = args.report_id

    report = run_pipeline(
        tool_results=tool_results,
        pipeline_info=pipeline_info,
        llm_enabled=not args.no_llm,
    )

    # JSON 리포트 저장
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        logger.info("JSON 리포트 저장 완료: %s", args.output)
    except OSError as e:
        logger.error("JSON 리포트 저장 실패: %s", e)
        sys.exit(1)

    # PDF 리포트 생성 (요청된 경우)
    if args.pdf:
        try:
            from engine.reporter import pdf_reporter
            pdf_path = pdf_reporter.generate(report, args.pdf)
            logger.info("PDF 리포트 저장 완료: %s", pdf_path)
        except Exception as e:
            logger.error("PDF 생성 실패: %s", e)

    # 게이트 결정 출력
    gate = report.get("dashboard_report", {}).get("summary_cards", {}).get("gate_decision", "UNKNOWN")
    print(f"\n게이트 결정: {gate}")
    if gate == "BLOCK":
        sys.exit(1)
    elif gate == "REVIEW":
        sys.exit(2)
    else:
        sys.exit(0)
