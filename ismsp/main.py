"""
ISMS-P 자동 점검 파이프라인 진입점

전체 점검 흐름:
  1. AWS 설정 데이터 수집 (aws_checker.collect)
  2. ISMS-P 매핑에 따른 평가 (evaluator.evaluate)
  3. JSON 보고서 생성 (json_report.generate)
  4. PDF 보고서 생성 선택 사항 (pdf_report.generate)
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone

# 패키지 내 모듈 임포트
from ismsp.checker import aws_checker, evaluator
from ismsp.reporter import json_report, pdf_report

logger = logging.getLogger(__name__)


def _setup_logging(level: str = "INFO") -> None:
    """로깅 설정을 초기화합니다."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def run(
    region: str = None,
    output_json: str = None,
    output_pdf: str = None,
    log_level: str = "INFO",
) -> dict:
    """
    ISMS-P 전체 자동 점검 파이프라인을 실행합니다.

    Parameters
    ----------
    region : str, optional
        AWS 리전 (기본값: 환경 변수 AWS_DEFAULT_REGION 또는 'ap-northeast-2')
    output_json : str, optional
        JSON 보고서를 저장할 파일 경로
    output_pdf : str, optional
        PDF 보고서를 저장할 파일 경로
    log_level : str, optional
        로그 레벨 (DEBUG, INFO, WARNING, ERROR)

    Returns
    -------
    dict
        evaluator.evaluate()가 반환한 평가 결과 딕셔너리
    """
    _setup_logging(log_level)

    start_time = datetime.now(timezone.utc)
    logger.info("=" * 60)
    logger.info("ISMS-P 자동 점검을 시작합니다.")
    logger.info("=" * 60)

    # 1단계: AWS 설정 데이터 수집
    logger.info("[1/4] AWS 설정 데이터 수집 중...")
    aws_config = aws_checker.collect(region=region)
    logger.info("[1/4] 데이터 수집 완료.")

    # 2단계: ISMS-P 매핑에 따른 평가
    logger.info("[2/4] ISMS-P 점검 항목 평가 중...")
    mapping = evaluator.load_mapping()
    result = evaluator.evaluate(aws_config, mapping=mapping)
    logger.info(
        "[2/4] 평가 완료: 총 %d개 항목, 통과 %d개, 실패 %d개, N/A %d개 (통과율 %.1f%%)",
        result["total"],
        result["passed"],
        result["failed"],
        result["na"],
        result["pass_rate"],
    )

    # 3단계: JSON 보고서 생성
    logger.info("[3/4] JSON 보고서 생성 중...")
    report = json_report.generate(result)

    if output_json:
        json_report.save(report, output_json)
        logger.info("[3/4] JSON 보고서 저장 완료: %s", output_json)
    else:
        logger.info("[3/4] JSON 보고서 생성 완료 (파일 저장 안 함).")

    # 4단계: PDF 보고서 생성 (선택 사항)
    if output_pdf:
        logger.info("[4/4] PDF 보고서 생성 중: %s ...", output_pdf)
        try:
            pdf_report.generate(result, output_path=output_pdf)
            logger.info("[4/4] PDF 보고서 저장 완료: %s", output_pdf)
        except ImportError as exc:
            logger.warning("[4/4] PDF 생성 건너뜀: %s", exc)
        except Exception as exc:
            logger.error("[4/4] PDF 생성 중 오류 발생: %s", exc)
    else:
        logger.info("[4/4] PDF 출력 경로가 지정되지 않아 건너뜁니다.")

    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    logger.info("=" * 60)
    logger.info("ISMS-P 자동 점검 완료 (소요 시간: %.2f초)", elapsed)
    logger.info("=" * 60)

    return result


def _print_summary(result: dict) -> None:
    """터미널에 점검 결과 요약을 출력합니다."""
    sep = "-" * 60
    print(sep)
    print("  ISMS-P 자동 점검 결과 요약")
    print(sep)
    print(f"  총 점검 항목: {result['total']}개")
    print(f"  통과:         {result['passed']}개")
    print(f"  실패:         {result['failed']}개")
    print(f"  미해당(N/A): {result['na']}개")
    print(f"  통과율:       {result['pass_rate']:.1f}%")
    print(sep)

    by_cat = result.get("by_category", {})
    if by_cat:
        print("  카테고리별 결과:")
        for cat_id, cat in sorted(by_cat.items()):
            total = cat.get("total", 0)
            passed = cat.get("passed", 0)
            failed = cat.get("failed", 0)
            na = cat.get("na", 0)
            rate = f"{passed / (total - na) * 100:.0f}%" if (total - na) > 0 else "N/A"
            status_icon = "✓" if failed == 0 else "✗"
            print(f"  {status_icon} {cat_id} {cat.get('name', ''):<20} "
                  f"전체:{total} 통과:{passed} 실패:{failed} ({rate})")
        print(sep)

    failures = [i for i in result.get("items", []) if i["status"] == "FAIL"]
    if failures:
        print(f"  실패 항목 ({len(failures)}개):")
        for item in sorted(failures, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 9)):
            print(f"  [{item['severity']:8}] {item['id']} - {item['title']}")
        print(sep)


# ---------------------------------------------------------------------------
# CLI 진입점
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI 명령 파싱 및 실행."""
    parser = argparse.ArgumentParser(
        prog="ismsp",
        description="ISMS-P AWS 기술 통제 자동 점검 도구",
    )
    parser.add_argument(
        "--region", "-r",
        default=None,
        help="AWS 리전 (기본값: AWS_DEFAULT_REGION 환경 변수 또는 ap-northeast-2)",
    )
    parser.add_argument(
        "--output-json", "-j",
        default=None,
        metavar="PATH",
        help="JSON 보고서 저장 경로 (예: /tmp/isms_report.json)",
    )
    parser.add_argument(
        "--output-pdf", "-p",
        default=None,
        metavar="PATH",
        help="PDF 보고서 저장 경로 (예: /tmp/isms_report.pdf, reportlab 필요)",
    )
    parser.add_argument(
        "--log-level", "-l",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="로그 레벨 (기본값: INFO)",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="JSON 보고서를 stdout에 출력",
    )

    args = parser.parse_args()

    result = run(
        region=args.region,
        output_json=args.output_json,
        output_pdf=args.output_pdf,
        log_level=args.log_level,
    )

    _print_summary(result)

    if args.print_json:
        report = json_report.generate(result)
        print(json_report.to_json_string(report))

    # 실패 항목이 있으면 종료 코드 1 반환 (CI/CD 파이프라인 연동)
    sys.exit(1 if result["failed"] > 0 else 0)


if __name__ == "__main__":
    main()
