"""
main.py
────────
CLI 진입점. 수집·판정·리포트 호출만 담당합니다.
비즈니스 로직은 ismsp/ 패키지 안에 있습니다.

사용법:
    python main.py
    python main.py --profile my-profile --region ap-northeast-2
    python main.py --items 2.5.3 2.7.1
    python main.py --output-dir ./reports --verbose
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import boto3

from ismsp.config import DEFAULT_REGION, DEFAULT_PROFILE, LOG_LEVEL
from ismsp.checker.aws_checker import AWSChecker
from ismsp.checker.evaluator import Evaluator
from ismsp.reporter.json_report import JsonReporter


def parse_args():
    p = argparse.ArgumentParser(description="SecureFlow — ISMS-P AWS 자동 점검")
    p.add_argument("--profile",    default=DEFAULT_PROFILE, help="AWS CLI 프로파일")
    p.add_argument("--region",     default=DEFAULT_REGION,  help="AWS 리전")
    p.add_argument("--items",      nargs="+", default=None, help="평가할 항목 ID (미지정 시 27개 전체)")
    p.add_argument("--output-dir", default="./reports",     help="결과 저장 디렉토리")
    p.add_argument("--verbose", "-v", action="store_true",  help="상세 로그")
    return p.parse_args()


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else getattr(logging, LOG_LEVEL)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    for noisy in ("boto3", "botocore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def print_summary(report: dict):
    s = report["summary"]
    m = report["metadata"]
    items = report["items"]

    print(f"\n{'='*58}")
    print("  ISMS-P 자동화 점검 결과")
    print(f"{'='*58}")
    print(f"  계정:   {m['aws_account']}")
    print(f"  리전:   {m['region']}")
    print(f"  일시:   {m['checked_at']}")
    print(f"{'-'*58}")
    print(f"  전체 {s['total']}개 항목")
    print(f"    ✅ COMPLIANT:          {s['compliant']:3d}개")
    print(f"    ❌ NON_COMPLIANT:      {s['non_compliant']:3d}개")
    print(f"    ⚠️  INSUFFICIENT_DATA:  {s['insufficient_data']:3d}개")
    print(f"    📋 MANUAL_REQUIRED:   {s['manual_required']:3d}개")
    print(f"  자동화 준수율: {s['compliance_rate_pct']}%")
    print(f"{'='*58}")

    nc = [r for r in items if r["status"] == "NON_COMPLIANT"]
    if nc:
        print(f"\n  [미준수 {len(nc)}개]")
        for r in nc:
            print(f"    ❌ {r['isms_p_id']:7s} {r['isms_p_name']}")
            if r.get("reason"):
                print(f"         → {r['reason']}")
    print()


def main():
    args = parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # AWS 세션
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        identity = session.client("sts").get_caller_identity()
        logger.info(f"AWS 연결: account={identity['Account']} arn={identity['Arn']}")
    except Exception as e:
        logger.error(f"AWS 연결 실패: {e}")
        sys.exit(1)

    # 수집 + 판정
    checker   = AWSChecker(session, region=args.region)
    evaluator = Evaluator(checker)
    evaluator.load_mappings()
    report = evaluator.run(item_ids=args.items)

    # 결과 저장 (전체 + 요약 + latest)
    reporter = JsonReporter(output_dir=args.output_dir)
    paths = reporter.save(report)
    logger.info(f"결과 저장: {paths['full']}")

    print_summary(report)
    print(f"  📄 전체 결과:  {paths['full']}")
    print(f"  📊 요약 결과:  {paths['summary']}")
    print(f"  🔗 최신 결과:  {paths['latest']}\n")


if __name__ == "__main__":
    main()
