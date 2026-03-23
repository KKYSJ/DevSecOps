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
    print(f"\n{'='*58}")
    print("  ISMS-P 자동화 점검 결과")
    print(f"{'='*58}")
    print(f"  계정:   {m['aws_account']}")
    print(f"  리전:   {m['region']}")
    print(f"  일시:   {m['checked_at']}")
    print(f"{'-'*58}")
    print(f"  자동화 {s['total_automated']}개 항목")
    print(f"    ✅ COMPLIANT:          {s['compliant']:3d}개")
    print(f"    ❌ NON_COMPLIANT:      {s['non_compliant']:3d}개")
    print(f"    ⚠️  INSUFFICIENT_DATA:  {s['insufficient_data']:3d}개")
    print(f"  준수율: {s['compliance_rate_pct']}%")
    print(f"  수동 심사: {len(report['manual_items'])}개")
    print(f"{'='*58}")

    nc = [r for r in report["automated_results"] if r["status"] == "NON_COMPLIANT"]
    if nc:
        print(f"\n  [미준수 {len(nc)}개]")
        for r in nc:
            print(f"    ❌ {r['isms_p_id']:7s} {r['isms_p_name']}")
            for d in r["check_details"]:
                if d["status"] == "NON_COMPLIANT" and d.get("reason"):
                    print(f"         → {d['check_id']}: {d['reason']}")
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

    # 결과 저장
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"isms_p_report_{ts}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print_summary(report)
    print(f"  📄 상세 결과: {out_file}\n")


if __name__ == "__main__":
    main()
