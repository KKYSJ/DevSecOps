"""
config.py
─────────
프로젝트 전체 설정값을 한 곳에 관리합니다.
aws_checker, evaluator, reporter 모두 여기서 import합니다.
"""

from pathlib import Path

# ── 경로 ──────────────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent
MAPPINGS_DIR = BASE_DIR / "mappings"

# 각 수집기가 실제 로드하는 파일 (27개 자동화 항목만)
AUTOMATABLE_MAPPING = MAPPINGS_DIR / "isms_p_automatable.json"
# 전체 101개 (감사 증적·리포트용)
FULL_MAPPING         = MAPPINGS_DIR / "isms_p_full_mapping.json"
# 74개 수동 항목 (리포트 참고용)
MANUAL_MAPPING       = MAPPINGS_DIR / "isms_p_manual.json"

# ── AWS 기본 설정 ──────────────────────────────────────────────────────────────
DEFAULT_REGION  = "ap-northeast-2"
DEFAULT_PROFILE = None          # None이면 환경변수/인스턴스 역할 사용

# ── 판정 기준 ──────────────────────────────────────────────────────────────────
# partial 항목: COMPLIANT 비율이 이 값 이상이면 INSUFFICIENT_DATA(경고) 처리
PARTIAL_COMPLIANT_THRESHOLD = 0.5

# ── 로깅 ──────────────────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"              # DEBUG | INFO | WARNING | ERROR
