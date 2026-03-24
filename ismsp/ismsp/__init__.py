"""
ismsp — ISMS-P AWS 컴플라이언스 자동화 패키지

구조:
    mappings/   1단계: ISMS-P ↔ AWS 매핑 테이블 JSON
    checker/    2단계: AWS 설정 수집(aws_checker) + 충족 판정(evaluator)
    reporter/   3단계: JSON/PDF 리포트 생성
"""
