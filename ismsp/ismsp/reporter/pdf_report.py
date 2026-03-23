"""
pdf_report.py
──────────────
역할: evaluator 결과 → 감사 증적 PDF 생성
      점검 일시 · AWS 계정 ID · 리전 · 항목별 판정 결과 · 수동 보완 사항 포함

구현 예정 (3단계). reportlab 사용.
"""
from pathlib import Path


class PdfReporter:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)

    def save(self, report: dict) -> Path:
        raise NotImplementedError("PDF 리포터는 3단계 구현 예정입니다.")
