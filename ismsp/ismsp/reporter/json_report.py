"""
json_report.py
───────────────
역할: evaluator 결과 → 대시보드 연동용 JSON 리포트 생성
"""
import json
from pathlib import Path
from datetime import datetime


class JsonReporter:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)

    def save(self, report: dict) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.output_dir / f"isms_p_report_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        return path
