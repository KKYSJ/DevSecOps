"""
json_report.py
───────────────
역할: evaluator 결과 → 대시보드 연동용 JSON 저장

출력 파일 두 가지:
    isms_p_report_{ts}.json     ← 전체 데이터 (백엔드 DB 저장 / API 응답용)
    isms_p_summary_{ts}.json    ← summary + items 상태만 (대시보드 빠른 로딩용)

변경 이력:
    v2 — 분리 저장 추가, latest_report.json 심볼릭 저장
"""

import json
from datetime import datetime
from pathlib import Path


class JsonReporter:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)

    def save(self, report: dict) -> dict:
        """
        전체 리포트와 요약 리포트를 각각 저장.

        Returns:
            {"full": Path, "summary": Path, "latest": Path}
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # 1) 전체 리포트
        full_path = self.output_dir / f"isms_p_report_{ts}.json"
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        # 2) 요약 리포트 (대시보드 빠른 로딩용 — check_details 제외)
        summary_report = {
            "metadata": report["metadata"],
            "summary":  report["summary"],
            "items": [
                {k: v for k, v in item.items() if k != "check_details"}
                for item in report["items"]
            ],
        }
        summary_path = self.output_dir / f"isms_p_summary_{ts}.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_report, f, ensure_ascii=False, indent=2)

        # 3) latest_report.json — 항상 최신 결과를 가리킴
        latest_path = self.output_dir / "latest_report.json"
        with open(latest_path, "w", encoding="utf-8") as f:
            json.dump(summary_report, f, ensure_ascii=False, indent=2)

        return {"full": full_path, "summary": summary_path, "latest": latest_path}
