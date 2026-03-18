"""
스캔 결과 파싱 Celery 태스크
"""

import logging

from backend.app.core.celery_app import celery_app
from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)


# 도구 → 카테고리 매핑
TOOL_CATEGORY = {
    "sonarqube": "SAST",
    "semgrep": "SAST",
    "trivy": "SCA",
    "depcheck": "SCA",
    "tfsec": "IaC",
    "checkov": "IaC",
    "zap": "DAST",
}


@celery_app.task(name="scan.process")
def process_scan(scan_id: int):
    """스캔 raw_result 파싱 → Vulnerability 저장 → Scan.status 업데이트"""
    _process_scan_sync(scan_id)


def _process_scan_sync(scan_id: int):
    """Celery 없이도 직접 호출 가능한 동기 처리 함수"""
    from backend.app.core.database import SessionLocal
    from backend.app.models.scan import Scan
    from backend.app.models.vulnerability import Vulnerability
    from backend.app.models.tool_result import ToolResult
    from backend.app.services import scan_service

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan ID {scan_id} not found")
            return

        scan.status = "processing"
        db.commit()

        # 1. 먼저 파싱 수행
        parsed = scan_service.process_tool_result(scan.tool, scan.raw_result or {})

        # 2. 번역기는 선택적으로 활성화
        translator = None
        try:
            from backend.app.services.translator_service import TranslatorService
            translator = TranslatorService()
        except Exception as te:
            logger.warning(f"Translator disabled: {te}")

        translated_findings = []

        # Vulnerability 행 저장
        for finding in parsed.get("findings", []):
            translated_finding = finding

            # 3. finding별 번역 실패도 전체 실패로 만들지 않음
            if translator is not None:
                try:
                    translated_finding = translator.translate_finding_fields(finding)
                except Exception as te:
                    logger.warning(f"Translation failed, original finding will be used: {te}")
                    translated_finding = finding

            translated_findings.append(translated_finding)

            conf = translated_finding.get("confidence", "MED") or "MED"
            if conf == "MEDIUM":
                conf = "MED"

            vuln = Vulnerability(
                scan_id=scan_id,
                tool=translated_finding.get("tool", scan.tool),
                category=translated_finding.get("category", scan.category),
                severity=translated_finding.get("severity", "MEDIUM"),
                title=str(translated_finding.get("title") or "Unknown")[:255],
                file_path=translated_finding.get("file_path"),
                line_number=translated_finding.get("line_number"),
                cwe_id=translated_finding.get("cwe_id"),
                cve_id=translated_finding.get("cve_id"),
                confidence=conf,
                description=(
                    str(translated_finding.get("description"))
                    if translated_finding.get("description") is not None
                    else None
                ),
                status="OPEN",
            )
            db.add(vuln)

        # ToolResult 저장
        # 번역된 결과도 같이 저장하고 싶으면 아래처럼 findings를 교체
        parsed["findings"] = translated_findings

        tool_result = ToolResult(
            name=scan.tool,
            status="ok",
            data={
                "scan_id": scan_id,
                "tool": scan.tool,
                "project_name": scan.project_name,
                "commit_hash": scan.commit_hash,
                "parsed": parsed,
            },
        )
        db.add(tool_result)

        scan.status = "done"
        db.commit()
        logger.info(f"Scan {scan_id} ({scan.tool}): {len(parsed.get('findings', []))} findings saved")

    except Exception as e:
        logger.exception(f"Scan processing failed scan_id={scan_id}: {e}")
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                db.commit()
        except Exception:
            pass
    finally:
        db.close()