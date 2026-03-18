"""
dashboard_report dict에서 PDF 리포트를 생성합니다.
reportlab을 사용합니다.
"""

import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

# 심각도별 색상 정의
_SEVERITY_COLORS = {
    "CRITICAL": (0.8, 0.0, 0.0),    # 진한 빨강
    "HIGH": (0.9, 0.3, 0.0),         # 주황
    "MEDIUM": (0.9, 0.7, 0.0),       # 노랑
    "LOW": (0.2, 0.6, 0.2),          # 초록
    "INFO": (0.4, 0.4, 0.8),         # 파랑
}

_JUDGEMENT_COLORS = {
    "TRUE_POSITIVE": (0.8, 0.0, 0.0),    # 빨강
    "REVIEW_NEEDED": (0.9, 0.5, 0.0),    # 주황
    "FALSE_POSITIVE": (0.3, 0.6, 0.3),   # 초록
}

_GATE_COLORS = {
    "BLOCK": (0.8, 0.0, 0.0),
    "REVIEW": (0.9, 0.5, 0.0),
    "ALLOW": (0.2, 0.6, 0.2),
}


def _check_reportlab():
    """reportlab이 설치되어 있는지 확인합니다."""
    try:
        from reportlab.lib.pagesizes import A4  # noqa
        return True
    except ImportError:
        return False


def generate(report: dict, output_path: str) -> str:
    """dashboard_report dict에서 PDF 리포트를 생성합니다.

    Args:
        report: dashboard_report JSON dict (generate()의 출력)
        output_path: PDF 저장 경로

    Returns:
        생성된 PDF 파일 경로
    """
    if not _check_reportlab():
        logger.error("reportlab이 설치되어 있지 않습니다. pip install reportlab으로 설치하세요.")
        # reportlab 없이 기본 텍스트 파일 생성
        return _generate_text_fallback(report, output_path)

    try:
        return _generate_pdf(report, output_path)
    except Exception as e:
        logger.error("PDF 생성 실패: %s", e)
        raise


def _generate_pdf(report: dict, output_path: str) -> str:
    """reportlab을 사용하여 PDF를 생성합니다."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Table, TableStyle,
        Spacer, HRFlowable, PageBreak
    )
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    # 한국어 폰트 등록 시도 (없으면 기본 폰트 사용)
    korean_font = "Helvetica"
    try:
        # 나눔고딕 등 한국어 폰트 경로 시도
        font_paths = [
            "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
            "/System/Library/Fonts/AppleSDGothicNeo.ttc",
            "C:/Windows/Fonts/malgun.ttf",
        ]
        for font_path in font_paths:
            if os.path.exists(font_path):
                pdfmetrics.registerFont(TTFont("Korean", font_path))
                korean_font = "Korean"
                break
    except Exception:
        pass

    # 출력 디렉토리 생성
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    dashboard = report.get("dashboard_report", report)
    report_id = dashboard.get("report_id", "report")
    generated_at = dashboard.get("generated_at", datetime.now().isoformat())
    summary_cards = dashboard.get("summary_cards", {})
    sections = dashboard.get("sections", [])

    # 스타일 설정
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleKorean",
        parent=styles["Title"],
        fontName=korean_font,
        fontSize=20,
        spaceAfter=6,
    )
    heading1_style = ParagraphStyle(
        "Heading1Korean",
        parent=styles["Heading1"],
        fontName=korean_font,
        fontSize=14,
        spaceAfter=4,
    )
    heading2_style = ParagraphStyle(
        "Heading2Korean",
        parent=styles["Heading2"],
        fontName=korean_font,
        fontSize=12,
        spaceAfter=3,
    )
    normal_style = ParagraphStyle(
        "NormalKorean",
        parent=styles["Normal"],
        fontName=korean_font,
        fontSize=9,
        leading=13,
    )
    small_style = ParagraphStyle(
        "SmallKorean",
        parent=styles["Normal"],
        fontName=korean_font,
        fontSize=8,
        leading=11,
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=20 * mm,
        bottomMargin=15 * mm,
    )

    story = []

    # 제목 페이지
    story.append(Paragraph("SecureFlow 보안 스캔 결과 리포트", title_style))
    story.append(Paragraph(f"리포트 ID: {report_id}", normal_style))
    story.append(Paragraph(f"생성 시각: {generated_at}", normal_style))
    story.append(Spacer(1, 10 * mm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 5 * mm))

    # 요약 카드
    story.append(Paragraph("요약", heading1_style))
    gate = summary_cards.get("gate_decision", "UNKNOWN")
    gate_color = _GATE_COLORS.get(gate, (0.5, 0.5, 0.5))

    summary_data = [
        ["항목", "값"],
        ["게이트 결정", gate],
        ["총점", str(summary_cards.get("total_score", 0))],
        ["CRITICAL", str(summary_cards.get("critical_count", 0))],
        ["HIGH", str(summary_cards.get("high_count", 0))],
        ["MEDIUM", str(summary_cards.get("medium_count", 0))],
        ["LOW", str(summary_cards.get("low_count", 0))],
    ]

    summary_table = Table(summary_data, colWidths=[80 * mm, 80 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), korean_font),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8 * mm))

    # 카테고리별 섹션
    for section in sections:
        story.append(Paragraph(section.get("title", ""), heading1_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Spacer(1, 3 * mm))

        rows = section.get("rows", [])
        if not rows:
            story.append(Paragraph("탐지된 취약점이 없습니다.", normal_style))
            story.append(Spacer(1, 5 * mm))
            continue

        tool_a_name = section.get("tool_a_name", "도구A")
        tool_b_name = section.get("tool_b_name", "도구B")
        target_label_name = section.get("target_label_name", "대상")

        # 테이블 헤더
        if tool_b_name:
            table_header = [
                target_label_name, "심각도", "판정", "신뢰도", "점수",
                f"{tool_a_name} 결과", f"{tool_b_name} 결과"
            ]
            col_widths = [35*mm, 18*mm, 22*mm, 15*mm, 12*mm, 38*mm, 38*mm]
        else:
            table_header = [
                target_label_name, "심각도", "판정", "신뢰도", "점수", f"{tool_a_name} 결과"
            ]
            col_widths = [40*mm, 20*mm, 25*mm, 18*mm, 12*mm, 60*mm]

        table_data = [table_header]

        for row in rows:
            severity = row.get("severity", "")
            judgement = row.get("judgement_code", "")
            target_label = row.get("target_label", "")

            # 긴 텍스트 줄임
            if len(target_label) > 40:
                target_label = target_label[:37] + "..."

            tool_a = row.get("tool_a", {})
            tool_b = row.get("tool_b", {})

            tool_a_result = tool_a.get("display_result", "탐지 안 됨")
            if len(tool_a_result) > 50:
                tool_a_result = tool_a_result[:47] + "..."

            if tool_b_name:
                tool_b_result = tool_b.get("display_result", "탐지 안 됨")
                if len(tool_b_result) > 50:
                    tool_b_result = tool_b_result[:47] + "..."

                table_data.append([
                    target_label,
                    severity,
                    row.get("display_label", ""),
                    row.get("confidence_level", ""),
                    str(row.get("row_score", 0)),
                    tool_a_result,
                    tool_b_result,
                ])
            else:
                table_data.append([
                    target_label,
                    severity,
                    row.get("display_label", ""),
                    row.get("confidence_level", ""),
                    str(row.get("row_score", 0)),
                    tool_a_result,
                ])

        table = Table(table_data, colWidths=col_widths, repeatRows=1)

        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), korean_font),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("ALIGN", (0, 1), (0, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
            ("PADDING", (0, 0), (-1, -1), 3),
            ("WORDWRAP", (0, 0), (-1, -1), True),
        ]

        # 심각도별 행 색상 적용
        for row_idx, row in enumerate(rows, start=1):
            severity = row.get("severity", "")
            sev_rgb = _SEVERITY_COLORS.get(severity)
            if sev_rgb and severity in ("CRITICAL", "HIGH"):
                r, g, b = sev_rgb
                # 밝은 버전으로 배경색 설정
                bg_color = colors.Color(min(r + 0.7, 1.0), min(g + 0.6, 1.0), min(b + 0.6, 1.0))
                table_style.append(("BACKGROUND", (0, row_idx), (-1, row_idx), bg_color))

        table.setStyle(TableStyle(table_style))
        story.append(table)
        story.append(Spacer(1, 5 * mm))

        # 상세 정보 (reason, action_text)
        for row in rows:
            reason = row.get("reason")
            action_text = row.get("action_text")
            if reason or action_text:
                target_label = row.get("target_label", "")
                story.append(Paragraph(
                    f"<b>[{row.get('row_id', '')}] {target_label}</b>",
                    small_style
                ))
                if reason:
                    story.append(Paragraph(f"분석: {reason}", small_style))
                if action_text:
                    story.append(Paragraph(f"조치: {action_text}", small_style))
                story.append(Spacer(1, 2 * mm))

        story.append(PageBreak())

    doc.build(story)
    logger.info("PDF 리포트 생성 완료: %s", output_path)
    return output_path


def _generate_text_fallback(report: dict, output_path: str) -> str:
    """reportlab 없을 때 텍스트 파일로 대체 생성합니다."""
    import json

    txt_path = output_path.replace(".pdf", ".txt") if output_path.endswith(".pdf") else output_path + ".txt"
    os.makedirs(os.path.dirname(os.path.abspath(txt_path)), exist_ok=True)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("SecureFlow 보안 스캔 결과 리포트\n")
        f.write("=" * 60 + "\n\n")
        f.write(json.dumps(report, ensure_ascii=False, indent=2))

    logger.info("텍스트 리포트 생성 완료 (reportlab 미설치): %s", txt_path)
    return txt_path
