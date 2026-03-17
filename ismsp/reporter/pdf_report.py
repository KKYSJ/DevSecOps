"""
ISMS-P 평가 결과 PDF 감사 보고서 생성 모듈

reportlab을 사용하여 ISMS-P 자동 점검 결과를 PDF 보고서로 출력합니다.
한글 폰트는 시스템 폰트를 사용하며, 없을 경우 ASCII 대체 텍스트를 사용합니다.
"""

import logging
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# reportlab 임포트 (설치되지 않은 환경에서도 모듈 임포트가 실패하지 않도록 처리)
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        HRFlowable,
        PageBreak,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab이 설치되어 있지 않습니다. PDF 생성이 불가능합니다. 'pip install reportlab'으로 설치하세요.")


# ---------------------------------------------------------------------------
# 한글 폰트 등록
# ---------------------------------------------------------------------------

_FONT_REGISTERED = False
_KOREAN_FONT_NAME = "NanumGothic"
_FALLBACK_FONT = "Helvetica"

_CANDIDATE_FONT_PATHS = [
    # Linux (NanumGothic)
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    "/usr/share/fonts/nanum/NanumGothic.ttf",
    # macOS
    "/Library/Fonts/NanumGothic.ttf",
    "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
    # Windows
    "C:/Windows/Fonts/malgun.ttf",          # 맑은 고딕
    "C:/Windows/Fonts/NanumGothic.ttf",
    "C:/Windows/Fonts/gulim.ttc",
    # 프로젝트 내 폰트
    str(Path(__file__).parent.parent / "fonts" / "NanumGothic.ttf"),
    str(Path(__file__).parent.parent / "fonts" / "malgun.ttf"),
]


def _register_korean_font() -> str:
    """시스템에서 한글 폰트를 찾아 reportlab에 등록합니다. 등록된 폰트명을 반환합니다."""
    global _FONT_REGISTERED, _KOREAN_FONT_NAME

    if _FONT_REGISTERED:
        return _KOREAN_FONT_NAME

    if not REPORTLAB_AVAILABLE:
        return _FALLBACK_FONT

    for path in _CANDIDATE_FONT_PATHS:
        if os.path.isfile(path):
            try:
                font_name = "KoreanFont"
                pdfmetrics.registerFont(TTFont(font_name, path))
                _KOREAN_FONT_NAME = font_name
                _FONT_REGISTERED = True
                logger.info("한글 폰트 등록 완료: %s", path)
                return font_name
            except Exception as exc:
                logger.debug("폰트 등록 실패 (%s): %s", path, exc)
                continue

    logger.warning("한글 폰트를 찾을 수 없습니다. ASCII 대체 폰트를 사용합니다.")
    _FONT_REGISTERED = True
    _KOREAN_FONT_NAME = _FALLBACK_FONT
    return _FALLBACK_FONT


# ---------------------------------------------------------------------------
# 상수 및 스타일 (reportlab 사용 가능 시에만 초기화)
# ---------------------------------------------------------------------------

def _make_color_maps():
    """reportlab colors 객체를 사용하는 색상 맵을 초기화합니다."""
    if not REPORTLAB_AVAILABLE:
        return {}, {}, {}
    status_colors = {
        "PASS":  colors.HexColor("#28a745"),
        "FAIL":  colors.HexColor("#dc3545"),
        "NA":    colors.HexColor("#6c757d"),
        "ERROR": colors.HexColor("#fd7e14"),
    }
    severity_colors = {
        "CRITICAL": colors.HexColor("#721c24"),
        "HIGH":     colors.HexColor("#dc3545"),
        "MEDIUM":   colors.HexColor("#fd7e14"),
        "LOW":      colors.HexColor("#28a745"),
    }
    severity_bg = {
        "CRITICAL": colors.HexColor("#f8d7da"),
        "HIGH":     colors.HexColor("#f8d7da"),
        "MEDIUM":   colors.HexColor("#fff3cd"),
        "LOW":      colors.HexColor("#d4edda"),
    }
    return status_colors, severity_colors, severity_bg


def _safe_text(text: str) -> str:
    """한글 폰트가 없을 때 ASCII 안전 텍스트를 반환합니다."""
    if _KOREAN_FONT_NAME == _FALLBACK_FONT:
        # 한글 문자 제거 (ASCII 범위 외 문자)
        return "".join(c if ord(c) < 128 else "?" for c in text)
    return text


def _make_styles(font_name: str) -> dict:
    """보고서용 paragraph 스타일을 생성합니다."""
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "ReportTitle",
            fontName=font_name,
            fontSize=20,
            leading=28,
            spaceAfter=6,
            textColor=colors.HexColor("#212529"),
            alignment=1,  # center
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            fontName=font_name,
            fontSize=11,
            leading=16,
            spaceAfter=4,
            textColor=colors.HexColor("#6c757d"),
            alignment=1,
        ),
        "section": ParagraphStyle(
            "SectionHeader",
            fontName=font_name,
            fontSize=13,
            leading=18,
            spaceBefore=14,
            spaceAfter=6,
            textColor=colors.HexColor("#212529"),
            borderPad=4,
        ),
        "body": ParagraphStyle(
            "BodyText",
            fontName=font_name,
            fontSize=9,
            leading=13,
            spaceAfter=4,
            textColor=colors.HexColor("#212529"),
        ),
        "small": ParagraphStyle(
            "SmallText",
            fontName=font_name,
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#6c757d"),
        ),
        "footer": ParagraphStyle(
            "FooterText",
            fontName=font_name,
            fontSize=7,
            leading=10,
            textColor=colors.HexColor("#adb5bd"),
            alignment=1,
        ),
        "cell": ParagraphStyle(
            "CellText",
            fontName=font_name,
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#212529"),
            wordWrap="CJK",
        ),
    }
    return styles


# ---------------------------------------------------------------------------
# 보고서 섹션 빌더
# ---------------------------------------------------------------------------

def _build_cover(styles: dict, generated_at: str, summary: dict) -> list:
    """표지 섹션을 생성합니다."""
    elements = []
    elements.append(Spacer(1, 2 * cm))
    elements.append(Paragraph(_safe_text("ISMS-P 자동 점검 보고서"), styles["title"]))
    elements.append(Paragraph(
        _safe_text("정보보호 및 개인정보보호 관리체계 (ISMS-P) AWS 기술 통제 자동 점검"),
        styles["subtitle"],
    ))
    elements.append(Spacer(1, 0.5 * cm))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#007bff")))
    elements.append(Spacer(1, 1 * cm))

    pass_rate = summary.get("pass_rate", 0)
    color = "#28a745" if pass_rate >= 80 else ("#fd7e14" if pass_rate >= 60 else "#dc3545")

    cover_data = [
        [_safe_text("점검 일시"), generated_at],
        [_safe_text("총 점검 항목"), f"{summary.get('total', 0)}{_safe_text('개 (자동 점검)')}"],
        [_safe_text("통과 항목"), f"{summary.get('passed', 0)}{_safe_text('개')}"],
        [_safe_text("실패 항목"), f"{summary.get('failed', 0)}{_safe_text('개')}"],
        [_safe_text("통과율"), f"{pass_rate:.1f}%"],
        [_safe_text("미해당(N/A)"), f"{summary.get('na', 0)}{_safe_text('개')}"],
    ]

    cover_table = Table(cover_data, colWidths=[5 * cm, 9 * cm])
    cover_table.setStyle(TableStyle([
        ("FONTNAME",        (0, 0), (-1, -1), styles["body"].fontName),
        ("FONTSIZE",        (0, 0), (-1, -1), 10),
        ("LEADING",         (0, 0), (-1, -1), 14),
        ("BACKGROUND",      (0, 0), (0, -1), colors.HexColor("#f8f9fa")),
        ("TEXTCOLOR",       (0, 0), (0, -1), colors.HexColor("#495057")),
        ("FONTNAME",        (0, 0), (0, -1), styles["body"].fontName),
        ("ALIGN",           (0, 0), (0, -1), "RIGHT"),
        ("ALIGN",           (1, 0), (1, -1), "LEFT"),
        ("ROWBACKGROUNDS",  (0, 0), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("GRID",            (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("TOPPADDING",      (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",   (0, 0), (-1, -1), 8),
        ("LEFTPADDING",     (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",    (0, 0), (-1, -1), 10),
    ]))
    elements.append(cover_table)
    elements.append(Spacer(1, 1 * cm))
    elements.append(Paragraph(
        _safe_text(
            "본 보고서는 ISMS-P 102개 통제 항목 중 AWS API를 통해 자동 점검 가능한 "
            "38개 기술 항목의 점검 결과를 포함합니다. "
            "나머지 64개 항목은 별도의 수동 심사가 필요합니다."
        ),
        styles["small"],
    ))
    return elements


def _build_summary_table(styles: dict, by_category: dict) -> list:
    """카테고리별 요약 테이블을 생성합니다."""
    elements = []
    elements.append(Paragraph(_safe_text("■ 카테고리별 점검 결과 요약"), styles["section"]))

    header = [
        Paragraph(_safe_text("통제 ID"), styles["cell"]),
        Paragraph(_safe_text("통제 항목명"), styles["cell"]),
        Paragraph(_safe_text("전체"), styles["cell"]),
        Paragraph(_safe_text("통과"), styles["cell"]),
        Paragraph(_safe_text("실패"), styles["cell"]),
        Paragraph(_safe_text("N/A"), styles["cell"]),
        Paragraph(_safe_text("통과율"), styles["cell"]),
    ]
    rows = [header]

    for cat_id, cat in sorted(by_category.items()):
        total = cat.get("total", 0)
        passed = cat.get("passed", 0)
        failed = cat.get("failed", 0)
        na = cat.get("na", 0)
        rate = f"{passed / (total - na) * 100:.0f}%" if (total - na) > 0 else "N/A"

        rows.append([
            Paragraph(cat_id, styles["cell"]),
            Paragraph(_safe_text(cat.get("name", "")), styles["cell"]),
            Paragraph(str(total), styles["cell"]),
            Paragraph(str(passed), styles["cell"]),
            Paragraph(str(failed), styles["cell"]),
            Paragraph(str(na), styles["cell"]),
            Paragraph(rate, styles["cell"]),
        ])

    col_widths = [2.2 * cm, 5.5 * cm, 1.5 * cm, 1.5 * cm, 1.5 * cm, 1.5 * cm, 2.0 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)

    style_cmds = [
        ("FONTNAME",       (0, 0), (-1, -1), styles["cell"].fontName),
        ("FONTSIZE",       (0, 0), (-1, -1), 8),
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#343a40")),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("ALIGN",          (0, 0), (-1, -1), "CENTER"),
        ("ALIGN",          (1, 0), (1, -1), "LEFT"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("GRID",           (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 4),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ]

    # 실패 항목이 있는 행 강조
    for i, row_data in enumerate(rows[1:], start=1):
        failed_val = int(by_category[sorted(by_category.keys())[i - 1]].get("failed", 0))
        if failed_val > 0:
            style_cmds.append(("TEXTCOLOR", (4, i), (4, i), colors.HexColor("#dc3545")))
            style_cmds.append(("FONTNAME",  (4, i), (4, i), styles["cell"].fontName))

    table.setStyle(TableStyle(style_cmds))
    elements.append(table)
    return elements


def _build_items_table(styles: dict, items: list) -> list:
    """전체 점검 항목 상세 테이블을 생성합니다."""
    elements = []
    elements.append(PageBreak())
    elements.append(Paragraph(_safe_text("■ 전체 점검 항목 상세"), styles["section"]))

    header = [
        Paragraph(_safe_text("항목 ID"), styles["cell"]),
        Paragraph(_safe_text("점검 항목"), styles["cell"]),
        Paragraph(_safe_text("심각도"), styles["cell"]),
        Paragraph(_safe_text("결과"), styles["cell"]),
        Paragraph(_safe_text("내용"), styles["cell"]),
    ]
    rows = [header]

    for item in items:
        status = item.get("status", "NA")
        severity = item.get("severity", "MEDIUM")
        status_text = {"PASS": _safe_text("통과"), "FAIL": _safe_text("실패"),
                       "NA": "N/A", "ERROR": "ERR"}.get(status, status)

        rows.append([
            Paragraph(item.get("id", ""), styles["cell"]),
            Paragraph(_safe_text(item.get("title", "")), styles["cell"]),
            Paragraph(_safe_text(severity), styles["cell"]),
            Paragraph(status_text, styles["cell"]),
            Paragraph(_safe_text(item.get("evidence", "")[:120]), styles["cell"]),
        ])

    col_widths = [3.5 * cm, 5.5 * cm, 1.8 * cm, 1.5 * cm, 5.5 * cm]
    table = Table(rows, colWidths=col_widths, repeatRows=1)

    style_cmds = [
        ("FONTNAME",       (0, 0), (-1, -1), styles["cell"].fontName),
        ("FONTSIZE",       (0, 0), (-1, -1), 7.5),
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#495057")),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("ALIGN",          (0, 0), (-1, -1), "LEFT"),
        ("ALIGN",          (2, 0), (3, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("GRID",           (0, 0), (-1, -1), 0.4, colors.HexColor("#dee2e6")),
        ("TOPPADDING",     (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 4),
        ("LEFTPADDING",    (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 4),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("WORDWRAP",       (0, 0), (-1, -1), True),
    ]

    # 결과별 색상 적용
    _status_colors, _severity_colors, _severity_bg = _make_color_maps()
    for i, item in enumerate(items, start=1):
        status = item.get("status", "NA")
        color = _status_colors.get(status, colors.HexColor("#6c757d"))
        style_cmds.append(("TEXTCOLOR", (3, i), (3, i), color))

        severity = item.get("severity", "MEDIUM")
        sev_color = _severity_colors.get(severity, colors.black)
        style_cmds.append(("TEXTCOLOR", (2, i), (2, i), sev_color))

        if status == "FAIL" and severity in ("CRITICAL", "HIGH"):
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fff5f5")))

    table.setStyle(TableStyle(style_cmds))
    elements.append(table)
    return elements


def _build_failures_section(styles: dict, items: list) -> list:
    """실패 항목 조치 권고 섹션을 생성합니다."""
    failures = [i for i in items if i.get("status") == "FAIL"]
    if not failures:
        return []

    elements = []
    elements.append(PageBreak())
    elements.append(Paragraph(_safe_text("■ 실패 항목 조치 권고"), styles["section"]))
    elements.append(Paragraph(
        _safe_text(f"총 {len(failures)}건의 실패 항목에 대한 조치 권고 사항입니다."),
        styles["body"],
    ))
    elements.append(Spacer(1, 0.3 * cm))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_failures = sorted(failures, key=lambda x: severity_order.get(x.get("severity", "LOW"), 99))
    _status_colors, _severity_colors, _severity_bg = _make_color_maps()

    for item in sorted_failures:
        severity = item.get("severity", "MEDIUM")
        bg_color = _severity_bg.get(severity, colors.white)
        border_color = _severity_colors.get(severity, colors.HexColor("#6c757d"))

        item_data = [
            [
                Paragraph(
                    f'<b>{item.get("id", "")}</b> | {_safe_text(item.get("isms_p_name", ""))} | '
                    f'{_safe_text(severity)}',
                    styles["cell"],
                ),
            ],
            [Paragraph(f'<b>{_safe_text(item.get("title", ""))}</b>', styles["cell"])],
            [Paragraph(_safe_text(f'점검 결과: {item.get("evidence", "")}'), styles["small"])],
            [Paragraph(_safe_text(f'조치 권고: {item.get("remediation", "")}'), styles["small"])],
        ]

        item_table = Table(item_data, colWidths=[17.7 * cm])
        item_table.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (-1, -1), styles["cell"].fontName),
            ("BACKGROUND",    (0, 0), (-1, 0), bg_color),
            ("BACKGROUND",    (0, 1), (-1, -1), colors.white),
            ("LEFTBORDERCOLOR", (0, 0), (-1, -1), border_color),
            ("BOX",           (0, 0), (-1, -1), 1, border_color),
            ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#dee2e6")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        elements.append(item_table)
        elements.append(Spacer(1, 0.2 * cm))

    return elements


def _build_footer_note(styles: dict, generated_at: str) -> list:
    """페이지 하단 면책 고지를 생성합니다."""
    elements = []
    elements.append(Spacer(1, 1 * cm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dee2e6")))
    elements.append(Spacer(1, 0.2 * cm))
    elements.append(Paragraph(
        _safe_text(
            f"생성 일시: {generated_at}  |  "
            "본 보고서는 SecureFlow ISMS-P 자동 점검 시스템에 의해 생성되었습니다.  |  "
            "ISMS-P 102개 항목 중 38개 기술 항목 자동 점검 결과이며, 나머지 64개는 수동 심사가 필요합니다."
        ),
        styles["footer"],
    ))
    return elements


# ---------------------------------------------------------------------------
# 퍼블릭 인터페이스
# ---------------------------------------------------------------------------

def generate(evaluation_result: dict, output_path: str = "/tmp/isms_report.pdf") -> str:
    """
    ISMS-P 점검 결과를 PDF 보고서로 생성합니다.

    Parameters
    ----------
    evaluation_result : dict
        evaluator.evaluate()가 반환한 평가 결과
    output_path : str, optional
        출력 PDF 파일 경로 (기본값: /tmp/isms_report.pdf)

    Returns
    -------
    str
        생성된 PDF 파일의 절대 경로

    Raises
    ------
    ImportError
        reportlab이 설치되어 있지 않은 경우
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab이 설치되어 있지 않습니다. 'pip install reportlab'으로 설치 후 다시 시도하세요."
        )

    # 출력 디렉터리 생성
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    font_name = _register_korean_font()
    styles = _make_styles(font_name)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="ISMS-P 자동 점검 보고서",
        author="SecureFlow",
        subject="ISMS-P AWS 기술 통제 자동 점검 결과",
    )

    summary = {
        "total":    evaluation_result.get("total", 0),
        "passed":   evaluation_result.get("passed", 0),
        "failed":   evaluation_result.get("failed", 0),
        "na":       evaluation_result.get("na", 0),
        "pass_rate": evaluation_result.get("pass_rate", 0.0),
    }
    items = evaluation_result.get("items", [])
    by_category = evaluation_result.get("by_category", {})

    story = []
    story.extend(_build_cover(styles, generated_at, summary))
    story.append(Spacer(1, 0.5 * cm))
    story.extend(_build_summary_table(styles, by_category))
    story.extend(_build_items_table(styles, items))
    story.extend(_build_failures_section(styles, items))
    story.extend(_build_footer_note(styles, generated_at))

    doc.build(story)
    logger.info("PDF 보고서가 생성되었습니다: %s", output_path)
    return output_path
