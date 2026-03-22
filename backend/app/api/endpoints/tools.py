"""
보안 도구 목록 및 발견 사항 조회 엔드포인트
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db

router = APIRouter()

_TOOLS = [
    {
        "name": "sonarqube",
        "category": "SAST",
        "version": "10.x",
        "status": "active",
        "description": "정적 코드 분석 도구. 소스 코드의 보안 취약점, 버그, 코드 스멜을 탐지합니다.",
        "language_support": ["Python", "Java", "JavaScript", "TypeScript", "Go", "C/C++"],
        "doc_url": "https://docs.sonarqube.org/",
    },
    {
        "name": "semgrep",
        "category": "SAST",
        "version": "1.x",
        "status": "active",
        "description": "패턴 기반 정적 분석 도구. OWASP Top 10 및 CWE 기반 규칙을 적용합니다.",
        "language_support": ["Python", "Java", "JavaScript", "TypeScript", "Go", "Ruby", "PHP"],
        "doc_url": "https://semgrep.dev/docs/",
    },
    {
        "name": "trivy",
        "category": "SCA",
        "version": "0.48.x",
        "status": "active",
        "description": "컨테이너 이미지 및 파일 시스템의 취약점을 스캔하는 SCA 도구입니다.",
        "language_support": ["Python (pip)", "Node.js (npm/yarn)", "Java (maven/gradle)", "Go", "Ruby"],
        "doc_url": "https://aquasecurity.github.io/trivy/",
    },
    {
        "name": "depcheck",
        "category": "SCA",
        "version": "9.x",
        "status": "active",
        "description": "OWASP Dependency-Check. 프로젝트 의존성의 알려진 취약점(CVE)을 탐지합니다.",
        "language_support": ["Java", ".NET", "Node.js", "Python", "Ruby"],
        "doc_url": "https://jeremylong.github.io/DependencyCheck/",
    },
    {
        "name": "tfsec",
        "category": "IaC",
        "version": "1.x",
        "status": "active",
        "description": "Terraform 코드의 보안 이슈를 정적 분석하는 IaC 스캐너입니다.",
        "language_support": ["Terraform (HCL)"],
        "doc_url": "https://aquasecurity.github.io/tfsec/",
    },
    {
        "name": "checkov",
        "category": "IaC",
        "version": "3.x",
        "status": "active",
        "description": "Terraform, CloudFormation, Kubernetes 등 IaC 코드의 보안 정책을 검사합니다.",
        "language_support": ["Terraform", "CloudFormation", "Kubernetes", "Helm", "Dockerfile"],
        "doc_url": "https://www.checkov.io/",
    },
    {
        "name": "zap",
        "category": "DAST",
        "version": "2.14.x",
        "status": "active",
        "description": "OWASP ZAP. 실행 중인 애플리케이션의 동적 보안 테스트를 수행합니다.",
        "language_support": ["Web Applications (HTTP/HTTPS)"],
        "doc_url": "https://www.zaproxy.org/docs/",
    },
    {
        "name": "nuclei",
        "category": "DAST",
        "version": "3.x",
        "status": "active",
        "description": "ProjectDiscovery Nuclei. ?⑦뀒?뚯뵆由우듃 湲곕컲???숈쟻 ?좏뵆由ъ??댁뀡??寃?ы빀?덈떎.",
        "language_support": ["Web Applications (HTTP/HTTPS)"],
        "doc_url": "https://nuclei.projectdiscovery.io/",
    },
]

_TOOL_MAP = {t["name"]: t for t in _TOOLS}


@router.get("")
def list_tools():
    """통합된 보안 도구 목록과 메타데이터를 반환합니다."""
    return {
        "tools": _TOOLS,
        "total": len(_TOOLS),
        "categories": {
            "SAST": [t["name"] for t in _TOOLS if t["category"] == "SAST"],
            "SCA": [t["name"] for t in _TOOLS if t["category"] == "SCA"],
            "IaC": [t["name"] for t in _TOOLS if t["category"] == "IaC"],
            "DAST": [t["name"] for t in _TOOLS if t["category"] == "DAST"],
        },
    }


@router.get("/{tool_name}/findings")
def get_tool_findings(tool_name: str, db: Session = Depends(get_db)):
    """특정 도구의 발견 사항을 반환합니다."""
    tool_name = tool_name.lower().strip()

    if tool_name not in _TOOL_MAP:
        raise HTTPException(
            status_code=404,
            detail=f"도구 '{tool_name}'을 찾을 수 없습니다. 지원 목록: {list(_TOOL_MAP.keys())}",
        )

    from backend.app.models.tool_result import ToolResult

    try:
        # DB에서 해당 도구의 최신 결과 조회
        record = (
            db.query(ToolResult)
            .filter(ToolResult.name == tool_name)
            .order_by(ToolResult.id.desc())
            .first()
        )

        if record and record.data:
            parsed = record.data.get("parsed", {})
            return {
                "tool": tool_name,
                "tool_info": _TOOL_MAP[tool_name],
                "scanned_at": parsed.get("scanned_at"),
                "findings": parsed.get("findings", []),
                "summary": parsed.get("summary", {}),
                "source": "db",
            }
    except Exception:
        pass

    return {
        "tool": tool_name,
        "tool_info": _TOOL_MAP[tool_name],
        "scanned_at": None,
        "findings": [],
        "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "source": "db",
    }
