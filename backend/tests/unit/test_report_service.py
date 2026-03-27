from backend.app.services.report_service import build_report_from_judgments


def test_build_report_from_judgments_uses_stage_gates_for_overall_decision():
    report = build_report_from_judgments(
        commit_hash="abc123",
        project_name="secureflow",
        judgments={
            "sast": [
                {
                    "severity": "HIGH",
                    "judgement_code": "TRUE_POSITIVE",
                    "confidence": "HIGH",
                    "finding_a": {"tool": "semgrep", "title": "issue-a"},
                    "finding_b": {"tool": "sonarqube", "title": "issue-a"},
                    "title_ko": "SAST issue",
                    "risk_summary": "risk",
                    "action_text": "fix it",
                }
            ]
        },
        summaries={"sast": {"summary": "one finding"}},
        gates={"sast": {"decision": "fail"}},
    )

    assert report is not None
    assert report["commit_hash"] == "abc123"
    assert report["gate_decision"] == "BLOCK"
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["by_severity"]["HIGH"] == 1
    assert report["findings"][0]["tool_a"] == "semgrep"
    assert report["findings"][0]["tool_b"] == "sonarqube"
