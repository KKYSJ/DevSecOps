from __future__ import annotations

import json
import logging
import re

from backend.app.core.prompt_loader import render_prompt_template


logger = logging.getLogger(__name__)

_TOOL_NAMES = {
    "SAST": ("SonarQube", "Semgrep"),
    "SCA": ("Trivy", "Dependency-Check"),
    "IaC": ("tfsec", "Checkov"),
    "DAST": ("OWASP ZAP", None),
    "IMAGE": ("Trivy", "Grype"),
}

_PAIR_PROMPT_FILES = {
    "SAST": "sast_pair_adjudication_prompt.txt",
    "SCA": "sca_pair_adjudication_prompt.txt",
    "IaC": "iac_pair_adjudication_prompt.txt",
    "DAST": "dast_pair_adjudication_prompt.txt",
    "IMAGE": "image_pair_adjudication_prompt.txt",
}


def _format_finding_compact(finding: dict | None, category: str) -> str:
    if finding is None:
        return "not_detected"

    parts = [f"severity={finding.get('severity', '?')}"]

    title = str(finding.get("title") or "").strip()
    if title:
        if len(title) > 80:
            title = title[:80] + "..."
        parts.append(f'title="{title}"')

    if category == "SAST":
        if finding.get("file_path"):
            parts.append(f"file={finding['file_path']}")
        if finding.get("line_number") is not None:
            parts.append(f"line={finding['line_number']}")
        if finding.get("cwe_id"):
            parts.append(f"cwe={finding['cwe_id']}")
    elif category == "SCA":
        if finding.get("package_name"):
            package_version = finding.get("package_version") or "unknown"
            parts.append(f"package={finding['package_name']}@{package_version}")
        if finding.get("cve_id"):
            parts.append(f"cve={finding['cve_id']}")
        if finding.get("fixed_version"):
            parts.append(f"fixed={finding['fixed_version']}")
    elif category == "IaC":
        if finding.get("file_path"):
            parts.append(f"file={finding['file_path']}")
        if finding.get("line_number") is not None:
            parts.append(f"line={finding['line_number']}")
        if finding.get("resource"):
            parts.append(f"resource={finding['resource']}")
        if finding.get("description"):
            description = str(finding["description"])[:100]
            parts.append(f'desc="{description}"')
    elif category == "DAST":
        if finding.get("url"):
            parts.append(f"url={finding['url']}")
        if finding.get("parameter"):
            parts.append(f"parameter={finding['parameter']}")

    return " | ".join(parts)


def _format_pair_compact(idx: int, pair: dict, category: str) -> str:
    tool_a_name, tool_b_name = _TOOL_NAMES.get(category, ("ToolA", "ToolB"))
    finding_a = pair.get("finding_a")
    finding_b = pair.get("finding_b")

    if finding_a and finding_b:
        match_type = "both_detected"
    elif finding_a:
        match_type = f"{tool_a_name}_only"
    elif finding_b:
        match_type = f"{tool_b_name}_only"
    else:
        match_type = "no_detection"

    lines = [f"[{idx + 1}] {match_type} | severity={pair.get('severity', '?')}"]
    lines.append(f"  {tool_a_name}: {_format_finding_compact(finding_a, category)}")
    if tool_b_name:
        lines.append(f"  {tool_b_name}: {_format_finding_compact(finding_b, category)}")

    return "\n".join(lines)


def build_cross_validation_prompt(category: str, matched_pairs: list[dict]) -> str:
    prompt_file = _PAIR_PROMPT_FILES.get(category)
    if not prompt_file:
        raise ValueError(f"Unsupported category: {category}")

    pairs_text = "\n".join(
        _format_pair_compact(idx, pair, category)
        for idx, pair in enumerate(matched_pairs)
    ) or "- no pairs -"

    return render_prompt_template(
        prompt_file,
        {
            "CATEGORY": category,
            "MATCHED_PAIRS_TEXT": pairs_text,
            "OUTPUT_SCHEMA_JSON": json.dumps(
                _build_output_schema(matched_pairs, category),
                ensure_ascii=False,
                indent=2,
            ),
        },
    )


def _build_output_schema(matched_pairs: list[dict], category: str) -> dict:
    judgements = []
    for idx, _pair in enumerate(matched_pairs):
        judgements.append(
            {
                "pair_index": idx,
                "judgement_code": "TRUE_POSITIVE | REVIEW_NEEDED | FALSE_POSITIVE",
                "confidence_level": "HIGH | MED | LOW",
                "reassessed_severity": "CRITICAL | HIGH | MEDIUM | LOW",
                "title_ko": "Korean vulnerability title",
                "risk_summary": "Korean risk summary",
                "reason": "Korean reasoning",
                "action_text": "Korean remediation guidance",
            }
        )

    return {
        "category": category,
        "judgements": judgements,
    }


def parse_llm_response(response_text: str, matched_pairs: list[dict]) -> list[dict]:
    try:
        fenced_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", response_text)
        if fenced_match:
            json_str = fenced_match.group(1)
        else:
            object_match = re.search(r"\{[\s\S]+\}", response_text)
            if not object_match:
                logger.warning("LLM response did not contain a JSON object; using rule-based fallback")
                return _rule_based_fallback(matched_pairs)
            json_str = object_match.group(0)

        data = json.loads(json_str)
        judgements = data.get("judgements", [])

        result_pairs = list(matched_pairs)
        for judgement in judgements:
            idx = judgement.get("pair_index")
            if idx is None or idx >= len(result_pairs):
                continue

            pair = dict(result_pairs[idx])
            judgement_code = judgement.get("judgement_code", "REVIEW_NEEDED")
            if judgement_code not in {"TRUE_POSITIVE", "REVIEW_NEEDED", "FALSE_POSITIVE"}:
                judgement_code = "REVIEW_NEEDED"

            pair["judgement_code"] = judgement_code
            pair["confidence_level"] = judgement.get("confidence_level", "MED")
            pair["reason"] = judgement.get("reason", "")
            pair["action_text"] = judgement.get("action_text", "")
            pair["title_ko"] = judgement.get("title_ko", "")
            pair["risk_summary"] = judgement.get("risk_summary", "")
            pair["description_ko"] = judgement.get("risk_summary", "")
            pair["reassessed_severity"] = judgement.get(
                "reassessed_severity",
                pair.get("severity", "MEDIUM"),
            )
            result_pairs[idx] = pair

        return result_pairs

    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        logger.warning("Failed to parse LLM response (%s); using rule-based fallback", exc)
        return _rule_based_fallback(matched_pairs)


def _rule_based_fallback(matched_pairs: list[dict]) -> list[dict]:
    result = []
    for pair in matched_pairs:
        item = dict(pair)
        finding_a = item.get("finding_a")
        finding_b = item.get("finding_b")
        severity = item.get("severity", "MEDIUM")
        title = str((finding_a or finding_b or {}).get("title") or "Unnamed finding").strip()
        if len(title) > 60:
            title = title[:60] + "..."

        if finding_a and finding_b:
            tool_a = finding_a.get("tool", "Tool A")
            tool_b = finding_b.get("tool", "Tool B")
            item["judgement_code"] = "TRUE_POSITIVE"
            item["confidence_level"] = "HIGH"
            item["title_ko"] = f"[Confirmed] {title}"
            item["risk_summary"] = (
                f"{tool_a} and {tool_b} reported the same vulnerability in the same area."
            )
            item["reason"] = (
                f"Two independent tools pointed to the same issue, so the confidence is high. "
                f"The current severity is {severity} and should be prioritized."
            )
            item["action_text"] = "Review the related code or configuration and apply the security fix."
            item["reassessed_severity"] = severity
        elif finding_a or finding_b:
            found = finding_a or finding_b
            tool = found.get("tool", "Tool")
            item["judgement_code"] = "REVIEW_NEEDED"
            item["confidence_level"] = "MED"
            item["title_ko"] = f"[Needs Review] {title}"
            item["risk_summary"] = f"Only {tool} reported this finding, so it still needs manual validation."
            item["reason"] = (
                "Cross-validation is incomplete, so this may be a real issue or a false positive. "
                "A reviewer should confirm the evidence and impact."
            )
            item["action_text"] = "Confirm the evidence and reachable path, then record the review result."
            item["reassessed_severity"] = severity
        else:
            item["judgement_code"] = "FALSE_POSITIVE"
            item["confidence_level"] = "LOW"
            item["title_ko"] = "[Likely False Positive] Not enough evidence"
            item["risk_summary"] = "There was not enough evidence from the available findings to confirm a real issue."
            item["reason"] = "The input data was too limited to support a confident security judgment."
            item["action_text"] = "Collect more evidence or review whether this item should be excluded."
            item["reassessed_severity"] = "LOW"

        result.append(item)
    return result
