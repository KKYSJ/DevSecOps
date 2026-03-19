from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


OPENAI_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
TIMEOUT_SECONDS = 60
MAX_RETRIES = 2

SYSTEM_PROMPT = (
    "You are a DevSecOps security gate analyst. "
    "Return only valid JSON with a recommended_decision of pass, review, or fail, "
    "plus concise reasoning grounded in the supplied summaries."
)


def run(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    prompt = build_prompt(payload)

    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    gemini_model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip() or DEFAULT_GEMINI_MODEL
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    openai_model = os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL

    if gemini_key:
        try:
            raw = call_gemini(prompt, gemini_key, gemini_model)
            parsed = parse_json_object(raw)
            return normalize_result(parsed, "gemini", gemini_model)
        except Exception as exc:  # pragma: no cover - defensive fallback
            if openai_key:
                try:
                    raw = call_openai(prompt, openai_key, openai_model)
                    parsed = parse_json_object(raw)
                    return normalize_result(
                        parsed,
                        "openai",
                        openai_model,
                        fallback_reason=f"gemini_failed: {exc}",
                    )
                except Exception as openai_exc:  # pragma: no cover - defensive fallback
                    return fallback_result(
                        reason=f"gemini_failed: {exc}; openai_failed: {openai_exc}",
                        prompt_preview=prompt[:600],
                    )
            return fallback_result(reason=f"gemini_failed: {exc}", prompt_preview=prompt[:600])

    if openai_key:
        try:
            raw = call_openai(prompt, openai_key, openai_model)
            parsed = parse_json_object(raw)
            return normalize_result(parsed, "openai", openai_model)
        except Exception as exc:  # pragma: no cover - defensive fallback
            return fallback_result(reason=f"openai_failed: {exc}", prompt_preview=prompt[:600])

    return fallback_result(reason="missing_llm_api_keys", prompt_preview=prompt[:600])


def build_prompt(payload: dict[str, Any]) -> str:
    prompt_file = Path(str(payload.get("prompt_file", "")))
    prompt_hint = prompt_file.stem if prompt_file.name else f"{payload.get('stage', 'unknown')}_gate"

    tool_lines = []
    for item in payload.get("tool_summaries", []):
        summary = item.get("summary", {})
        tool_lines.append(
            {
                "tool": item.get("tool"),
                "executed": item.get("executed", True),
                "disabled_reason": item.get("disabled_reason"),
                "summary": {
                    "total": summary.get("total", 0),
                    "critical": summary.get("critical", 0),
                    "high": summary.get("high", 0),
                    "medium": summary.get("medium", 0),
                    "low": summary.get("low", 0),
                    "info": summary.get("info", 0),
                },
            }
        )

    compact_payload = {
        "stage": payload.get("stage"),
        "prompt_hint": prompt_hint,
        "combined_summary": payload.get("combined_summary", {}),
        "divergence_ratio": payload.get("divergence_ratio", 0),
        "tool_summaries": tool_lines,
    }

    return (
        f"{SYSTEM_PROMPT}\n\n"
        "Evaluate the following CI/CD security gate context.\n"
        "Be conservative: if tools disagree materially or important tools did not execute, prefer review.\n"
        "Use this JSON schema exactly:\n"
        "{\n"
        '  "recommended_decision": "pass | review | fail",\n'
        '  "confidence": "low | medium | high",\n'
        '  "summary": "short summary",\n'
        '  "reasons": ["reason 1", "reason 2"],\n'
        '  "provider_notes": "optional note"\n'
        "}\n\n"
        "Input:\n"
        f"{json.dumps(compact_payload, ensure_ascii=False, indent=2)}"
    )


def call_openai(prompt: str, api_key: str, model: str) -> str:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    raw = http_post(
        url=OPENAI_URL,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        payload=payload,
        provider="openai",
    )
    data = json.loads(raw)
    return data["choices"][0]["message"]["content"]


def call_gemini(prompt: str, api_key: str, model: str) -> str:
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }
    raw = http_post(
        url=f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
        headers={"Content-Type": "application/json"},
        payload=payload,
        provider="gemini",
    )
    data = json.loads(raw)
    return data["candidates"][0]["content"]["parts"][0]["text"]


def http_post(url: str, headers: dict[str, str], payload: dict[str, Any], provider: str) -> str:
    body = json.dumps(payload).encode("utf-8")
    last_error: Exception | None = None

    for attempt in range(MAX_RETRIES + 1):
        request = urllib.request.Request(url=url, headers=headers, data=body, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue
            detail = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"{provider}_http_{exc.code}: {detail[:300]}") from exc
        except Exception as exc:  # pragma: no cover - defensive fallback
            last_error = exc
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue

    raise RuntimeError(f"{provider}_request_failed: {last_error}")


def parse_json_object(raw_text: str) -> dict[str, Any]:
    text = raw_text.strip()

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        data = json.loads(match.group(0))
        if isinstance(data, dict):
            return data

    raise ValueError("llm_response_not_json_object")


def normalize_result(
    data: dict[str, Any],
    provider: str,
    model: str,
    fallback_reason: str | None = None,
) -> dict[str, Any]:
    recommended = normalize_decision(data.get("recommended_decision"))
    confidence = str(data.get("confidence", "medium")).strip().lower()
    if confidence not in {"low", "medium", "high"}:
        confidence = "medium"

    reasons = data.get("reasons")
    if not isinstance(reasons, list):
        reasons = [str(reasons)] if reasons else []

    result = {
        "component": "analyzer",
        "provider": provider,
        "model": model,
        "recommended_decision": recommended,
        "confidence": confidence,
        "summary": str(data.get("summary", "")).strip(),
        "reasons": [str(reason) for reason in reasons if str(reason).strip()],
        "provider_notes": str(data.get("provider_notes", "")).strip() or None,
    }
    if fallback_reason:
        result["fallback_reason"] = fallback_reason
    return result


def normalize_decision(value: Any) -> str:
    text = str(value or "").strip().lower()
    mapping = {
        "pass": "pass",
        "allow": "pass",
        "approve": "pass",
        "review": "review",
        "manual_review": "review",
        "needs_review": "review",
        "fail": "fail",
        "block": "fail",
        "deny": "fail",
    }
    return mapping.get(text, "review")


def fallback_result(reason: str, prompt_preview: str | None = None) -> dict[str, Any]:
    return {
        "component": "analyzer",
        "provider": "fallback",
        "model": None,
        "recommended_decision": "review",
        "confidence": "low",
        "summary": "LLM API was unavailable, so the gate used fallback handling.",
        "reasons": [reason],
        "provider_notes": None,
        "prompt_preview": prompt_preview,
    }
