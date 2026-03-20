from __future__ import annotations

import json
import logging
import os
import re
import time

from backend.app.core.prompt_loader import load_prompt_text


logger = logging.getLogger(__name__)

_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_OPENAI_MODEL = "gpt-4o-mini"
_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash"
_TIMEOUT = 60.0
_MAX_RETRIES = 2
_SYSTEM_PROMPT_FILE = "crosscheck_system_prompt.txt"


def call_llm(prompt: str) -> str:
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()

    has_openai = bool(openai_key)
    has_gemini = bool(gemini_key)

    if has_openai and has_gemini:
        logger.info("Dual LLM crosscheck mode: GPT + Gemini")
        return _dual_llm(prompt, openai_key, gemini_key)

    if has_openai:
        logger.info("Single LLM crosscheck mode: GPT")
        try:
            return _call_openai(prompt, openai_key)
        except Exception as exc:
            logger.error("OpenAI call failed (%s). Falling back to mock response", exc)
            return _mock_response(prompt)

    if has_gemini:
        logger.info("Single LLM crosscheck mode: Gemini")
        try:
            return _call_gemini(prompt, gemini_key)
        except Exception as exc:
            logger.error("Gemini call failed (%s). Falling back to mock response", exc)
            return _mock_response(prompt)

    logger.info("No LLM API keys configured. Using mock response")
    return _mock_response(prompt)


def _dual_llm(prompt: str, openai_key: str, gemini_key: str) -> str:
    import threading

    results = {"openai": None, "gemini": None}

    def run_openai() -> None:
        try:
            results["openai"] = _call_openai(prompt, openai_key)
        except Exception as exc:
            logger.warning("GPT crosscheck failed: %s", exc)

    def run_gemini() -> None:
        try:
            results["gemini"] = _call_gemini(prompt, gemini_key)
        except Exception as exc:
            logger.warning("Gemini crosscheck failed: %s", exc)

    thread_a = threading.Thread(target=run_openai)
    thread_b = threading.Thread(target=run_gemini)
    thread_a.start()
    thread_b.start()
    thread_a.join()
    thread_b.join()

    openai_result = results["openai"]
    gemini_result = results["gemini"]

    if not openai_result and not gemini_result:
        logger.error("Both LLM providers failed. Using mock response")
        return _mock_response(prompt)

    if not openai_result:
        logger.warning("GPT failed, returning Gemini result only")
        return gemini_result
    if not gemini_result:
        logger.warning("Gemini failed, returning GPT result only")
        return openai_result

    return _merge_dual_results(openai_result, gemini_result)


def _merge_dual_results(openai_raw: str, gemini_raw: str) -> str:
    try:
        gpt_data = json.loads(openai_raw)
        gemini_data = json.loads(gemini_raw)
    except json.JSONDecodeError:
        logger.warning("Failed to parse dual-LLM JSON. Returning GPT result only")
        return openai_raw

    gpt_judgements = {item["pair_index"]: item for item in gpt_data.get("judgements", [])}
    gemini_judgements = {item["pair_index"]: item for item in gemini_data.get("judgements", [])}

    merged = []
    for idx in sorted(set(gpt_judgements) | set(gemini_judgements)):
        gpt_item = gpt_judgements.get(idx)
        gemini_item = gemini_judgements.get(idx)

        if gpt_item and gemini_item:
            gpt_code = gpt_item.get("judgement_code", "REVIEW_NEEDED")
            gemini_code = gemini_item.get("judgement_code", "REVIEW_NEEDED")
            agree = gpt_code == gemini_code

            merged.append(
                {
                    "pair_index": idx,
                    "correlation_key": gpt_item.get("correlation_key", ""),
                    "judgement_code": gpt_code if agree else "REVIEW_NEEDED",
                    "confidence_level": "HIGH" if agree else "MED",
                    "llm_agreement": agree,
                    "gpt_judgement": gpt_code,
                    "gemini_judgement": gemini_code,
                    "reason": (
                        f"[GPT/Gemini {'agree' if agree else 'disagree'}] "
                        + (
                            gpt_item.get("reason", "")
                            if agree
                            else (
                                f"GPT: {gpt_code} / {gpt_item.get('reason', '')} ; "
                                f"Gemini: {gemini_code} / {gemini_item.get('reason', '')} ; "
                                "manual review is recommended."
                            )
                        )
                    ),
                    "action_text": gpt_item.get("action_text", gemini_item.get("action_text", "")),
                }
            )
        else:
            base = gpt_item or gemini_item
            merged.append({**base, "llm_agreement": None, "confidence_level": "MED"})

    agreement_rate = (
        sum(1 for item in merged if item.get("llm_agreement") is True) / len(merged) * 100
        if merged
        else 0
    )

    logger.info(
        "Dual LLM crosscheck completed: %d judgements, %.0f%% agreement",
        len(merged),
        agreement_rate,
    )

    return json.dumps(
        {
            "category": gpt_data.get("category", gemini_data.get("category", "")),
            "judgements": merged,
            "dual_llm": True,
            "agreement_rate": agreement_rate,
        },
        ensure_ascii=False,
    )


def _call_openai(prompt: str, api_key: str) -> str:
    system_prompt = load_prompt_text(_SYSTEM_PROMPT_FILE)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model": _OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 4096,
        "response_format": {"type": "json_object"},
    }
    raw = _http_post(_OPENAI_URL, headers, payload, "OpenAI")

    try:
        data = json.loads(raw)
        if "choices" in data:
            return data["choices"][0]["message"]["content"]
    except (json.JSONDecodeError, KeyError, IndexError):
        pass
    return raw


def _call_gemini(prompt: str, api_key: str) -> str:
    system_prompt = load_prompt_text(_SYSTEM_PROMPT_FILE)
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{_GEMINI_MODEL}:generateContent?key={api_key}"
    )
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": f"{system_prompt}\n\n{prompt}"}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 4096,
            "responseMimeType": "application/json",
        },
    }
    raw = _http_post(url, headers, payload, "Gemini")

    try:
        data = json.loads(raw)
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            return json_match.group(0)
        return text
    except (json.JSONDecodeError, KeyError, IndexError):
        return raw


def _http_post(url: str, headers: dict, payload: dict, provider: str) -> str:
    import httpx

    last_error = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                response = client.post(url, headers=headers, json=payload)

            if response.status_code == 200:
                logger.info("%s request succeeded", provider)
                return response.text

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", "5"))
                logger.warning("%s rate limited. Retrying in %d seconds", provider, retry_after)
                if attempt < _MAX_RETRIES:
                    time.sleep(retry_after)
                    continue
                raise RuntimeError(f"{provider} rate limit: {response.text[:200]}")

            if response.status_code in (500, 502, 503, 504):
                if attempt < _MAX_RETRIES:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"{provider} server error {response.status_code}")

            raise RuntimeError(f"{provider} API error {response.status_code}: {response.text[:200]}")

        except httpx.TimeoutException as exc:
            last_error = exc
            if attempt < _MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue
        except httpx.HTTPError as exc:
            last_error = exc
            if attempt < _MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue

    raise RuntimeError(f"{provider} retries exhausted: {last_error}")


def _mock_response(prompt: str) -> str:
    pair_indices = re.findall(r'"pair_index":\s*(\d+)', prompt)
    correlation_keys = re.findall(r'"correlation_key":\s*"([^"]*)"', prompt)
    category_match = re.search(r'"category":\s*"([^"]*)"', prompt)
    category = category_match.group(1) if category_match else "UNKNOWN"

    judgements = []
    for i, idx_str in enumerate(pair_indices):
        judgements.append(
            {
                "pair_index": int(idx_str),
                "correlation_key": correlation_keys[i] if i < len(correlation_keys) else "",
                "judgement_code": "REVIEW_NEEDED",
                "confidence_level": "MED",
                "llm_agreement": None,
                "reason": "LLM API key is unavailable, so the result falls back to a manual-review default.",
                "action_text": "Review the evidence manually.",
            }
        )

    return json.dumps(
        {
            "category": category,
            "judgements": judgements,
            "dual_llm": False,
        },
        ensure_ascii=False,
    )
