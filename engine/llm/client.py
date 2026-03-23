"""
LLM 클라이언트 — OpenAI GPT + Google Gemini 이중 검증

환경변수:
    OPENAI_API_KEY  — GPT-4o-mini 사용
    GEMINI_API_KEY  — Gemini 1.5 Flash 사용

둘 다 설정 시: 두 LLM 모두 호출 → 판정 일치 여부로 신뢰도 상향
하나만 설정 시: 해당 LLM만 사용
둘 다 없을 시: 규칙 기반 mock 반환
"""

import json
import logging
import os
import re
import time

logger = logging.getLogger(__name__)

_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_OPENAI_MODEL = "gpt-4o-mini"
_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite-preview").strip() or "gemini-3.1-flash-lite-preview"
_TIMEOUT = 60.0
_MAX_RETRIES = 2

_SYSTEM_PROMPT = (
    "너는 보안 취약점 분석 전문가다. "
    "주어진 보안 스캔 결과를 분석하여 정확한 판정을 JSON 형식으로만 반환한다. "
    "절대 JSON 외의 텍스트를 포함하지 않는다."
)


# ── 공개 인터페이스 ────────────────────────────────────────────────────────


def call_llm(prompt: str) -> str:
    """
    사용 가능한 LLM으로 분석 요청.

    - 두 키 모두 있으면: GPT + Gemini 동시 호출 → 교차 검증
    - 하나만 있으면: 해당 LLM만 사용
    - 없으면: 규칙 기반 mock
    """
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()

    has_openai = bool(openai_key)
    has_gemini = bool(gemini_key)

    if has_openai and has_gemini:
        logger.info("두 LLM 교차 검증 모드: GPT + Gemini")
        return _dual_llm(prompt, openai_key, gemini_key)

    if has_openai:
        logger.info("단일 LLM 모드: GPT")
        return _call_openai(prompt, openai_key)

    if has_gemini:
        logger.info("단일 LLM 모드: Gemini")
        return _call_gemini(prompt, gemini_key)

    raise RuntimeError("LLM API 키 없음. GEMINI_API_KEY 또는 OPENAI_API_KEY를 설정하세요.")


# ── 이중 LLM 교차 검증 ────────────────────────────────────────────────────


def _dual_llm(prompt: str, openai_key: str, gemini_key: str) -> str:
    """GPT + Gemini 동시 호출 후 판정 교차 검증."""
    import threading

    results = {"openai": None, "gemini": None}

    def run_openai():
        try:
            results["openai"] = _call_openai(prompt, openai_key)
        except Exception as e:
            logger.warning("GPT 호출 실패: %s", e)

    def run_gemini():
        try:
            results["gemini"] = _call_gemini(prompt, gemini_key)
        except Exception as e:
            logger.warning("Gemini 호출 실패: %s", e)

    t1 = threading.Thread(target=run_openai)
    t2 = threading.Thread(target=run_gemini)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    openai_result = results["openai"]
    gemini_result = results["gemini"]

    if not openai_result and not gemini_result:
        raise RuntimeError("두 LLM 모두 실패 — 룰 기반 폴백 사용")

    if not openai_result:
        logger.warning("GPT 실패, Gemini 결과만 사용")
        return gemini_result
    if not gemini_result:
        logger.warning("Gemini 실패, GPT 결과만 사용")
        return openai_result

    return _merge_dual_results(openai_result, gemini_result)


def _merge_dual_results(openai_raw: str, gemini_raw: str) -> str:
    """
    두 LLM 판정을 비교하여 최종 결과 생성.

    - 판정 코드 일치 → confidence_level HIGH로 상향
    - 판정 코드 불일치 → REVIEW_NEEDED로 보수적 처리
    """
    try:
        gpt_data = json.loads(openai_raw)
        gemini_data = json.loads(gemini_raw)
    except json.JSONDecodeError:
        logger.warning("JSON 파싱 실패. GPT 결과 사용")
        return openai_raw

    gpt_j = {j["pair_index"]: j for j in gpt_data.get("judgements", [])}
    gem_j = {j["pair_index"]: j for j in gemini_data.get("judgements", [])}

    merged = []
    for idx in sorted(set(gpt_j) | set(gem_j)):
        g = gpt_j.get(idx)
        m = gem_j.get(idx)

        if g and m:
            g_code = g.get("judgement_code", "REVIEW_NEEDED")
            m_code = m.get("judgement_code", "REVIEW_NEEDED")
            agree = g_code == m_code

            merged.append({
                "pair_index": idx,
                "correlation_key": g.get("correlation_key", ""),
                "judgement_code": g_code if agree else "REVIEW_NEEDED",
                "confidence_level": "HIGH" if agree else "MED",
                "llm_agreement": agree,
                "gpt_judgement": g_code,
                "gemini_judgement": m_code,
                "reason": (
                    f"[GPT·Gemini {'일치' if agree else '불일치'}] "
                    + (f"{g.get('reason', '')}" if agree
                       else f"GPT: {g_code} — {g.get('reason', '')} / "
                            f"Gemini: {m_code} — {m.get('reason', '')} "
                            "두 AI 판단이 달라 수동 검토가 필요합니다.")
                ),
                "action_text": g.get("action_text", m.get("action_text", "")),
            })
        else:
            base = g or m
            merged.append({**base, "llm_agreement": None, "confidence_level": "MED"})

    agreement_rate = (
        sum(1 for j in merged if j.get("llm_agreement") is True) / len(merged) * 100
        if merged else 0
    )

    logger.info("LLM 교차 검증 완료: %d개 판정, 일치율 %.0f%%", len(merged), agreement_rate)

    return json.dumps({
        "category": gpt_data.get("category", gemini_data.get("category", "")),
        "judgements": merged,
        "dual_llm": True,
        "agreement_rate": agreement_rate,
    }, ensure_ascii=False)


# ── OpenAI 호출 ────────────────────────────────────────────────────────────


def _call_openai(prompt: str, api_key: str) -> str:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model": _OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 4096,
        "response_format": {"type": "json_object"},
    }
    raw = _http_post(_OPENAI_URL, headers, payload, "OpenAI")

    # OpenAI 응답에서 content 추출
    try:
        data = json.loads(raw)
        if "choices" in data:
            return data["choices"][0]["message"]["content"]
    except (json.JSONDecodeError, KeyError, IndexError):
        pass
    return raw


# ── Gemini 호출 ────────────────────────────────────────────────────────────


def _call_gemini(prompt: str, api_key: str) -> str:
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{_GEMINI_MODEL}:generateContent?key={api_key}"
    )
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": f"{_SYSTEM_PROMPT}\n\n{prompt}"}
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

    # Gemini 응답 구조: {"candidates": [{"content": {"parts": [{"text": "..."}]}}]}
    try:
        data = json.loads(raw)
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        # JSON만 추출
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            return json_match.group(0)
        return text
    except (json.JSONDecodeError, KeyError, IndexError):
        return raw


# ── 공통 HTTP 호출 ─────────────────────────────────────────────────────────


def _http_post(url: str, headers: dict, payload: dict, provider: str) -> str:
    import httpx

    last_error = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.post(url, headers=headers, json=payload)

            if resp.status_code == 200:
                logger.info("%s 호출 성공", provider)
                return resp.text

            elif resp.status_code == 429:
                logger.warning("%s rate limit (429). 룰 기반 폴백으로 전환", provider)
                raise RuntimeError(f"{provider} rate limit — 룰 기반 폴백 사용")

            elif resp.status_code in (500, 502, 503, 504):
                if attempt < _MAX_RETRIES:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"{provider} 서버 오류 {resp.status_code}")

            else:
                raise RuntimeError(f"{provider} API 오류 {resp.status_code}: {resp.text[:200]}")

        except httpx.TimeoutException as e:
            last_error = e
            if attempt < _MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue
        except httpx.HTTPError as e:
            last_error = e
            if attempt < _MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue

    raise RuntimeError(f"{provider} 최대 재시도 초과: {last_error}")


# ── Mock (키 없을 때) ──────────────────────────────────────────────────────


def _mock_response(prompt: str) -> str:
    pair_indices = re.findall(r'"pair_index":\s*(\d+)', prompt)
    correlation_keys = re.findall(r'"correlation_key":\s*"([^"]*)"', prompt)
    category_match = re.search(r'"category":\s*"([^"]*)"', prompt)
    category = category_match.group(1) if category_match else "UNKNOWN"

    judgements = []
    for i, idx_str in enumerate(pair_indices):
        judgements.append({
            "pair_index": int(idx_str),
            "correlation_key": correlation_keys[i] if i < len(correlation_keys) else "",
            "judgement_code": "REVIEW_NEEDED",
            "confidence_level": "MED",
            "llm_agreement": None,
            "reason": "LLM API 키가 없어 자동 규칙 기반 판정을 사용했습니다. 수동 검토가 필요합니다.",
            "action_text": "보안 담당자가 직접 검토하세요.",
        })

    return json.dumps({
        "category": category,
        "judgements": judgements,
        "dual_llm": False,
    }, ensure_ascii=False)
