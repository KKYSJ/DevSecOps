import time

from google import genai

from backend.app.core.config import GEMINI_API_KEY, GEMINI_MODEL


def generate_with_gemini(prompt: str) -> str:
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY is not configured.")

    client = genai.Client(api_key=GEMINI_API_KEY)
    last_error = None

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
            )
            text = response.text.strip()

            if text.startswith("```"):
                text = text.strip("`")
                if text.startswith("json"):
                    text = text[4:].strip()

            return text
        except Exception as exc:
            last_error = exc

            error_text = str(exc)
            if "503" in error_text or "UNAVAILABLE" in error_text:
                time.sleep(2 * (attempt + 1))
                continue

            raise

    raise last_error
