import os
import json
import logging
from typing import Optional, Dict

from google import genai
from google.genai import types

logger = logging.getLogger(__name__)


class TranslatorService:
    """
    finding의 title/description/message 같은 사용자 표시용 문장을
    한국어로 번역하는 서비스
    """

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY 환경변수가 설정되지 않았습니다.")

        self.client = genai.Client(api_key=api_key)
        self.model_name = os.getenv("GEMINI_MODEL")

    def _translate_text(self, text: Optional[str]) -> Optional[str]:
        """
        단일 텍스트를 한국어로 번역
        - None/빈 문자열이면 그대로 반환
        - 이미 한국어면 그대로 반환하도록 프롬프트에서 제어
        - 기술명, 제품명, CVE/CWE, 경로, 버전, 코드, 라인번호 등은 유지
        """
        if text is None:
            return None

        text = str(text).strip()
        if not text:
            return text

        prompt = f"""
너는 보안 취약점 결과 번역기다.

아래 문장을 자연스러운 한국어로 번역하라.

규칙:
1. 출력은 번역 결과 한 문장 또는 원문의 자연스러운 한국어 버전만 반환한다.
2. 다음과 같은 기술 키워드는 필요 시 원문 그대로 유지한다:
   AWS, IAM, EC2, S3, RDS, Terraform, Docker, Kubernetes, OWASP, SonarQube, Semgrep,
   tfsec, Checkov, Trivy, Dependency-Check, OWASP ZAP, CVE, CWE, SQL Injection, XSS,
   파일 경로, 패키지명, 버전, 리소스명, 코드 조각, 라인 번호
3. 의미를 축약하거나 생략하지 마라.
4. 이미 한국어면 그대로 반환하라.
5. 불필요한 설명, 따옴표, JSON 포맷 없이 결과 텍스트만 반환하라.

원문:
{text}
""".strip()

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    max_output_tokens=300,
                ),
            )

            translated = (response.text or "").strip()
            if not translated:
                logger.warning("번역 응답이 비어 있어 원문을 그대로 사용합니다. text=%s", text)
                return text

            return translated

        except Exception as e:
            logger.exception("번역 중 오류 발생. 원문을 그대로 사용합니다. error=%s", str(e))
            return text

    def translate_finding_fields(self, finding: Dict) -> Dict:
        """
        finding dict에서 번역 대상 필드만 한국어로 바꿔서 반환
        기술 식별용 필드는 그대로 유지
        """
        translated = dict(finding)

        # title 번역
        if "title" in translated:
            translated["title"] = self._translate_text(translated.get("title"))

        # description 번역
        if "description" in translated:
            translated["description"] = self._translate_text(translated.get("description"))

        # message 번역
        if "message" in translated:
            translated["message"] = self._translate_text(translated.get("message"))

        # 필요하면 recommendation / remediation 등도 확장 가능
        if "recommendation" in translated:
            translated["recommendation"] = self._translate_text(translated.get("recommendation"))

        return translated