# 도구 및 연동 설정 가이드

이 문서는 현재 저장소 기준으로 보안 도구, GitHub Actions, 외부 연동 설정에서 꼭 알아야 할 항목을 정리합니다.

## 현재 사용하는 보안 도구

### SAST

- Semgrep
- SonarQube

### SCA

- Trivy
- OWASP Dependency-Check

### IaC

- Checkov
- tfsec

### Image

- Trivy
- Grype

### DAST

- ZAP
- Nuclei

## LLM 관련 설정

필수 또는 주요 값:

- `GEMINI_API_KEY`
- `GEMINI_MODEL`

관련 스크립트:

- `scripts/ci/run_llm_gate.py`
- `scripts/ci/run_llm_judgments.py`
- `scripts/ci/run_overall_verdict.py`
- `scripts/ci/run_ismsp_gate.py`

## SonarQube 관련 설정

필요 값:

- `SONAR_HOST_URL`
- `SONAR_ORGANIZATION`
- `SONAR_PROJECT_KEY`
- `SONAR_TOKEN`

로컬 SonarQube는 `docker-compose.yml`로 함께 올릴 수 있습니다.

## AWS 관련 설정

필수 GitHub Variables:

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `AWS_ROLE_TO_ASSUME`

선택:

- `AWS_ROLE_TO_ASSUME_PROD`

## 업로드 관련 설정

### API URL

- `API_SERVER_URL`

이 값은 SecureFlow backend의 `/api/v1` base URL이어야 합니다.

### WAF bypass

- `SECUREFLOW_UPLOAD_KEY`

이 값은 업로드 시 아래 헤더로 전달됩니다.

- `X-SecureFlow-Upload-Key`

Terraform 쪽 `actions_upload_bypass_key`와 동일해야 합니다.

## DAST 관련 설정

대표 URL 관련 변수:

- `DAST_STAGING_TARGET_URL`
- `DAST_TARGET_URL`
- `ZAP_TARGET_URL`

권장값:

- CloudFront URL
- ALB URL

권장하지 않는 값:

- EC2 퍼블릭 IP
- 내부 포트 주소

## 현재 코드 기준 운영 팁

- raw 결과만 올라가면 대시보드가 바로 채워지지 않을 수 있습니다.
- 현재 워크플로는 analyze 호출까지 포함해 report 생성을 맞추고 있습니다.
- production ECS deploy는 `main`에서만 허용됩니다.
