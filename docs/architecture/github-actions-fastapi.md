# GitHub Actions ECS CD Setup

파일 이름은 `fastapi`라는 이름을 갖고 있지만, 현재 문서는 저장소 전체 GitHub Actions 흐름을 설명합니다.

## 주요 워크플로

- `.github/workflows/ci-security-scan.yml`
- `.github/workflows/cd-deploy.yml`
- `.github/workflows/reusable-ecs-deploy.yml`
- `.github/workflows/tool-integrity-check.yml`

## CI 흐름

현재 CI는 다음 축으로 구성됩니다.

### 대상 앱 기본 검증

- FastAPI smoke test
- Node syntax check
- Spring package build
- frontend build

### 보안 스캔

- IaC
  - Checkov
  - tfsec
- SAST
  - Semgrep
  - SonarQube
- SCA
  - Trivy
  - OWASP Dependency-Check

### LLM 게이트 및 업로드

- `run_llm_gate.py`
- `run_llm_judgments.py`

CI는 raw 결과와 gate 결과를 백엔드로 업로드하고, 현재 백엔드와의 호환성을 위해 Phase 1 dashboard analyze도 호출합니다.

## CD 흐름

### 1. context 결정

`cd-deploy.yml`은 다음 값을 기준으로 실행 흐름을 정합니다.

- branch
- source sha
- target service
- staging 여부
- production 여부

### 2. staging ECS 배포

`reusable-ecs-deploy.yml`을 사용해 각 서비스 이미지를 빌드/푸시하고 ECS에 반영합니다.

대상 서비스:

- FastAPI
- Node
- Spring
- frontend

### 3. staging 보안 단계

- Image scan
  - Trivy
  - Grype
- DAST
  - ZAP
  - Nuclei
- ISMS-P gate

### 4. 대시보드 반영

CD도 raw 결과와 gate 결과를 업로드하고, 현재 백엔드와의 호환성을 위해 Phase 2 dashboard analyze를 호출합니다.

## production 배포 정책

현재 코드 기준으로 final production ECS 배포는 `main` 브랜치에서만 가능합니다.

즉:

- `SEO`, `nayoung`, `sun`
  - staging / 보안 검사 / 대시보드 반영까지만
- `main`
  - production ECS deploy 가능

## 필수 GitHub Secrets

- `API_SERVER_URL`
- `SECUREFLOW_UPLOAD_KEY`
- `GEMINI_API_KEY`
- `SONAR_TOKEN`
- 필요 시 `OPENAI_API_KEY`

## 필수 GitHub Variables

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `AWS_ROLE_TO_ASSUME`

선택적으로:

- `AWS_ROLE_TO_ASSUME_PROD`
- `DAST_STAGING_TARGET_URL`
- `DAST_TARGET_URL`
- `ZAP_TARGET_URL`
- `GEMINI_MODEL`
- `SONAR_HOST_URL`
- `SONAR_ORGANIZATION`
- `SONAR_PROJECT_KEY`

## 중요 운영 메모

- 업로드는 `API_SERVER_URL` 기준으로 수행합니다.
- WAF가 있으면 `X-SecureFlow-Upload-Key` 헤더가 필요합니다.
- `SECUREFLOW_UPLOAD_KEY`는 Terraform의 bypass key와 동일해야 합니다.
- DAST 대표 URL은 CloudFront 또는 ALB 주소를 권장합니다.
