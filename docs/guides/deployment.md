# 배포 가이드

이 문서는 현재 저장소 기준으로 SecureFlow 관련 인프라와 CI/CD를 연결하는 기본 흐름을 설명합니다.

## 1. 인프라 준비

먼저 `secureflow_dashboard_infra/`를 기준으로 AWS 인프라를 준비합니다.

주요 결과물:

- ALB / CloudFront
- WAF
- ECS cluster
- ECR
- RDS PostgreSQL
- Redis
- S3 / Secrets Manager / CloudWatch

적용 후 확인할 값:

- `frontend_url`
- `backend_api_url`
- `github_secret_backend_url`
- `github_repository_variables`

## 2. GitHub Secrets / Variables 설정

### Secrets

- `API_SERVER_URL`
- `SECUREFLOW_UPLOAD_KEY`
- `GEMINI_API_KEY`
- `SONAR_TOKEN`
- 필요 시 `OPENAI_API_KEY`

### Variables

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `AWS_ROLE_TO_ASSUME`
- 필요 시 `AWS_ROLE_TO_ASSUME_PROD`
- `DAST_STAGING_TARGET_URL`
- `GEMINI_MODEL`
- `SONAR_HOST_URL`
- `SONAR_ORGANIZATION`
- `SONAR_PROJECT_KEY`

## 3. 브랜치별 동작

현재 코드 기준으로 CD chaining 대상 브랜치는 아래와 같습니다.

- `SEO`
- `nayoung`
- `sun`
- `main`

다만 production ECS deploy는 `main`에서만 허용됩니다.

즉:

- non-`main`
  - CI
  - staging/security checks
  - backend 업로드
  - 대시보드 반영
- `main`
  - 위 전체 + production ECS deploy

## 4. staging 배포

`cd-deploy.yml`은 `reusable-ecs-deploy.yml`을 통해 아래 서비스를 staging에 배포합니다.

- FastAPI
- Node
- Spring
- frontend

배포 후 각 job은 `service_url`과 `image_uri`를 output으로 남깁니다.

## 5. DAST 대상 URL

현재 DAST는 대표 URL 1개를 사용합니다.

우선순위:

1. `DAST_STAGING_TARGET_URL`
2. `DAST_TARGET_URL`
3. `ZAP_TARGET_URL`
4. staging deploy output의 `service_url`

권장값:

- dev/staging CloudFront URL
- dev/staging ALB URL

비권장값:

- EC2 퍼블릭 IP
- 내부 포트 주소 (`:8000`)

## 6. 대시보드 반영

현재 백엔드 구조에서는 raw 결과 업로드만으로는 대시보드가 채워지지 않습니다.
그래서 워크플로는 현재 아래까지 수행합니다.

- raw 결과 업로드
- gate 결과 업로드
- 짧은 대기
- `POST /api/v1/scans/analyze`

이 흐름이 살아 있어야 대시보드의 report / history가 정상적으로 보입니다.
