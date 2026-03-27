# AWS Terraform Flow

이 문서는 현재 저장소 기준으로 AWS 인프라를 어떻게 적용하고, 그 결과를 GitHub Actions와 어떻게 연결하는지 정리합니다.

## 현재 기준 인프라 디렉터리

운영 기준점은 아래 디렉터리입니다.

- `secureflow_dashboard_infra/`

이 디렉터리는 SecureFlow 대시보드 런타임 인프라를 위한 Terraform 코드를 포함합니다.

## 배포 흐름

### 1. Terraform bootstrap

원격 state를 사용하려면 먼저 bootstrap 리소스를 준비합니다.

- S3 state bucket
- DynamoDB lock table
- 필요한 KMS 리소스

관련 경로:

- `secureflow_dashboard_infra/bootstrap/`

### 2. 메인 인프라 적용

메인 인프라는 아래와 같은 리소스를 생성합니다.

- VPC
- ALB
- CloudFront
- WAF
- ECS cluster
- ECR repositories
- RDS PostgreSQL
- ElastiCache Redis
- S3 buckets
- Secrets Manager
- CloudWatch / SNS / IAM 관련 리소스

관련 경로:

- `secureflow_dashboard_infra/`

### 3. Terraform 출력값 확인

배포 후 특히 아래 출력값이 중요합니다.

- `frontend_url`
- `backend_api_url`
- `github_secret_backend_url`
- `github_repository_variables`
- `cloudfront_domain_name`
- `alb_dns_name`

출력 정의는 여기 있습니다.

- `secureflow_dashboard_infra/outputs.tf`

## GitHub와 연결하는 값

### GitHub Secrets

- `API_SERVER_URL`
  - `github_secret_backend_url` 값을 사용하는 것이 가장 안전합니다.
- `SECUREFLOW_UPLOAD_KEY`
  - WAF 우회용 업로드 헤더 값
- `GEMINI_API_KEY`
- `SONAR_TOKEN`
- 필요 시 `OPENAI_API_KEY`

### GitHub Variables

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `AWS_ROLE_TO_ASSUME`
- 선택적으로 `AWS_ROLE_TO_ASSUME_PROD`
- `GEMINI_MODEL`
- `SONAR_HOST_URL`
- `SONAR_ORGANIZATION`
- `SONAR_PROJECT_KEY`
- `DAST_STAGING_TARGET_URL`

## WAF / CloudFront 관련 주의사항

CloudFront + WAF를 사용하는 환경에서는 GitHub Actions 업로드가 기본 규칙에 막힐 수 있습니다.

현재 저장소는 업로드 시 아래 헤더를 사용하도록 맞춰져 있습니다.

- `X-SecureFlow-Upload-Key`

따라서:

- Terraform의 `actions_upload_bypass_key`
- GitHub Secret `SECUREFLOW_UPLOAD_KEY`

이 두 값이 반드시 같아야 합니다.

## DAST 대상 URL 권장값

`DAST_STAGING_TARGET_URL`에는 아래 중 하나를 넣는 것이 좋습니다.

- dev/staging CloudFront URL
- dev/staging ALB URL

권장하지 않는 값:

- 특정 EC2 퍼블릭 IP
- 내부 컨테이너 포트 주소 (`:8000`)

현재 DAST는 대표 URL 1개를 기준으로 ZAP / Nuclei를 수행하므로, 실제 외부 진입점과 같은 URL을 써야 합니다.

## 현재 코드와의 연결점

- CI/CD 워크플로는 `API_SERVER_URL` 기준으로 결과를 업로드합니다.
- DAST 대표 URL은 GitHub Variables 우선순위를 통해 결정됩니다.
- production ECS 배포는 `main` 브랜치에서만 허용됩니다.
