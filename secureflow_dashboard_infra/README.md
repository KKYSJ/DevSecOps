# SecureFlow Dashboard AWS Terraform

이 디렉터리는 SecureFlow 플랫폼 자체를 AWS에 배포하기 위한 Terraform 스택입니다.
루트 `app/*` 대상 애플리케이션용 인프라와는 별도로, SecureFlow 대시보드와 API 서버, worker, 데이터 계층을 올리는 용도로 사용합니다.

## 포함 범위

현재 코드 기준으로 이 스택은 아래 리소스를 다룹니다.

- VPC / subnet / NAT gateway
- ALB
- CloudFront
- WAF
- ECS cluster / service
- ECR repositories
- RDS PostgreSQL
- Redis
- S3
- Secrets Manager
- IAM / KMS
- CloudWatch / SNS 알림

## 배포 대상 서비스

이 스택으로 배포되는 SecureFlow 구성요소는 보통 아래 3개입니다.

- frontend ECS service
- backend ECS service
- worker ECS service

대상 앱인 `app/api-server-*`, `app/frontend`와는 별개입니다.

## 주요 입력값

예시 파일:

- `terraform.tfvars.example`
- `backend.hcl.example`

실행 전 주로 맞추는 값:

- AWS region
- ALB / CloudFront / WAF 사용 여부
- ECS desired count
- DB / Redis 관련 설정
- `actions_upload_bypass_key`

## GitHub Actions와 연결되는 값

현재 저장소의 CI/CD 기준으로 중요한 값은 아래입니다.

### GitHub Secrets

- `API_SERVER_URL`
- `SECUREFLOW_UPLOAD_KEY`
- `GEMINI_API_KEY`
- `OPENAI_API_KEY`
- `SONAR_TOKEN`

### GitHub Variables

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `AWS_ROLE_TO_ASSUME`
- `AWS_ROLE_TO_ASSUME_PROD`
- `GEMINI_MODEL`
- `SONAR_HOST_URL`
- `SONAR_ORGANIZATION`
- `SONAR_PROJECT_KEY`
- `DAST_STAGING_TARGET_URL`

## WAF 우회 업로드

CloudFront와 WAF가 활성화된 경우 GitHub Actions의 raw scan 업로드와 gate 업로드가 차단될 수 있습니다.
현재 워크플로는 아래 헤더를 사용해 업로드를 보냅니다.

- 헤더: `X-SecureFlow-Upload-Key`
- GitHub Secret: `SECUREFLOW_UPLOAD_KEY`
- Terraform 변수: `actions_upload_bypass_key`

즉 `SECUREFLOW_UPLOAD_KEY` 값과 `actions_upload_bypass_key` 값은 같아야 합니다.

## DAST 대표 URL

현재 CD는 대표 URL 1개를 대상으로 DAST를 수행합니다.
권장값은 아래와 같습니다.

- dev/staging CloudFront URL
- 또는 dev/staging ALB URL

권장하지 않는 값:

- EC2 퍼블릭 IP
- 컨테이너 내부 포트 주소 (`:8000`)

보통 `DAST_STAGING_TARGET_URL`에는 dev용 ALB 또는 CloudFront 주소를 넣습니다.

## 기본 사용 순서

### 1. bootstrap 적용

```powershell
cd secureflow_dashboard_infra/bootstrap
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform apply -var-file="terraform.tfvars"
```

### 2. 본 스택 초기화

```powershell
cd ..
Copy-Item backend.hcl.example backend.hcl
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init -backend-config="backend.hcl"
terraform plan
terraform apply
```

## 주요 출력값

적용 후 아래 출력값을 주로 사용합니다.

- `frontend_url`
- `backend_api_url`
- `github_secret_backend_url`
- `github_repository_variables`
- `db_secret_arn`
- `redis_secret_arn`
- `external_api_secret_arn`

이 값들은 GitHub Actions와 런타임 설정 연결에 사용됩니다.
