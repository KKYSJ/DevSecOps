# Terraform Security Baseline

이 디렉터리는 계정/리전 단위 보안 베이스라인 리소스를 관리하는 Terraform 스택입니다.
애플리케이션 스택과 리소스 소유권이 겹치지 않도록, 공통 보안 서비스만 별도 상태로 관리하는 용도입니다.

## 범위

- CloudTrail
- AWS Config recorder 및 일부 managed rule
- Security Hub
- GuardDuty
- 계정 단위 ECR registry scanning
- VPC Flow Logs
- 선택적 incident response baseline

## 범위 밖

아래 리소스는 각 애플리케이션 또는 플랫폼 스택 소유로 남겨두는 편이 맞습니다.

- VPC
- ALB
- ECS
- 개별 ECR repository
- S3 애플리케이션 bucket
- RDS
- DynamoDB
- SQS / SNS
- Secrets Manager

## 운영 원칙

하나의 AWS 리소스는 하나의 Terraform state만 소유해야 합니다.

예시:

- ECR repository별 설정: 리포지토리 owner stack
- ECR registry 수준 스캔: 이 security stack
- RDS hardening: RDS를 생성하는 owner stack

## 권장 적용 순서

1. backend 설정 준비
2. shared 환경 state 초기화
3. 기존 singleton 리소스 존재 여부 확인
4. 필요한 리소스 import 또는 정렬
5. plan / apply
6. 이후 ISMS-P 결과 비교

## backend 예시

### shared

```powershell
cd infra/terraform-security
Copy-Item backend.shared.hcl.example backend.shared.hcl
Copy-Item environments/shared/terraform.tfvars.example environments/shared/terraform.tfvars
terraform init -backend-config="backend.shared.hcl"
terraform plan -var-file="environments/shared/terraform.tfvars"
```

### dev

```powershell
cd infra/terraform-security
Copy-Item backend.dev.hcl.example backend.dev.hcl
Copy-Item environments/dev/terraform.tfvars.example environments/dev/terraform.tfvars
terraform init -backend-config="backend.dev.hcl"
terraform plan -var-file="environments/dev/terraform.tfvars"
```

### prod

```powershell
cd infra/terraform-security
Copy-Item backend.prod.hcl.example backend.prod.hcl
Copy-Item environments/prod/terraform.tfvars.example environments/prod/terraform.tfvars
terraform init -backend-config="backend.prod.hcl"
terraform plan -var-file="environments/prod/terraform.tfvars"
```

## 메모

- `waf.tf`는 기존 live WAF를 안전하게 맞추기 전까지 stub 성격일 수 있습니다.
- 실제 계정의 singleton 서비스는 import 없이 바로 생성하지 않는 편이 안전합니다.
- 실사용 backend/tfvars 값은 로컬에서만 관리하고 저장소에는 예시 파일만 두는 것을 권장합니다.
