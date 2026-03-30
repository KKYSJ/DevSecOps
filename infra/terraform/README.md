# Terraform Bootstrap And Base Stack

이 디렉터리는 대상 애플리케이션과 공통 AWS 기반 리소스를 올리기 위한 Terraform 스택입니다.
루트 `secureflow_dashboard_infra/`가 SecureFlow 플랫폼 자체 인프라라면, 이 디렉터리는 앱 계열과 그 기반 리소스에 더 가깝습니다.

## 구조

이 스택은 두 단계로 나뉩니다.

1. `bootstrap`
2. base infra (`infra/terraform`)

즉 흐름은 아래와 같습니다.

`bootstrap -> backend init -> plan/apply`

## bootstrap이 만드는 것

- Terraform state용 S3 bucket
- Terraform lock용 DynamoDB table
- Terraform state 암호화용 KMS key

## base infra가 만드는 것

- VPC
- public / private subnet
- NAT gateway
- ALB
- ECS cluster
- ECR repositories
- S3 bucket
- DynamoDB
- SQS / SNS
- CloudWatch log groups
- IAM / KMS
- optional RDS

실제 리소스는 `main.tf`, `modules/`, `outputs.tf`를 기준으로 확인하면 됩니다.

## 사전 준비

- Terraform 또는 OpenTofu
- AWS CLI
- AWS 인증 설정

확인:

```powershell
aws sts get-caller-identity
```

## bootstrap 적용

```powershell
cd infra/terraform/bootstrap
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform apply -var-file="terraform.tfvars"
```

## base stack 적용

예시 tfvars:

- `environments/dev/terraform.tfvars`

초기화 후 실행:

```powershell
cd ..
terraform init
terraform plan -var-file="environments/dev/terraform.tfvars"
terraform apply -var-file="environments/dev/terraform.tfvars"
```

## 운영 메모

- dev 환경은 비용 절감을 위해 `single_nat_gateway = true` 구성이 일반적입니다.
- 처음부터 RDS를 꼭 붙일 필요가 없다면 `create_rds = false`로 시작하는 편이 안전합니다.
- 리뷰 저장소 타입이나 앱별 DB 전략은 실제 대상 앱 구현에 맞춰 확인해야 합니다.

## SecureFlow와의 관계

이 디렉터리는 SecureFlow 플랫폼 자체 인프라 문서라기보다는, 앱/기반 AWS 리소스 문서에 가깝습니다.
SecureFlow 플랫폼용 최신 AWS 흐름은 아래 문서를 우선 참고하는 편이 좋습니다.

- `README.md`
- `docs/guides/deployment.md`
- `docs/architecture/aws-terraform-flow.md`
- `secureflow_dashboard_infra/README.md`
