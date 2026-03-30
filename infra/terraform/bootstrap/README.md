# Bootstrap Stack

이 스택은 `infra/terraform` 본 스택에서 사용할 Terraform remote state 리소스만 먼저 생성합니다.

## 생성 리소스

- Terraform state 저장용 S3 bucket
- Terraform state lock용 DynamoDB table
- Terraform state 암호화용 KMS key

## 사전 준비

- Terraform 또는 OpenTofu
- AWS CLI
- AWS 인증 완료

확인:

```powershell
aws sts get-caller-identity
```

## 실행 방법

```powershell
cd infra/terraform/bootstrap
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform apply -var-file="terraform.tfvars"
```

적용 후 출력값은 상위 `infra/terraform` 스택의 backend 설정에 사용합니다.
