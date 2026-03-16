# Bootstrap Stack

이 스택은 Terraform remote state용 리소스만 만듭니다.

## 만드는 것

- S3 bucket for Terraform state
- DynamoDB table for Terraform state locking
- KMS key for Terraform state encryption

## 사전 준비

- `Terraform` 또는 `OpenTofu`
- `AWS CLI`
- AWS 자격증명 설정 완료

연동 확인:

```powershell
aws sts get-caller-identity
```

## 사용 순서

```powershell
cd infra/terraform/bootstrap
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform apply -var-file="terraform.tfvars"
```

이 스택의 출력값은 이후 `infra/terraform`에서 `terraform init -backend-config=...` 할 때 사용합니다.
