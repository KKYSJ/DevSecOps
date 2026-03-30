# SecureFlow Dashboard Bootstrap

이 스택은 `secureflow_dashboard_infra` 본 스택이 사용할 Terraform remote state 리소스를 먼저 생성합니다.

## 생성 리소스

- Terraform state 저장용 S3 bucket
- Terraform lock용 DynamoDB table
- Terraform state 암호화용 KMS key

## 사용 순서

```powershell
cd secureflow_dashboard_infra/bootstrap
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform apply -var-file="terraform.tfvars"
```

적용 후 출력값을 본 스택 `backend.hcl`에 반영하거나, `terraform init`에 직접 넘겨서 사용합니다.

예시:

```powershell
cd ..
terraform init `
  -backend-config="bucket=<bootstrap-state-bucket>" `
  -backend-config="key=secureflow_dashboard_infra/terraform.tfstate" `
  -backend-config="region=ap-northeast-2" `
  -backend-config="dynamodb_table=<bootstrap-lock-table>" `
  -backend-config="encrypt=true"
```

## 참고

본 bootstrap은 SecureFlow 플랫폼용 인프라에만 해당합니다.
대상 앱 인프라와는 별도로 관리합니다.
