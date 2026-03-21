# SecureFlow Dashboard Bootstrap

This stack creates Terraform backend resources for the separate `secureflow_dashboard_infra` deployment.

It creates:

- S3 bucket for Terraform state
- DynamoDB table for Terraform locking
- KMS key for Terraform state encryption

## Usage

```powershell
cd secureflow_dashboard_infra/bootstrap
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform apply -var-file="terraform.tfvars"
```

After apply, copy the outputs into `../backend.hcl` or pass them directly to `terraform init` in the main stack.

Example:

```powershell
cd ..
terraform init `
  -backend-config="bucket=<bootstrap-state-bucket>" `
  -backend-config="key=secureflow_dashboard_infra/terraform.tfstate" `
  -backend-config="region=ap-northeast-2" `
  -backend-config="dynamodb_table=<bootstrap-lock-table>" `
  -backend-config="encrypt=true"
```
