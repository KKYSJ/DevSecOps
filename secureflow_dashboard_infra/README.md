# SecureFlow Dashboard AWS Terraform

This stack is a separate copy of `dashboard_infra` so the existing deployed environment can remain untouched.

What is separated here:

- Resource names start with `secureflow-dashboard`
- The VPC defaults to `10.50.0.0/16`
- The Terraform backend state key is `secureflow_dashboard_infra/terraform.tfstate`
- The Terraform backend bucket and lock table are created by `secureflow_dashboard_infra/bootstrap`
- `dashboard_infra` is left unchanged

Security controls included:

- Public ALB with WAF and access logging
- CloudFront HTTPS entrypoint without a custom domain
- VPC Flow Logs to encrypted CloudWatch Logs
- KMS for app data and CloudWatch Logs
- Encrypted S3 buckets with TLS-only bucket policies
- RDS PostgreSQL with SSL forced, log exports, Performance Insights, and Enhanced Monitoring
- Redis with encryption at rest, TLS in transit, and auth token
- ECS task roles scoped for reports bucket access and read-only security checks
- CloudWatch alarms for ALB, ECS, and RDS health

## GitHub variable and secret mapping

Terraform still cannot read GitHub repository variables and secrets automatically from a local shell.
For the current GitHub Actions deployment flow, only the AWS deployment variables are required because the workflow is infrastructure-only.

Required for GitHub Actions deployment:

- GitHub variable `AWS_ACCOUNT_ID`
- GitHub variable `AWS_REGION`
- GitHub variable `AWS_ROLE_TO_ASSUME`

Notes:

- `AWS_ACCOUNT_ID` is detected automatically with STS.
- `AWS_ROLE_TO_ASSUME` stays in GitHub Actions and is not consumed by Terraform itself.
- App-related secrets and variables such as `GEMINI_API_KEY`, `SONAR_TOKEN`, `GEMINI_MODEL`, and `SONAR_*` are not used by the infrastructure-only GitHub Actions deployment.
- The repository now includes `.github/workflows/secureflow-dashboard-deploy.yml` for the dashboard stack.

## GitHub Actions deployment

`cd-deploy.yml` is now the entrypoint for GitHub Actions deployment, and it calls `secureflow-dashboard-deploy.yml` internally.

This deployment flow is infrastructure-only:

- It creates or updates the AWS infrastructure defined in `secureflow_dashboard_infra`
- It creates or reuses the dedicated Terraform state bucket and lock table
- It migrates the bootstrap Terraform state into S3 so later runs stay consistent
- It forces ECS desired counts to `0`
- It does not build or push application images
- It does not populate LLM or scanner secrets
- It does not run IaC, SAST, SCA, or DAST jobs

Required repository variables:

- `AWS_ACCOUNT_ID`
- `AWS_REGION`
- `AWS_ROLE_TO_ASSUME`

Optional repository variables:

- `ALARM_EMAIL`
- `ACM_CERTIFICATE_ARN`

The deployment workflow runs automatically on every push to the `SUN` branch.

You can also run it manually with `workflow_dispatch`.

Important behavior:

- `frontend`, `backend`, and `worker` ECS services are created with desired count `0`
- URLs such as `frontend_url` and `backend_api_url` are infrastructure endpoints only
- The application itself will not respond until you later build and deploy containers on top of this infrastructure
- If bootstrap resources already exist but the bootstrap state file is missing, the workflow attempts an automatic bootstrap state recovery and uploads detailed recovery logs as artifacts

## HTTPS without a domain

This stack enables CloudFront by default when `enable_cloudfront_https = true`.
That gives you a public URL such as `https://d123example.cloudfront.net` without buying a domain or issuing your own certificate.

Important limitation:

- Client to CloudFront is HTTPS.
- CloudFront to the ALB is HTTPS only if you later attach an ACM certificate to the ALB.
- Without an ACM certificate, the CloudFront origin connection uses HTTP inside AWS.

## Usage

```powershell
cd secureflow_dashboard_infra/bootstrap
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init
terraform apply -var-file="terraform.tfvars"

cd ..
Copy-Item backend.hcl.example backend.hcl
Copy-Item terraform.tfvars.example terraform.tfvars
terraform init -backend-config="backend.hcl"
terraform plan
terraform apply
```

After apply, use the outputs:

- `frontend_url` for the user-facing URL
- `backend_api_url` for the API base URL
- `github_repository_variables` for values such as `DAST_STAGING_TARGET_URL`
- `db_secret_arn`, `redis_secret_arn`, and `external_api_secret_arn` for the split runtime secrets
- `external_api_secret_template` as the JSON skeleton to store in the external API secret
