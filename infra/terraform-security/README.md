# Terraform Security Baseline

This folder manages account and region level security controls that support
ISMS-P checks without overlapping ownership with the existing application stack.

## Scope

- CloudTrail
- AWS Config recorder and selected managed rules
- Security Hub and FSBP
- GuardDuty
- Account-level ECR registry scanning
- VPC Flow Logs
- Optional incident response baseline

## Out of Scope

These resources are already owned by the main Terraform stack and should stay
there:

- VPC, ALB, ECS, ECR repositories, S3 application buckets
- RDS instances and subnet groups
- DynamoDB, SQS, SNS, Secrets

## Ownership Rule

One AWS resource must belong to exactly one Terraform state.

Use this stack for shared security controls. Keep application resource
hardening in the owner stack for that resource.

Examples:

- RDS `copy_tags_to_snapshot`: existing RDS module
- ECR repository settings: existing ECR module
- ECR registry scanning: this security stack

## Suggested Rollout Order

1. Initialize this stack with backend settings.
2. Use the `shared` backend/tfvars for singleton regional services:
   Security Hub, Config, GuardDuty, ECR registry scanning, and CloudTrail.
3. Import or align existing singleton services before enabling ownership:
   Security Hub, Config, GuardDuty, and any existing VPC Flow Logs.
4. Create CloudTrail only after confirming there is no live trail to preserve.
5. Re-run the ISMS-P report and compare reduced `INSUFFICIENT_DATA`.
6. Import existing Flow Logs and WAF only after confirming exact live config.
7. Update the application stack for RDS and repository-level ECR hardening.

## Notes

- `waf.tf` is intentionally a stub because importing an existing Web ACL safely
  requires preserving the current full rule set first.
- `enable_incident_response` should remain false unless the account is allowed
  to use Incident Manager.
- `config.tf` and `flowlogs.tf` are written to support existing live resources,
  but you should still import before turning the flags on.
- `backend.shared.hcl` plus `environments/shared/terraform.tfvars` should be
  the only state used for account/region singleton services in this account.
- `backend.dev.hcl` and `backend.prod.hcl` are for environment-scoped follow-up
  work such as per-VPC flow logs or per-environment WAF ownership.
- Keep real backend and tfvars values local.
- This repository should only contain sanitized example files for backend/tfvars.

## Backend Init

Example init commands:

```powershell
cd infra/terraform-security
Copy-Item backend.shared.hcl.example backend.shared.hcl
Copy-Item environments/shared/terraform.tfvars.example environments/shared/terraform.tfvars
terraform init -backend-config="backend.shared.hcl"
terraform plan -var-file="environments/shared/terraform.tfvars"
```

```powershell
cd infra/terraform-security
Copy-Item backend.dev.hcl.example backend.dev.hcl
Copy-Item environments/dev/terraform.tfvars.example environments/dev/terraform.tfvars
terraform init -backend-config="backend.dev.hcl"
terraform plan -var-file="environments/dev/terraform.tfvars"
```

```powershell
cd infra/terraform-security
Copy-Item backend.prod.hcl.example backend.prod.hcl
Copy-Item environments/prod/terraform.tfvars.example environments/prod/terraform.tfvars
terraform init -backend-config="backend.prod.hcl"
terraform plan -var-file="environments/prod/terraform.tfvars"
```
