# FastAPI GitHub Actions Setup

This repository now includes:

- `.github/workflows/ci-security-scan.yml`
- `.github/workflows/cd-deploy.yml`

## CI coverage

The CI workflow runs on FastAPI and Terraform changes and performs:

- FastAPI smoke test against `/api/health`
- Python SAST with `bandit`
- Python dependency audit with `pip-audit`
- Docker image build for the FastAPI service
- Terraform formatting and validation
- IaC scan with `checkov` in advisory mode

## CD flow

The CD workflow deploys the FastAPI service to the dev ECS service by:

1. assuming an AWS role through GitHub OIDC
2. building and pushing a Docker image to ECR with the commit SHA as the tag
3. reading the current ECS task definition
4. replacing the container image
5. registering a new task definition revision
6. updating the ECS service and waiting for stability

The deploy workflow intentionally uses the commit SHA instead of `latest` because the ECR repositories are configured as immutable.

Terraform creates the initial ECS service, but the GitHub Actions CD workflow owns later image rollouts. The ECS service module ignores external `task_definition` revisions so future Terraform applies do not roll the service back to an older image tag.

## Required AWS Terraform settings

Before the GitHub CD workflow can deploy, create the GitHub Actions role in AWS.

Recommended `infra/terraform/environments/dev/terraform.tfvars` values:

```tfvars
create_github_oidc_role = true
github_org              = "KKYSJ"
github_repo             = "DevSecOps"
github_branch           = "main"
```

Then apply Terraform again from `infra/terraform`:

```powershell
terraform apply -var-file="environments/dev/terraform.tfvars"
```

After that, copy the `github_actions_role_arn` Terraform output.

## Required GitHub repository variable

Set this repository variable in GitHub:

- `AWS_ROLE_TO_ASSUME`

Value:

- the ARN from `terraform output github_actions_role_arn`

## Runtime defaults used by the deploy workflow

The current CD workflow targets these dev resources:

- region: `ap-northeast-2`
- ECR repository: `api-server-fastapi`
- ECS cluster: `secureflow-dev-cluster`
- ECS service: `secureflow-dev-api-server-fastapi`
- ECS task family: `secureflow-dev-api-server-fastapi`

If those names change later, update `.github/workflows/cd-deploy.yml`.
