# GitHub Actions ECS CD Setup

This repository now includes:

- `.github/workflows/ci-security-scan.yml`
- `.github/workflows/cd-deploy.yml`
- `.github/workflows/reusable-ecs-deploy.yml`

## CI coverage

The CI workflow runs on FastAPI and Terraform changes and performs:

- FastAPI smoke test against `/api/health`
- Python SAST with `bandit`
- Python dependency audit with `pip-audit`
- Docker image build for the FastAPI service
- Terraform formatting and validation
- IaC scan with `checkov` in advisory mode

## CD flow

The CD workflow now deploys all four dev ECS services:

- `api-server-fastapi`
- `api-server-node`
- `api-server-spring`
- `frontend`

On push to the `SEO` branch, GitHub Actions checks which service directories changed and deploys only those services.

Each deploy job:

1. assumes an AWS role through GitHub OIDC
2. builds and pushes a Docker image to ECR
3. tags that image with `short-sha + run-attempt`
4. reads the current ECS task definition
5. replaces the container image
6. registers a new task definition revision
7. updates the ECS service and waits for stability

The workflow intentionally uses a unique tag per run instead of `latest` because the ECR repositories are configured as immutable.

Terraform still creates the initial ECS services. After that, GitHub Actions owns image rollouts. Terraform can still update ECS task definitions later if you change infrastructure-managed settings such as environment variables, secrets, CPU, memory, or listener rules.

## Required AWS Terraform settings

Before the GitHub CD workflow can deploy, create the GitHub Actions role in AWS.

Recommended `infra/terraform/environments/dev/terraform.tfvars` values:

```tfvars
create_github_oidc_role = true
github_org              = "KKYSJ"
github_repo             = "DevSecOps"
github_branch           = "SEO"
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

The current CD workflow targets these dev resources in `ap-northeast-2`:

- FastAPI
  - ECR: `api-server-fastapi`
  - ECS service: `secureflow-dev-api-server-fastapi`
  - task family: `secureflow-dev-api-server-fastapi`
- Node
  - ECR: `api-server-node`
  - ECS service: `secureflow-dev-api-server-node`
  - task family: `secureflow-dev-api-server-node`
- Spring
  - ECR: `api-server-spring`
  - ECS service: `secureflow-dev-api-server-spring`
  - task family: `secureflow-dev-api-server-spring`
- Frontend
  - ECR: `frontend`
  - ECS service: `secureflow-dev-frontend`
  - task family: `secureflow-dev-frontend`

All services deploy into the ECS cluster `secureflow-dev-cluster`.

## How to use it

- Push FastAPI changes under `app/api-server-fastapi/**` to auto-deploy FastAPI
- Push Node changes under `app/api-server-node/**` to auto-deploy Node
- Push Spring changes under `app/api-server-spring/**` to auto-deploy Spring
- Push frontend changes under `app/frontend/**` to auto-deploy the frontend
- Run `CD Deploy` manually in GitHub Actions and choose `all`, `fastapi`, `node`, `spring`, or `frontend`
