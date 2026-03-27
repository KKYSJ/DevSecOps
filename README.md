# SecureFlow

SecureFlow is a DevSecOps platform repository that combines:

- a security analysis platform (`backend`, `engine`, `frontend`, `ismsp`)
- sample deploy targets (`app/*`)
- GitHub Actions pipelines for CI/CD and security gating
- AWS infrastructure code for the dashboard/runtime environment

The current pipeline design runs paired security tools per domain, sends raw results and LLM gate results to the backend, and uses the dashboard as the reporting surface.

## What Is In This Repository

This repository is intentionally split into two layers.

### 1. SecureFlow platform

- `backend/`: FastAPI API, database models, report endpoints, Celery integration
- `engine/`: parsing, normalization, matching, scoring, and reporting utilities
- `frontend/`: SecureFlow dashboard UI
- `ismsp/`: ISMS-P gate/report helpers
- `secureflow_dashboard_infra/`: Terraform for AWS infrastructure

### 2. Deploy target applications

- `app/api-server-fastapi/`: FastAPI sample API
- `app/api-server-node/`: Express sample API
- `app/api-server-spring/`: Spring Boot sample API
- `app/frontend/`: React sample frontend

These target apps are what the CI/CD pipeline scans, gates, and deploys.

## Architecture

At a high level, the repository works like this:

1. GitHub Actions runs CI security checks against the target apps and infrastructure.
2. Each security domain uses two tools where applicable.
3. LLM gate scripts generate cross-check decisions from those tool outputs.
4. Raw scanner outputs and gate outputs are uploaded to the SecureFlow backend.
5. The backend stores scan data and generates dashboard reports.
6. CD deploys staging services first, runs image scan / DAST / ISMS-P checks, and only allows production ECS deployment from `main`.

![SecureFlow architecture](docs/assets/architecture/secureflow-architecture.png)

## Tech Stack

### Platform

| Area | Stack |
| --- | --- |
| Backend API | FastAPI, SQLAlchemy, Pydantic, Alembic |
| Async / workers | Celery, Redis |
| Database | PostgreSQL, SQLite (local/dev usage exists in repo) |
| Dashboard frontend | React 19, TypeScript, Vite 7, Tailwind CSS 4, Radix UI, Recharts |
| Analysis / reporting | Python, custom engine modules, ReportLab |
| LLM integration | Google GenAI / Gemini-based scripts and gates |
| Compliance | boto3-based ISMS-P checks |

### Security Tooling

| Domain | Tools |
| --- | --- |
| SAST | Semgrep, SonarQube |
| SCA | Trivy, OWASP Dependency-Check |
| IaC | Checkov, tfsec |
| Image | Trivy, Grype |
| DAST | ZAP, Nuclei |
| Gate layer | LLM gate scripts in `scripts/ci/` |

### Target application stack

| App | Stack |
| --- | --- |
| `app/api-server-fastapi` | FastAPI, Uvicorn |
| `app/api-server-node` | Express, AWS SDK v3, MySQL / Redis-related packages |
| `app/api-server-spring` | Spring Boot 3.2, Java 17, Redis, JDBC |
| `app/frontend` | React, Vite |

### Infrastructure and delivery

| Area | Stack |
| --- | --- |
| CI/CD | GitHub Actions |
| Containers | Docker, Docker Compose |
| AWS infra | Terraform |
| Runtime services | ECS, ECR, ALB, CloudFront, WAF, RDS, Redis, S3, CloudWatch, Secrets Manager |

## Repository Map

```text
secureflow/
+-- .github/workflows/           CI/CD and security workflows
+-- app/                         Deploy target applications
|   +-- api-server-fastapi/
|   +-- api-server-node/
|   +-- api-server-spring/
|   '-- frontend/
+-- backend/                     FastAPI backend for SecureFlow
+-- engine/                      Parsing, matching, scoring, reporting logic
+-- frontend/                    SecureFlow dashboard frontend
+-- ismsp/                       ISMS-P tooling
+-- docs/                        Architecture and usage docs
+-- infra/                       Docker / worker infra assets
'-- secureflow_dashboard_infra/  Terraform for AWS deployment
```

## Current CI/CD Flow

### CI

- App validation runs for the sample FastAPI, Node, Spring, and frontend targets.
- IaC, SAST, and SCA jobs run paired tools.
- LLM gate results are generated and uploaded to the backend.
- Raw scan results are uploaded to the backend.
- Phase 1 dashboard analysis is triggered for current backend compatibility.

### CD

- Staging ECS deployment runs through reusable ECS deploy workflow.
- Image scans run on the built staging images.
- DAST runs against a representative target URL.
- ISMS-P pre-production gate runs after image and DAST gates.
- Phase 2 dashboard analysis is triggered for current backend compatibility.

### Production deployment policy

- Branches such as `SEO`, `sun`, and other non-`main` branches can run CI, staging/security checks, uploads, and dashboard updates.
- Only `main` is allowed to deploy the final production ECS services.

## Upload / API Notes

- Workflow uploads use `API_SERVER_URL`.
- WAF bypass uploads use the `X-SecureFlow-Upload-Key` header.
- `SECUREFLOW_UPLOAD_KEY` in GitHub Secrets must match the infrastructure-side bypass key.
- For DAST, the preferred representative URL is a CloudFront or ALB URL, not a direct EC2 IP and not an internal container port like `:8000`.

## Local Development

### Prerequisites

- Docker / Docker Compose
- Python 3.11+ for local script execution
- Node.js 20+ if you want to run frontend or target apps directly
- A configured `.env` file for backend runtime settings

### Start with Docker Compose

```bash
docker compose up --build -d
```

Or use the Makefile:

```bash
make up
```

### Local endpoints

- Dashboard frontend: `http://localhost:3000`
- Backend API docs: `http://localhost:8000/docs`
- Backend API base: `http://localhost:8000/api/v1`
- SonarQube: `http://localhost:9000`

### Common commands

```bash
make logs
make test
make migrate
make seed
docker compose down
```

## Useful Docs

- [Architecture index](docs/architecture/README.md)
- [Local setup guide](docs/guides/local-setup.md)
- [Deployment guide](docs/guides/deployment.md)
- [Tool setup guide](docs/guides/tool-setup.md)
- [API docs index](docs/api/README.md)

## Notes

- The root `frontend/` directory is the SecureFlow dashboard.
- The `app/frontend/` directory is a separate sample frontend used as a deployment target.
- The root `backend/` directory is the SecureFlow backend, not the sample FastAPI app.
- The current workflows are tuned around backend uploads, dashboard visibility, and `main`-only production ECS deployment.
