# 아키텍처 문서 모음

이 디렉터리는 SecureFlow 저장소의 현재 구조를 코드 기준으로 설명하는 문서 모음입니다.

## 먼저 보면 좋은 문서

- [루트 README](../../README.md)
  - 저장소 전체 개요
- [Target App And DevSecOps Architecture](target-app-devsecops-architecture.md)
  - 저장소를 구성하는 두 축: 대상 앱과 SecureFlow 플랫폼
- [LLM Risk Gate Pipeline](llm-risk-gate-pipeline.md)
  - 2도구 + LLM gate 구조와 업로드 흐름
- [GitHub Actions ECS CD Setup](github-actions-fastapi.md)
  - 현재 GitHub Actions CI/CD 동작 방식

## 세부 문서

- [AWS Terraform Flow](aws-terraform-flow.md)
  - `secureflow_dashboard_infra` 기준 AWS 배포 흐름
- [AWS Zero To FastAPI](aws-zero-to-fastapi.md)
  - 샘플 FastAPI 앱이 현재 구조 안에서 어떤 역할인지 설명
- [Frontend One API Three Rollout](frontend-one-api-three-rollout.md)
  - 대상 프론트엔드 1개 + API 3개 + SecureFlow 플랫폼 분리 구조
- [Feature Based Routing](feature-based-routing.md)
  - 단일 ingress 아래 기능 단위 라우팅 권장 구조

## 아키텍처 이미지

루트 README에서 사용하는 아키텍처 이미지는 아래 경로를 사용합니다.

- `docs/assets/architecture/secureflow-architecture.png`
