# Target App And DevSecOps Architecture

이 문서는 현재 저장소를 어떤 아키텍처로 이해해야 하는지 정리합니다.

## 핵심 해석

이 저장소는 "하나의 앱"이 아니라 아래 두 묶음을 함께 담고 있습니다.

### 1. 대상 애플리케이션 묶음

- `app/frontend`
- `app/api-server-fastapi`
- `app/api-server-node`
- `app/api-server-spring`

### 2. DevSecOps / SecureFlow 플랫폼 묶음

- `frontend`
- `backend`
- `engine`
- `ismsp`
- `secureflow_dashboard_infra`

즉, SecureFlow는 대상 서비스를 검사하고 보고하는 플랫폼이고, `app/*`는 그 플랫폼이 실제로 스캔/배포하는 대상입니다.

## 현재 구조를 이렇게 보는 이유

실제 코드 기준으로도 두 축의 역할이 분명히 갈립니다.

- `app/*`
  - CI/CD의 배포 대상
- `backend`
  - raw 결과 / gate 결과 수집
  - 대시보드 report 생성
- `frontend`
  - 보안 대시보드 UI
- `engine`
  - 분석 보조 로직
- `ismsp`
  - 클라우드 운영 항목 점검

## 현재 런타임 그림

### 대상 서비스 쪽

- frontend ECS
- FastAPI ECS
- Node ECS
- Spring ECS

### 플랫폼 쪽

- SecureFlow backend ECS
- worker ECS
- dashboard frontend
- PostgreSQL
- Redis
- S3 / CloudWatch / ECR / ECS / ALB / CloudFront / WAF

## CI/CD와의 연결

GitHub Actions는 대상 앱과 인프라에 대해 아래를 수행합니다.

- 기본 빌드/검증
- 보안 도구 2개씩 실행
- LLM gate 생성
- SecureFlow backend 업로드
- 대시보드 report 생성
- staging / production ECS 배포

현재 production ECS 배포는 `main`에서만 허용됩니다.

## 현재 문서 해석에서 중요한 구분

### `backend` vs `app/api-server-fastapi`

- `backend`
  - SecureFlow 플랫폼 API
- `app/api-server-fastapi`
  - 대상 샘플 FastAPI 앱

### `frontend` vs `app/frontend`

- `frontend`
  - SecureFlow 대시보드
- `app/frontend`
  - 사용자 대상 샘플 프론트엔드

## 권장 설명 방식

팀 문서나 발표 자료에서는 아래처럼 설명하는 것이 가장 덜 헷갈립니다.

```text
대상 서비스 계층
  - frontend 1개
  - API 3개

보안 플랫폼 계층
  - dashboard frontend
  - backend API
  - worker / engine
  - ISMS-P helpers
```
