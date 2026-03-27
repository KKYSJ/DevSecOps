# Frontend One API Three Rollout

이 문서는 현재 저장소를 다음 구조로 이해할 때 가장 덜 헷갈리도록 정리한 문서입니다.

## 현재 저장소에서의 역할 구분

### 대상 서비스

- `app/frontend`
- `app/api-server-fastapi`
- `app/api-server-node`
- `app/api-server-spring`

### SecureFlow 플랫폼

- `frontend`
- `backend`
- `engine`
- `ismsp`

즉, 저장소 안에는 "사용자에게 서비스되는 앱"과 "그 앱을 검사/분석/보고하는 플랫폼"이 함께 들어 있습니다.

## 왜 이 구분이 중요한가

처음 보면 `frontend`가 두 개이고, FastAPI도 두 개처럼 보여 혼동되기 쉽습니다.

- `frontend/`
  - SecureFlow 대시보드
- `app/frontend/`
  - 사용자 대상 샘플 프론트엔드

- `backend/`
  - SecureFlow 백엔드
- `app/api-server-fastapi/`
  - 대상 FastAPI 앱

## 현재 배포 관점

CD 워크플로는 대상 앱 쪽을 중심으로 staging / production ECS 배포를 수행합니다.

- 대상 프론트엔드 1개
- 대상 API 3개

SecureFlow 플랫폼 쪽은 별도 인프라/대시보드 문맥으로 이해하는 것이 맞습니다.

## 현재 롤아웃 설명

### 1. 대상 앱 롤아웃

- `app/frontend`
- `app/api-server-fastapi`
- `app/api-server-node`
- `app/api-server-spring`

이 네 서비스는 GitHub Actions CD에서 개별 ECS 서비스로 다뤄집니다.

### 2. 플랫폼 데이터 흐름

대상 앱과 인프라에서 나온 결과는 SecureFlow 플랫폼으로 들어갑니다.

- raw scan 결과 업로드
- LLM gate 결과 업로드
- judgments 업로드
- 대시보드 report 생성

### 3. production 정책

현재 코드 기준으로 final production ECS 배포는 `main`에서만 허용됩니다.

## 운영에서 권장하는 공개 구조

- 사용자 서비스 공개 진입점
  - CloudFront 또는 ALB
- SecureFlow 대시보드 공개 진입점
  - 별도 CloudFront 또는 별도 경로/도메인

이렇게 분리하면 사용자 서비스와 보안 대시보드의 역할이 명확해집니다.
