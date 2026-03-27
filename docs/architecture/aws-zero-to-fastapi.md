# AWS Zero To FastAPI

이 문서는 저장소 안의 `app/api-server-fastapi`가 현재 구조에서 어떤 위치를 차지하는지 설명합니다.

## 이 문서에서 말하는 FastAPI

여기서 말하는 FastAPI는 루트 `backend/`가 아니라 아래 샘플 앱입니다.

- `app/api-server-fastapi/`

즉:

- `backend/` = SecureFlow 플랫폼 백엔드
- `app/api-server-fastapi/` = 배포/스캔 대상 샘플 FastAPI 앱

## 현재 역할

`app/api-server-fastapi`는 CI/CD에서 다른 대상 앱들과 함께 다음 역할을 가집니다.

- CI에서 smoke test 대상
- SAST / SCA / DAST / Image scan 대상
- staging ECS 배포 대상
- `main` 브랜치일 경우 production ECS 배포 대상

## CI에서 하는 일

현재 CI 워크플로에서 FastAPI 앱은 다음 검사를 거칩니다.

- Python 의존성 설치
- `pytest app/api-server-fastapi/tests -q`
- 이후 SAST / SCA / gate 흐름에 간접 포함

관련 워크플로:

- `.github/workflows/ci-security-scan.yml`

## CD에서 하는 일

CD에서는 `reusable-ecs-deploy.yml`을 통해 ECS에 배포됩니다.

현재 배포 정보는 대략 다음 기준을 사용합니다.

- build context: `app/api-server-fastapi`
- staging cluster: `secureflow-dev-cluster`
- production cluster: `secureflow-prod-cluster`
- 컨테이너 이름과 ECS 서비스 이름은 워크플로 입력값으로 관리

관련 워크플로:

- `.github/workflows/cd-deploy.yml`
- `.github/workflows/reusable-ecs-deploy.yml`

## production 배포 정책

현재 코드 기준으로 production ECS 배포는 `main` 브랜치에서만 허용됩니다.

즉 FastAPI 앱도 다음과 같이 동작합니다.

- `SEO`, `sun`, 기타 브랜치: staging/보안 검사까지만
- `main`: 최종 production ECS 배포 가능

## 인프라 연결

FastAPI 샘플 앱은 최종적으로 다음과 같은 AWS 경로를 따릅니다.

- GitHub Actions
- ECR image push
- ECS task definition 갱신
- ECS service rolling deploy
- ALB 뒤에서 서비스 URL 제공

배포 후 대표 URL은 `reusable-ecs-deploy.yml`의 `service_url` output으로 탐지됩니다.

## 문서 해석 팁

이 저장소에서 "FastAPI"라는 말이 두 군데를 가리킬 수 있으니 항상 구분해서 보는 것이 좋습니다.

- 플랫폼 FastAPI: `backend/`
- 대상 앱 FastAPI: `app/api-server-fastapi/`
