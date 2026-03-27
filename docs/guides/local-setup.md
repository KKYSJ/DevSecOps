# 로컬 실행 가이드

이 문서는 현재 저장소 기준으로 SecureFlow 플랫폼을 로컬에서 띄우는 가장 빠른 방법을 설명합니다.

## 사전 준비

- Docker / Docker Compose
- Python 3.11 이상
- Node.js 20 이상
- `.env` 파일

## 로컬에서 기본적으로 뜨는 것

루트 `docker-compose.yml`은 주로 SecureFlow 플랫폼 쪽을 띄웁니다.

- PostgreSQL
- Redis
- backend
- worker
- frontend
- SonarQube

즉, `app/*` 샘플 대상 앱 전체를 compose로 띄우는 구조는 아닙니다.

## 빠른 시작

### 1. 환경 파일 준비

```bash
cp .env.example .env
```

### 2. 컨테이너 실행

```bash
docker compose up --build -d
```

또는:

```bash
make up
```

### 3. 마이그레이션 / 초기화

```bash
make migrate
make seed
```

## 로컬 접속 주소

- Dashboard frontend: `http://localhost:3000`
- Backend API docs: `http://localhost:8000/docs`
- Backend API base: `http://localhost:8000/api/v1`
- SonarQube: `http://localhost:9000`

## 자주 쓰는 명령어

```bash
make logs
make test
make migrate
make seed
docker compose down
```

## 샘플 대상 앱은 어떻게 보나

`app/*` 아래 샘플 앱들은 별도로 실행하거나, GitHub Actions CI/CD에서 검사/배포 대상으로 보는 편이 현재 구조와 더 맞습니다.

예:

- `app/api-server-fastapi`
- `app/api-server-node`
- `app/api-server-spring`
- `app/frontend`
