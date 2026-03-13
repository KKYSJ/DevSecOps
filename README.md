# SecureFlow

SecureFlow는 정적/동적/IaC/의존성 보안 스캔 결과를 수집·정규화·교차 검증하고,
대시보드와 리포트, ISMS-P 매핑 결과를 제공하는 DevSecOps 플랫폼입니다.

## 빠른 시작
```bash
cp .env.example .env
make up
```

- Backend: http://localhost:8000/docs
- Frontend: http://localhost:3000
- SonarQube: http://localhost:9000

## 개발 명령어
```bash
make up
make down
make logs
make test
make scan
```
