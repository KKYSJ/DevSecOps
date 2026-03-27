# API 문서 개요

SecureFlow 백엔드는 FastAPI로 동작하며, 기본 API prefix는 `/api/v1` 입니다.

## 기본 주소

- 로컬 API base: `http://localhost:8000/api/v1`
- 로컬 Swagger UI: `http://localhost:8000/docs`
- 배포 환경 API base: GitHub Secret `API_SERVER_URL` 값 사용

## 주요 엔드포인트

### 시스템

- `GET /`
  - API 루트 확인
- `GET /health`
  - 헬스체크

### 스캔

- `POST /api/v1/scans`
  - raw 스캔 결과 업로드
- `GET /api/v1/scans`
  - 최근 스캔 목록 조회
- `GET /api/v1/scans/{scan_id}`
  - 특정 스캔 상세 조회
- `POST /api/v1/scans/analyze`
  - 대시보드용 report / cross-validation 데이터 생성
- `POST /api/v1/scans/gate-result`
  - LLM gate 결과 저장

### 취약점

- `GET /api/v1/vulns`
  - 취약점 목록 조회
  - `severity`, `tool`, `category`, `commit_hash`, `limit`, `offset` 필터 지원

### 교차검증 / 대시보드

- `GET /api/v1/cross`
  - 최신 대시보드 report 조회
- `GET /api/v1/cross/history`
  - report 히스토리 조회
- `GET /api/v1/cross/gates`
  - commit 기준 gate / judgments 요약 조회

### 도구 메타데이터

- `GET /api/v1/tools`
  - 통합 보안 도구 목록 조회
- `GET /api/v1/tools/{tool_name}/findings`
  - 특정 도구 최신 결과 조회

### 리포트

- `GET /api/v1/reports`
  - 저장된 report 목록 조회
- `GET /api/v1/reports/{report_id}`
  - 특정 report 조회
- `GET /api/v1/reports/{report_id}/download`
  - report JSON 다운로드

### 파이프라인

- `GET /api/v1/pipelines`
  - 파이프라인 실행 목록 조회
- `GET /api/v1/pipelines/{pipeline_id}`
  - 파이프라인 상세 조회

### ISMS-P

- `GET /api/v1/isms`
  - 최신 ISMS-P 결과 조회
- `POST /api/v1/isms`
  - ISMS-P 결과 저장
- `POST /api/v1/isms/run`
  - 서버 환경에서 ISMS-P 점검 실행

### SIEM

- `GET /api/v1/siem`
- `GET /api/v1/siem/events`

## 레거시 경로

아래 라우터도 현재 코드에 포함되어 있습니다.

- `/api/v1/scan-results/*`
- `/api/v1/crosscheck/*`

이 경로들은 레거시 또는 보조 흐름 성격이 있으므로, 신규 연동은 `scans`, `cross`, `reports`, `pipelines` 계열을 우선 사용하는 것을 권장합니다.

## 소스 기준점

- 라우터 등록: `backend/app/api/router.py`
- 스캔 업로드/분석: `backend/app/api/endpoints/scans.py`
- 대시보드 조회: `backend/app/api/endpoints/cross_validation.py`
- 리포트 조회: `backend/app/api/endpoints/reports.py`
