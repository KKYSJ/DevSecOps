# SecureFlow

**SecureFlow**는 7개 보안 도구의 스캔 결과를 수집·정규화·교차 검증하고,
Gemini LLM으로 판정하여 CI/CD 배포 게이트를 자동 결정하는 DevSecOps 플랫폼입니다.

---

## 목차

- [아키텍처](#아키텍처)
- [기술 스택](#기술-스택)
- [모듈 구조](#모듈-구조)
- [데이터 흐름](#데이터-흐름)
- [빠른 시작](#빠른-시작)
- [API 명세](#api-명세)
- [DB 스키마](#db-스키마)
- [스코어링 공식](#스코어링-공식)
- [CI/CD 연동](#cicd-연동)
- [환경 변수](#환경-변수)

---

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                        CI/CD Pipeline                           │
│                                                                 │
│  semgrep  sonarqube  trivy  depcheck  tfsec  checkov   zap     │
│     │         │        │       │        │       │        │      │
│     └─────────┴────────┴───────┴────────┴───────┴────────┘     │
│                              │                                  │
│                 POST /api/v1/scans (raw JSON)                   │
└──────────────────────────────┼──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                      Backend (FastAPI)                          │
│                                                                 │
│  Celery Worker ──▶ engine/normalizer/parsers/ ──▶ Vulnerability │
│                                                                 │
│  POST /analyze ──▶ match_findings()                            │
│                ──▶ Gemini LLM (engine/llm/)                    │
│                ──▶ score_findings()                            │
│                ──▶ BLOCK / REVIEW / ALLOW                      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
     ┌────────▼────────┐               ┌────────▼────────┐
     │  PostgreSQL DB  │               │  React Frontend │
     │                 │               │  localhost:3000  │
     │  scans          │               │                 │
     │  vulnerabilities│               │  대시보드        │
     │  pipeline_runs  │               │  교차검증 결과   │
     │  cross_valid... │               │  파이프라인 이력 │
     └─────────────────┘               └─────────────────┘
```

### 2-Phase 배포 게이트

```
Phase 1 (Docker 빌드 전)           Phase 2 (Docker 빌드 후)
─────────────────────────          ─────────────────────────
SAST + SCA + IaC 스캔              DAST (ZAP) 스캔
      ↓                                    ↓
POST /analyze { phase: 1 }         POST /analyze { phase: 2 }
      ↓                                    ↓
BLOCK → 파이프라인 중단             BLOCK → 배포 중단
ALLOW/REVIEW → Docker 빌드 진행    ALLOW/REVIEW → 배포 진행
```

---

## 기술 스택

| 영역 | 기술 |
|------|------|
| Backend | FastAPI, SQLAlchemy 2.0, Pydantic v2 |
| Database | PostgreSQL (JSONB), SQLite (로컬) |
| Task Queue | Celery + Redis |
| LLM | Google Gemini 2.5 Flash |
| Frontend | React 18, Recharts, Axios |
| Container | Docker, Docker Compose |
| CI/CD | GitHub Actions |
| IaC | Terraform |
| ISMS-P | boto3 (AWS SDK) |

---

## 모듈 구조

```
DevSecOps/
├── backend/                    FastAPI REST API 서버
│   └── app/
│       ├── main.py             앱 진입점, DB 마이그레이션
│       ├── core/               DB, Celery, Security 설정
│       ├── models/             SQLAlchemy 모델 (7개 테이블)
│       ├── api/endpoints/      REST 엔드포인트 (8개)
│       ├── services/           비즈니스 로직 (scan_service, report_service)
│       └── workers/            Celery 태스크 (scan_worker)
│
├── engine/                     분석 엔진 (독립 실행 가능)
│   ├── main.py                 파이프라인 전체 실행
│   ├── normalizer/parsers/     도구별 파서 7개 (공통 포맷 변환)
│   ├── matcher/                도구 쌍 매칭 (CWE, file/line 기반)
│   ├── scorer/                 점수 계산 + 게이트 결정
│   ├── llm/                    Gemini / GPT 호출 + 프롬프트
│   ├── reporter/               JSON / PDF 리포트 생성
│   └── integrity/              SHA256 파일 무결성 검증
│
├── frontend/                   React 대시보드
│   └── src/
│       ├── pages/              8개 페이지
│       └── components/         공통 UI 컴포넌트
│
├── ismsp/                      ISMS-P AWS 자동 점검
│   ├── checker/                AWS 데이터 수집 + 38개 항목 평가
│   ├── mappings/               ISMS-P 기술통제 항목 정의
│   └── reporter/               JSON / PDF 보고서
│
└── .github/workflows/          GitHub Actions CI/CD
```

---

## 통합 도구

| 도구 | 카테고리 | 역할 | 교차검증 쌍 |
|------|----------|------|------------|
| SonarQube | SAST | 정적 코드 분석 | ↔ Semgrep |
| Semgrep | SAST | 패턴 기반 정적 분석 | ↔ SonarQube |
| Trivy | SCA | 컨테이너/의존성 취약점 | ↔ Dependency-Check |
| Dependency-Check | SCA | OWASP 의존성 CVE 점검 | ↔ Trivy |
| tfsec | IaC | Terraform 보안 검사 | ↔ Checkov |
| Checkov | IaC | 다중 IaC 보안 정책 검사 | ↔ tfsec |
| OWASP ZAP | DAST | 동적 웹 애플리케이션 스캔 | (단독) |

---

## 데이터 흐름

### 1. 스캔 결과 제출

```
POST /api/v1/scans
{
  "tool": "semgrep",
  "raw_result": { ...도구 원시 JSON... },
  "commit_hash": "abc1234",   ← 필수, 파이프라인 묶음 키
  "project_name": "myapp",
  "branch": "main"
}
```

### 2. 내부 처리 흐름

```
Scan 모델 생성 (status=received)
PipelineRun upsert (commit_hash 기준)
       ↓
Celery Worker 비동기 처리
(Redis 없으면 동기 폴백)
       ↓
engine.normalizer.parsers.{tool}.parse(raw)
       ↓
Vulnerability 행 저장
ToolResult 저장 (교차검증 엔진이 여기서 읽음)
```

### 3. 교차검증 + 게이트 결정

```
POST /api/v1/scans/analyze { "commit_hash": "abc1234", "phase": 1 }

match_findings()
  SAST: sonarqube ↔ semgrep  (동일 CWE ID 또는 동일 file + ±5 라인)
  SCA:  trivy ↔ depcheck     (동일 CVE ID 또는 동일 패키지+버전)
  IaC:  tfsec ↔ checkov     (동일 file + ±10 라인)
       ↓
Gemini LLM 판정
  → TRUE_POSITIVE / REVIEW_NEEDED / FALSE_POSITIVE
       ↓
score_findings()
  row_score = severity × judgement_weight × confidence_weight
       ↓
get_gate_decision() → BLOCK / REVIEW / ALLOW
```

---

## 빠른 시작

### 사전 요구사항

- Docker + Docker Compose
- `GEMINI_API_KEY` (Gemini LLM 교차검증용)

### 실행

```bash
# 1. 환경 변수 설정
cp .env.example .env
# .env 파일에 GEMINI_API_KEY 입력

# 2. 컨테이너 실행
docker compose up -d

# 3. 접속
# Frontend:   http://localhost:3000
# Backend:    http://localhost:8000/docs
# SonarQube:  http://localhost:9000
```

### 개발 명령어

```bash
# 전체 실행
docker compose up -d

# 로그 확인
docker compose logs -f backend
docker compose logs -f worker

# 재시작 (환경 변수 반영)
docker compose up -d --force-recreate backend worker

# 종료
docker compose down
```

---

## API 명세

Base URL: `http://localhost:8000/api/v1`
Swagger UI: `http://localhost:8000/docs`

### 스캔

| 메서드 | 경로 | 설명 |
|--------|------|------|
| `POST` | `/scans` | 스캔 결과 제출 (tool, raw_result, commit_hash 필수) |
| `GET` | `/scans` | 스캔 목록 조회 |
| `GET` | `/scans/{scan_id}` | 스캔 상세 + findings |
| `POST` | `/scans/analyze` | LLM 교차검증 + 게이트 결정 |

**POST /scans/analyze 파라미터:**

| 파라미터 | 타입 | 설명 |
|---------|------|------|
| `commit_hash` | string | 분석 대상 커밋 (없으면 최신) |
| `phase` | int | `1` = SAST/SCA/IaC만, `2` = 전체 (기본값) |

### 취약점

| 메서드 | 경로 | 설명 |
|--------|------|------|
| `GET` | `/vulns` | 취약점 목록 (severity/tool/category/limit/offset 필터) |

### 교차검증

| 메서드 | 경로 | 설명 |
|--------|------|------|
| `GET` | `/cross` | 최신 교차검증 대시보드 |
| `GET` | `/cross/history` | 교차검증 이력 |

### 파이프라인

| 메서드 | 경로 | 설명 |
|--------|------|------|
| `GET` | `/pipelines` | 파이프라인 이력 |
| `GET` | `/pipelines/{id}` | 파이프라인 상세 |

### 도구 / 리포트 / ISMS-P / SIEM

| 메서드 | 경로 | 설명 |
|--------|------|------|
| `GET` | `/tools` | 7개 도구 메타데이터 |
| `GET` | `/tools/{name}/findings` | 도구별 최신 발견사항 |
| `GET` | `/reports` | 리포트 목록 |
| `GET` | `/reports/{id}/download` | 리포트 JSON 다운로드 |
| `GET` | `/isms` | ISMS-P 점검 결과 |
| `POST` | `/isms/run` | ISMS-P 점검 실행 (AWS 자격증명 필요) |
| `GET` | `/siem` | SIEM 이벤트 요약 |
| `GET` | `/siem/events` | SIEM 이벤트 목록 |

---

## DB 스키마

### 테이블 목록

| 테이블 | 설명 |
|--------|------|
| `scans` | 제출된 스캔 (tool, commit_hash, raw_result, status) |
| `vulnerabilities` | 파싱된 취약점 (scan_id FK, severity, cwe_id, cve_id) |
| `pipeline_runs` | 커밋별 파이프라인 (commit_hash INDEX, status, gate_result) |
| `cross_validations` | 교차검증 결과 (commit_hash, phase, judgement_code, raw_report) |
| `tool_results` | 파싱 결과 캐시 (name=도구명 또는 'report') |
| `isms_checks` | ISMS-P 점검 결과 |
| `siem_events` | SIEM 이벤트 |

### pipeline_runs 상태 전이

```
scanning_phase1 → scanning_phase2 → completed
                                  → blocked
```

---

## 스코어링 공식

```
row_score = severity_score × judgement_weight × confidence_weight

severity_score:    CRITICAL=100  HIGH=40  MEDIUM=15  LOW=5
judgement_weight:  TRUE_POSITIVE=×1.0  REVIEW_NEEDED=×0.6  FALSE_POSITIVE=×0.0
confidence_weight: HIGH=×1.0  MED=×0.8  LOW=×0.5
```

### 게이트 결정

| 조건 | 결정 |
|------|------|
| CRITICAL TRUE_POSITIVE ≥ 1 | **BLOCK** |
| HIGH TRUE_POSITIVE ≥ 3 | **BLOCK** |
| total_score ≥ 100 | **BLOCK** |
| total_score ≥ 40 | **REVIEW** |
| total_score < 40 | **ALLOW** |

### 신뢰도 결정

| 조건 | 신뢰도 |
|------|--------|
| 두 도구 모두 탐지 | HIGH (×1.0) |
| 한 도구만 탐지 | LOW (×0.5) |

---

## CI/CD 연동

### GitHub Actions 흐름

```yaml
# .github/workflows/ci-security-scan.yml
# 병렬 스캔 후 결과를 SecureFlow Backend로 자동 제출

jobs:
  sast-semgrep:     semgrep → JSON
  sast-sonarqube:   sonarqube 분석
  sca-trivy:        trivy → JSON
  sca-depcheck:     dependency-check → JSON
  iac-tfsec:        tfsec → JSON
  iac-checkov:      checkov → JSON
  submit-results:   모든 결과 → POST /api/v1/scans
```

### GitHub Secrets 설정 필요

| Secret | 설명 |
|--------|------|
| `BACKEND_URL` | SecureFlow 백엔드 URL (스캔 결과 자동 업로드용) |
| `GEMINI_API_KEY` | Gemini LLM API 키 |

---

## 환경 변수

`.env` 파일 설정:

```env
# Database
DATABASE_URL=postgresql://secureflow:secureflow@postgres:5432/secureflow

# Redis / Celery
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0

# LLM (Gemini만 사용)
GEMINI_API_KEY=your_gemini_api_key_here

# AWS (ISMS-P 점검용, 선택)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=ap-northeast-2
```

---

## ISMS-P 점검

AWS 자격증명이 설정된 환경에서:

```bash
POST /api/v1/isms/run?region=ap-northeast-2
```

- IAM, EC2, RDS, S3, CloudTrail, CloudWatch, GuardDuty 등 점검
- 38개 ISMS-P 기술통제 항목 자동 평가
- JSON / PDF 보고서 생성
- 자격증명 없으면 `status: "skipped"` 반환

---

## 프로젝트 현황

| 기능 | 상태 |
|------|------|
| 백엔드 REST API (8개 엔드포인트) | ✅ 완성 |
| engine 파서 7개 | ✅ 완성 |
| 교차검증 엔진 (매칭 + 스코어링) | ✅ 완성 |
| Gemini LLM 연동 | ✅ 완성 |
| 2-Phase 배포 게이트 | ✅ 완성 |
| React 대시보드 (8개 페이지) | ✅ 완성 |
| ISMS-P 자동 점검 | ⚠️ AWS 연결 필요 |
| SIEM 이벤트 수집 | ⚠️ AWS 연결 필요 |
| Docker → ECS 배포 | 🔧 진행 중 |
