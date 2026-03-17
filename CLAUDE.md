# SecureFlow — Claude Code 컨텍스트

SecureFlow는 7개 보안 도구의 결과를 Gemini LLM으로 교차 검증하여
배포 게이트를 자동 결정하는 DevSecOps 플랫폼이다.

---

## 프로젝트 구조

```
DevSecOps/
├── backend/          FastAPI REST API + Celery worker
├── engine/           분석 엔진 (매칭, LLM, 스코어링, 리포터)
├── frontend/         React 대시보드
├── ismsp/            ISMS-P AWS 점검 모듈
└── docker-compose.yml
```

---

## 스캔 도구 목록

| 도구 | 카테고리 | 설명 |
|------|----------|------|
| sonarqube | SAST | 정적 코드 분석 |
| semgrep | SAST | 패턴 기반 정적 분석 |
| trivy | SCA | 컨테이너/파일시스템 취약점 |
| depcheck | SCA | 의존성 CVE 탐지 |
| tfsec | IaC | Terraform 정적 분석 |
| checkov | IaC | IaC 보안 정책 검사 |
| zap | DAST | 동적 웹 애플리케이션 테스트 |

---

## 스코어링 공식

```
row_score = severity_score × judgement_weight × confidence_weight

severity:    CRITICAL=100  HIGH=40  MEDIUM=15  LOW=5  INFO=1
judgement:   TRUE_POSITIVE=×1.0  REVIEW_NEEDED=×0.6  FALSE_POSITIVE=×0.0
confidence:  HIGH=×1.0  MED=×0.8  LOW=×0.5
```

**게이트 결정 규칙:**
- `BLOCK`: CRITICAL TRUE_POSITIVE ≥ 1 **또는** total_score ≥ 100 **또는** HIGH TRUE_POSITIVE ≥ 3
- `REVIEW`: total_score ≥ 40
- `ALLOW`: 그 외

---

## 2-Phase 파이프라인 구조

```
Phase 1 (Docker 빌드 전)
  SAST + SCA + IaC 스캔 제출 → POST /api/v1/scans/analyze?phase=1
  → BLOCK: 파이프라인 중단 (pipeline.status = 'blocked')
  → ALLOW/REVIEW: Docker 빌드 진행 (pipeline.status = 'scanning_phase2')

Phase 2 (Docker 빌드 후)
  DAST 스캔 제출 → POST /api/v1/scans/analyze?phase=2
  → Phase 1 결과 재사용 + DAST 신규 분석 합산
  → 최종 게이트 결정 (pipeline.status = 'completed' or 'blocked')
```

**Pipeline 상태 전이:**
`scanning_phase1` → `scanning_phase2` → `completed` | `blocked`

---

## LLM 연동

- **Gemini만 사용** (GEMINI_API_KEY만 설정됨, OPENAI_API_KEY 없음)
- `engine/llm/client.py` → `call_llm(prompt)` 진입점
- `engine/llm/prompts.py` → `build_cross_validation_prompt()` + `parse_llm_response()`
- LLM 실패 시 `scan_service._rule_based_analyze()` 로 폴백

---

## DB 스키마

### `scans`
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| tool | VARCHAR(50) | sonarqube \| semgrep \| trivy \| depcheck \| tfsec \| checkov \| zap |
| category | VARCHAR(20) | SAST \| SCA \| IaC \| DAST |
| project_name | VARCHAR(255) | 기본값 secureflow |
| commit_hash | VARCHAR(64) | 파이프라인 묶음 키 (필수) |
| raw_result | JSONB | 원시 스캔 결과 |
| status | VARCHAR(50) | received → processing → done \| failed |
| created_at | TIMESTAMPTZ | |

### `vulnerabilities`
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| scan_id | INTEGER FK→scans | SET NULL on delete |
| tool | VARCHAR(50) | |
| category | VARCHAR(20) | |
| severity | VARCHAR(32) | CRITICAL \| HIGH \| MEDIUM \| LOW |
| title | VARCHAR(255) | |
| file_path | VARCHAR(500) | |
| line_number | INTEGER | |
| cwe_id | VARCHAR(50) | |
| cve_id | VARCHAR(50) | |
| confidence | VARCHAR(32) | HIGH \| MED \| LOW |
| description | TEXT | |
| status | VARCHAR(32) | OPEN \| RESOLVED \| IGNORED |
| created_at | TIMESTAMPTZ | |

### `pipeline_runs`
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| project_name | VARCHAR(255) | |
| commit_hash | VARCHAR(64) INDEX | 동일 커밋 스캔 묶음 키 |
| branch | VARCHAR(100) | 기본값 main |
| status | VARCHAR(50) | scanning_phase1 → scanning_phase2 → completed \| blocked |
| gate_result | VARCHAR(20) | BLOCK \| REVIEW \| ALLOW |
| gate_score | FLOAT | |
| scan_ids | JSONB | 연결된 scan id 배열 |
| created_at | TIMESTAMPTZ | |

### `cross_validations`
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| project_name | VARCHAR(255) | |
| commit_hash | VARCHAR(64) INDEX | |
| phase | INTEGER | 1 (SAST/SCA/IaC) \| 2 (최종) |
| category | VARCHAR(20) | |
| tool_a | VARCHAR(50) | |
| tool_b | VARCHAR(50) | |
| judgement_code | VARCHAR(50) | TRUE_POSITIVE \| REVIEW_NEEDED \| FALSE_POSITIVE |
| confidence | VARCHAR(20) | |
| severity | VARCHAR(32) | |
| llm_summary | TEXT | Gemini 분석 요약 |
| gate_result | VARCHAR(20) | BLOCK \| REVIEW \| ALLOW |
| gate_score | FLOAT | |
| raw_report | JSONB | 전체 리포트 JSON (findings 배열 포함, Phase 2에서 재사용) |
| created_at | TIMESTAMPTZ | |

### `tool_results`
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| name | VARCHAR(255) | 도구명 또는 'report' |
| status | VARCHAR(50) | ok \| error |
| data | JSONB | 파싱 결과 또는 리포트 JSON |

> name='report' 레코드가 GET /api/v1/cross 의 소스로 사용됨
> POST /api/v1/scans/analyze 호출 시 자동 저장됨

### `isms_checks`
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| name | VARCHAR(255) | isms-check-{region} |
| status | VARCHAR(50) | completed \| error |
| data | JSONB | ISMS-P 점검 결과 JSON |

### `siem_events`
| 컬럼 | 타입 | 설명 |
|------|------|------|
| id | INTEGER PK | |
| name | VARCHAR(255) | summary 또는 이벤트 타입 |
| status | VARCHAR(50) | |
| data | JSONB | 이벤트 데이터 |

---

## API 명세 요약

**Base URL:** `http://localhost:8000`
**API Prefix:** `/api/v1`
**Swagger UI:** `http://localhost:8000/docs`

### Health
| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /health | 서버 상태 확인 |

---

### 스캔 — `/api/v1/scans`

| 메서드 | 경로 | 설명 |
|--------|------|------|
| POST | /api/v1/scans | 스캔 결과 제출 |
| GET | /api/v1/scans | 스캔 목록 (limit=50) |
| GET | /api/v1/scans/{scan_id} | 스캔 상세 + findings |
| POST | /api/v1/scans/analyze | LLM 교차검증 + 게이트 결정 |

**POST /api/v1/scans 요청 바디:**
```json
{
  "tool": "semgrep",
  "raw_result": { ... },
  "commit_hash": "abc1234",
  "project_name": "secureflow",
  "branch": "main"
}
```
- commit_hash 필수 — PipelineRun 생성/업데이트 키
- 제출 즉시 Celery 태스크로 파싱 (Redis 없으면 동기 처리)
- 파서 호출 경로: scan_worker → scan_service.process_tool_result() → PARSERS[tool].parse(raw)

**POST /api/v1/scans/analyze 요청 바디:**
```json
{
  "commit_hash": "abc1234",
  "phase": 1
}
```
| phase | 분석 대상 | Pipeline 상태 |
|-------|-----------|--------------|
| 1 | SAST + SCA + IaC | BLOCK→blocked, 통과→scanning_phase2 |
| 2 (기본값) | Phase1 재사용 + DAST | completed or blocked |

---

### 취약점 — `/api/v1/vulns`

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/v1/vulns | 취약점 목록 (severity/tool/category/limit/offset 필터) |

---

### 교차검증 — `/api/v1/cross`

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/v1/cross | 최신 교차검증 대시보드 |
| GET | /api/v1/cross/history | 교차검증 이력 (최근 20개) |

---

### 파이프라인 — `/api/v1/pipelines`

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/v1/pipelines | 파이프라인 이력 (최근 50개) |
| GET | /api/v1/pipelines/{pipeline_id} | 파이프라인 상세 |

---

### 보안 도구 — `/api/v1/tools`

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/v1/tools | 7개 도구 메타데이터 목록 |
| GET | /api/v1/tools/{tool_name}/findings | 도구별 최신 발견사항 |

---

### 리포트 — `/api/v1/reports`

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/v1/reports | 리포트 목록 |
| GET | /api/v1/reports/{report_id} | 리포트 상세 |
| GET | /api/v1/reports/{report_id}/download | 리포트 JSON 다운로드 |

---

### ISMS-P — `/api/v1/isms`

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/v1/isms | 최신 ISMS-P 점검 결과 |
| POST | /api/v1/isms/run | ISMS-P 점검 실행 (region 파라미터) |

> AWS 자격증명(AWS_ACCESS_KEY_ID 또는 AWS_ROLE_ARN) 없으면 status: "skipped"

---

### SIEM — `/api/v1/siem`

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/v1/siem | SIEM 이벤트 요약 |
| GET | /api/v1/siem/events | 이벤트 목록 (severity/source/limit 필터) |

---

## CI/CD 연동 흐름

```bash
# Phase 1 — Docker 빌드 전
POST /api/v1/scans  {"tool":"sonarqube", "commit_hash":"abc1234", "raw_result":{...}}
POST /api/v1/scans  {"tool":"semgrep",   "commit_hash":"abc1234", "raw_result":{...}}
POST /api/v1/scans  {"tool":"trivy",     "commit_hash":"abc1234", "raw_result":{...}}
POST /api/v1/scans  {"tool":"depcheck",  "commit_hash":"abc1234", "raw_result":{...}}
POST /api/v1/scans  {"tool":"tfsec",     "commit_hash":"abc1234", "raw_result":{...}}
POST /api/v1/scans  {"tool":"checkov",   "commit_hash":"abc1234", "raw_result":{...}}
POST /api/v1/scans/analyze  {"commit_hash":"abc1234", "phase":1}
# → BLOCK: 중단 / ALLOW or REVIEW: Docker 빌드 진행

# Phase 2 — Docker 빌드 후
POST /api/v1/scans  {"tool":"zap", "commit_hash":"abc1234", "raw_result":{...}}
POST /api/v1/scans/analyze  {"commit_hash":"abc1234", "phase":2}
# → BLOCK: 배포 중단 / ALLOW or REVIEW: 배포 진행
```

---

## 파서 구조

**백엔드는 `engine/normalizer/parsers/`를 직접 호출한다.**
- 위치: `engine/normalizer/parsers/` (sonarqube, semgrep, trivy, depcheck, tfsec, checkov, zap)
- 인터페이스: `parse(raw_dict) → dict` (함수 기반)
- `scan_service.py`의 `_Adapter` 클래스가 `.parse()` 메서드로 래핑

**호출 경로:**
```
POST /api/v1/scans
  → scan_worker._process_scan_sync(scan_id)
  → scan_service.process_tool_result(tool, raw)
  → PARSERS[tool].parse(raw)
    → engine.normalizer.parsers.{tool}.parse(raw)
```

**`backend/app/services/parsers/`** — 구 구현, 현재 미사용 (참고용으로 유지)
