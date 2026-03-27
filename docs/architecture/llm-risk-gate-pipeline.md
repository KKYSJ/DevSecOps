# LLM Risk Gate Pipeline

이 문서는 현재 저장소에서 실제로 사용 중인 LLM gate 구조를 설명합니다.

## 기본 원칙

SecureFlow는 한 영역에 대해 가능한 경우 2개 도구를 함께 실행하고, 그 결과를 LLM gate로 교차검증하는 방향을 사용합니다.

즉 구조는 대략 아래와 같습니다.

```text
도구 A 실행
도구 B 실행
-> 결과 수집
-> LLM gate 생성
-> raw 결과 업로드
-> gate 결과 업로드
-> 대시보드 report 생성
```

## 현재 영역별 구성

### IaC

- Checkov
- tfsec
- `llm-iac-gate`

### SAST

- Semgrep
- SonarQube
- `llm-sast-gate`

### SCA

- Trivy
- OWASP Dependency-Check
- `llm-sca-gate`

### Image

- Trivy image scan
- Grype
- `llm-image-gate`

### DAST

- ZAP
- Nuclei
- `llm-dast-gate`

## 현재 스크립트

`scripts/ci/` 아래 스크립트가 핵심입니다.

- `run_llm_gate.py`
  - 영역별 gate 결과 생성
- `run_llm_judgments.py`
  - 개별 취약점 수준 judgments 업로드
- `run_overall_verdict.py`
  - 종합 verdict 보조
- `run_ismsp_gate.py`
  - ISMS-P 보조 게이트

## 백엔드 업로드 구조

현재 파이프라인은 아래 두 종류를 모두 백엔드로 보냅니다.

### 1. raw 결과

- `POST /api/v1/scans`

예:

- `semgrep`
- `sonarqube`
- `trivy`
- `depcheck`
- `tfsec`
- `checkov`
- `trivy-image`
- `grype`
- `zap`
- `nuclei`

### 2. gate 결과

- `POST /api/v1/scans/gate-result`

stage 예:

- `iac`
- `sast`
- `sca`
- `image`
- `dast`

### 3. judgments

`run_llm_judgments.py`는 stage별 judgments / summaries를 업로드합니다.

## 현재 백엔드와의 연결

현재 백엔드 구조에서는 대시보드에 report가 보이려면 `/api/v1/scans/analyze`가 필요합니다.

그래서 현재 워크플로는:

- 업로드
- 짧은 대기
- `phase 1` 또는 `phase 2` analyze 호출

까지 수행해 대시보드용 report를 생성합니다.

## 운영 시 주의할 점

- gate는 CI/CD 상의 의사결정에 사용됩니다.
- dashboard report는 백엔드가 따로 생성합니다.
- 업로드 URL은 `API_SERVER_URL`을 사용합니다.
- WAF가 있을 경우 `X-SecureFlow-Upload-Key` 헤더가 필요합니다.

## 대표 URL 기반 DAST

현재 DAST는 서비스별 전체 순회가 아니라 대표 URL 1개를 기준으로 수행합니다.
따라서 LLM DAST gate 품질을 유지하려면 대표 URL을 실제 ingress와 맞추는 것이 중요합니다.

권장값:

- CloudFront URL
- ALB URL

비권장값:

- 특정 EC2 퍼블릭 IP
- 내부 컨테이너 포트
