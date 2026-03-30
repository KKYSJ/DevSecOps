# ShopEasy API Server (FastAPI)

이 디렉터리는 SecureFlow 파이프라인에서 사용하는 FastAPI 기반 대상 애플리케이션입니다.
인증, 상품, 리뷰, 장바구니, 주문, 업로드 API를 제공하며, DAST/SAST 실험용 취약 예제 파일도 함께 포함합니다.

## 역할

- Python/FastAPI 대상 서비스 예제
- CI에서 FastAPI 보안 검사 대상
- staging / production ECS 배포 대상
- 프론트엔드와 연동되는 실제 샘플 API

## 기술 스택

- FastAPI
- Uvicorn
- SQLite 또는 MySQL
- 로컬 파일 업로드 또는 S3
- DynamoDB 기반 리뷰 저장소 옵션
- Redis / SQS / SNS 연동 옵션

## 디렉터리 구조

```text
app/api-server-fastapi/
|-- app/
|   |-- config/
|   |-- middleware/
|   |-- models/
|   |-- routes/
|   `-- services/
|-- tests/
|-- uploads/
|-- main.py
|-- seed.py
|-- vulnerable_example.py
`-- vulnerable_endpoints.py
```

## 로컬 실행

### 1. 의존성 설치

```bash
pip install -r requirements.txt
```

### 2. 환경 변수 파일 준비

```bash
cp .env.example .env
```

### 3. 시드 데이터 생성

```bash
python seed.py
```

### 4. 서버 실행

```bash
python main.py
```

기본 주소:

- API: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/docs`
- 업로드 파일: `http://localhost:8000/uploads/...`

## 주요 환경 변수

`app/config/settings.py` 기준으로 아래 값을 사용합니다.

- `PORT`
- `DB_TYPE`
- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`
- `STORAGE_TYPE`
- `S3_BUCKET`
- `S3_REGION`
- `REVIEW_STORE`
- `DYNAMODB_TABLE`
- `DYNAMODB_REGION`
- `CACHE_TYPE`
- `REDIS_HOST`
- `REDIS_PORT`
- `QUEUE_TYPE`
- `SQS_QUEUE_URL`
- `SNS_TOPIC_ARN`
- `JWT_SECRET`

기본 개발 모드는 다음 조합입니다.

- DB: SQLite
- 스토리지: local
- 리뷰 저장소: local
- 캐시: memory
- 큐: sync

## 주요 API

실제 라우트는 `app/routes/` 아래에 있습니다.

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/products`
- `GET /api/products/{id}`
- `GET /api/products/{id}/reviews`
- `POST /api/products/{id}/reviews`
- `GET /api/cart`
- `POST /api/cart`
- `PUT /api/cart/{itemId}`
- `DELETE /api/cart/{itemId}`
- `DELETE /api/cart`
- `POST /api/orders`
- `GET /api/orders`
- `POST /api/upload`
- `POST /api/upload/presigned`
- `GET /api/health`
- `GET /api/config`

## 테스트

```bash
pytest
```

현재 저장소에는 기본 헬스체크 테스트가 포함되어 있습니다.

## SecureFlow와의 관계

이 서비스는 `app/*` 아래 대상 애플리케이션 중 하나입니다.
SecureFlow 플랫폼 자체는 루트 `backend`, `frontend`, `engine` 디렉터리에 있으며, 이 FastAPI 서비스와는 별도입니다.

참고:

- 플랫폼 API 문서: `docs/api/README.md`
- 전체 구조: `README.md`
