# ShopEasy API Server (Node.js / Express)

이 디렉터리는 SecureFlow 파이프라인에서 사용하는 Express 기반 대상 애플리케이션입니다.
동일한 전자상거래 기능을 JavaScript/Node 환경으로 구현해 두었고, SecureFlow의 SAST/SCA/IMAGE/DAST 대상 중 하나로 사용됩니다.

## 역할

- Node.js / Express 대상 서비스 예제
- CI에서 Node 계열 보안 검사 대상
- staging / production ECS 배포 대상
- 프론트엔드 라우팅 분산 구조의 일부

## 기술 스택

- Node.js
- Express
- JWT 인증
- sql.js 또는 MySQL
- AWS SDK v3
- Redis / SQS / SNS 옵션

## 디렉터리 구조

```text
app/api-server-node/
|-- src/
|   |-- config/
|   |-- middleware/
|   |-- routes/
|   `-- services/
|-- uploads/
|-- seed.js
|-- src/app.js
`-- vulnerable_example.js
```

## 로컬 실행

### 1. 패키지 설치

```bash
npm install
```

### 2. 환경 변수 파일 준비

```bash
cp .env.example .env
```

### 3. 시드 데이터 생성

```bash
npm run seed
```

### 4. 서버 실행

```bash
npm start
```

개발 모드:

```bash
npm run dev
```

기본 주소:

- API: `http://localhost:5000`

## 주요 환경 변수

코드 기준으로 아래 환경 변수를 사용합니다.

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

- DB: SQLite(sql.js)
- 스토리지: local
- 리뷰 저장소: local
- 캐시: memory
- 큐: sync

## 주요 API

라우트 구현은 `src/routes/` 아래에 있습니다.

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/products`
- `GET /api/products/:id`
- `GET /api/products/:id/reviews`
- `POST /api/products/:id/reviews`
- `GET /api/cart`
- `POST /api/cart`
- `PUT /api/cart/:itemId`
- `DELETE /api/cart/:itemId`
- `DELETE /api/cart`
- `POST /api/orders`
- `GET /api/orders`
- `POST /api/upload`
- `POST /api/upload/presigned`
- `GET /api/health`
- `GET /api/config`

## SecureFlow와의 관계

이 서비스는 `app/*` 아래 대상 애플리케이션 중 하나이며, 루트 `backend`의 SecureFlow API 서버와는 다릅니다.

프론트엔드 개발 프록시 기준으로는 주로 아래 요청을 담당합니다.

- 인증
- 장바구니
- 주문

실제 프록시 분산 규칙은 [app/frontend/vite.config.js](c:/Users/User/Desktop/secureflow/secureflow/app/frontend/vite.config.js) 에 있습니다.
