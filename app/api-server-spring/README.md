# ShopEasy API Server (Spring Boot)

이 디렉터리는 SecureFlow 파이프라인에서 사용하는 Spring Boot 기반 대상 애플리케이션입니다.
전자상거래 API를 Java 17 / Spring Boot 3 환경으로 구현했으며, 대상 앱 3종 중 Java 계열 예제로 사용됩니다.

## 역할

- Java / Spring 대상 서비스 예제
- CI에서 Spring 빌드 및 보안 검사 대상
- staging / production ECS 배포 대상
- 프론트엔드 라우팅 분산 구조의 일부

## 기술 스택

- Spring Boot 3.2
- Java 17
- JDBC
- H2 또는 MySQL
- Redis
- AWS SDK v2
- JWT

## 디렉터리 구조

```text
app/api-server-spring/
|-- src/main/java/com/shopeasy/api/
|   |-- config/
|   |-- controller/
|   |-- dto/
|   |-- security/
|   `-- service/
|-- src/main/resources/
|   |-- application.yml
|   |-- application-local.yml
|   `-- application-prod.yml.example
|-- data/
|-- uploads/
|-- pom.xml
`-- Dockerfile
```

## 로컬 실행

### 기본 실행

```bash
./mvnw spring-boot:run
```

### 패키징 후 실행

```bash
./mvnw clean package -DskipTests
java -jar target/api-server-spring-1.0.0.jar
```

기본 주소:

- API: `http://localhost:8080`

## 설정 파일

### 공통

- `src/main/resources/application.yml`
  - 기본 포트
  - 공통 API base path
  - 업로드 기본 경로

### 로컬 개발

- `src/main/resources/application-local.yml`
  - H2 파일 DB
  - local 스토리지
  - memory 캐시
  - sync 큐

### 운영 예시

- `src/main/resources/application-prod.yml.example`
  - MySQL / S3 / DynamoDB / Redis / SQS / SNS 예시

운영 프로필을 직접 테스트하려면 예시 파일을 복사해 별도 구성한 뒤 실행하면 됩니다.

```bash
cp src/main/resources/application-prod.yml.example src/main/resources/application-prod.yml
./mvnw spring-boot:run -Dspring-boot.run.profiles=prod
```

## 주요 API

컨트롤러 구현은 `src/main/java/com/shopeasy/api/controller/` 아래에 있습니다.

- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/products`
- `GET /api/products/{id}`
- `GET /api/products/{productId}/reviews`
- `POST /api/products/{productId}/reviews`
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

## SecureFlow와의 관계

이 서비스는 `app/*` 아래 대상 애플리케이션 중 하나이며, 루트 `backend`의 SecureFlow 플랫폼 API와는 별개입니다.

프론트엔드 개발 프록시 기준으로는 주로 아래 요청을 담당합니다.

- 상품 목록 / 상품 상세

실제 프록시 분산 규칙은 [app/frontend/vite.config.js](c:/Users/User/Desktop/secureflow/secureflow/app/frontend/vite.config.js) 에 있습니다.
