# ShopEasy Frontend

이 디렉터리는 대상 애플리케이션용 React 프론트엔드입니다.
루트 `frontend/`의 SecureFlow 대시보드와는 다른 앱이며, `app/api-server-fastapi`, `app/api-server-node`, `app/api-server-spring` 세 API를 프록시로 분산해 사용하는 구조입니다.

## 역할

- 대상 서비스용 사용자 프론트엔드
- CI 빌드 및 배포 대상
- dev/staging/prod ECS frontend 컨테이너

## 기술 스택

- React 18
- Vite 5
- React Router 6
- Axios

## 로컬 실행

### 1. 패키지 설치

```bash
npm install
```

### 2. 개발 서버 실행

```bash
npm run dev
```

기본 주소:

- 프론트엔드: `http://localhost:3000`

### 3. 프로덕션 빌드

```bash
npm run build
```

## API 연결 방식

이 앱은 `VITE_API_URL`이 비어 있으면 Vite 개발 프록시를 사용합니다.
프록시 규칙은 [app/frontend/vite.config.js](c:/Users/User/Desktop/secureflow/secureflow/app/frontend/vite.config.js) 에 정의되어 있습니다.

현재 기준 분산 규칙:

- 인증 / 장바구니 / 주문: Node (`http://localhost:5000`)
- 리뷰 / 업로드 / `/uploads`: FastAPI (`http://localhost:8000`)
- 상품 관련: Spring (`http://localhost:8080`)

즉 프론트엔드 1개가 API 3개를 기능별로 나눠 호출하는 구조입니다.

## 환경 변수

- `VITE_API_URL`

권장 사용 방식:

- 로컬 개발: 비워 두고 프록시 사용
- 정적 배포 또는 별도 ingress 환경: 실제 외부 API base URL 지정

예시:

```env
VITE_API_URL=https://example-alb-or-cloudfront-domain
```

## 주요 화면

`src/pages/` 아래에 주요 화면이 있습니다.

- 홈
- 로그인
- 회원가입
- 상품 목록 / 상세
- 장바구니
- 주문 내역

## SecureFlow와의 관계

이 앱은 SecureFlow가 스캔하고 배포하는 대상 앱입니다.
SecureFlow 자체 대시보드는 루트 [frontend](c:/Users/User/Desktop/secureflow/secureflow/frontend) 에 있습니다.
