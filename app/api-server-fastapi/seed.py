"""
시드 데이터 스크립트
- 테스트 사용자 및 20개 상품 데이터 삽입
- 독립 실행: python seed.py
"""

import asyncio
import sys
import os
from pathlib import Path

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, str(Path(__file__).resolve().parent))

import bcrypt
from app.config.settings import settings
from app.config.database import init_database, query, close_database


# 테스트 사용자
TEST_USER = {
    "email": "test@test.com",
    "password": "password123",
    "name": "테스트유저",
}

# 20개 상품 (5 카테고리 x 4개)
PRODUCTS = [
    # 전자기기 (Electronics)
    {
        "name": "삼성 갤럭시 S24 울트라",
        "description": "최신 AI 기능을 탑재한 프리미엄 스마트폰. 2억 화소 카메라와 티타늄 프레임으로 완성된 최고의 스마트폰입니다.",
        "price": 1698000,
        "image_url": "/images/products/product-1.jpg",
        "category": "전자기기",
        "stock": 50,
    },
    {
        "name": "LG 그램 17인치 노트북",
        "description": "초경량 17인치 노트북. 뛰어난 배터리 수명과 성능을 갖춘 업무용 노트북입니다.",
        "price": 1890000,
        "image_url": "/images/products/product-2.jpg",
        "category": "전자기기",
        "stock": 30,
    },
    {
        "name": "애플 에어팟 프로 2세대",
        "description": "능동형 소음 차단과 적응형 오디오를 지원하는 무선 이어폰입니다.",
        "price": 359000,
        "image_url": "/images/products/product-3.jpg",
        "category": "전자기기",
        "stock": 100,
    },
    {
        "name": "LG 스탠바이미 27인치",
        "description": "이동이 자유로운 무선 스탠드 모니터. 터치스크린과 배터리 내장으로 어디서든 사용 가능합니다.",
        "price": 1090000,
        "image_url": "/images/products/product-4.jpg",
        "category": "전자기기",
        "stock": 20,
    },
    # 패션 (Fashion)
    {
        "name": "나이키 에어맥스 97 화이트",
        "description": "클래식한 디자인의 나이키 에어맥스. 풀 에어 유닛으로 편안한 착용감을 제공합니다.",
        "price": 219000,
        "image_url": "/images/products/product-5.jpg",
        "category": "패션",
        "stock": 80,
    },
    {
        "name": "유니클로 히트텍 울트라 웜 세트",
        "description": "한겨울에도 따뜻한 히트텍 울트라 웜 상하의 세트. 발열 기능이 뛰어납니다.",
        "price": 49900,
        "image_url": "/images/products/product-6.jpg",
        "category": "패션",
        "stock": 200,
    },
    {
        "name": "캉골 버킷햇 클래식",
        "description": "캉골의 시그니처 버킷햇. 사계절 착용 가능한 클래식 디자인입니다.",
        "price": 69000,
        "image_url": "/images/products/product-7.jpg",
        "category": "패션",
        "stock": 150,
    },
    {
        "name": "노스페이스 눕시 패딩 자켓",
        "description": "가볍고 따뜻한 눕시 패딩. 700 필파워 구스다운으로 보온성이 뛰어납니다.",
        "price": 399000,
        "image_url": "/images/products/product-8.jpg",
        "category": "패션",
        "stock": 60,
    },
    # 식품 (Food)
    {
        "name": "곰곰 유기농 현미 10kg",
        "description": "국내산 유기농 현미. 건강한 식단을 위한 프리미엄 쌀입니다.",
        "price": 42900,
        "image_url": "/images/products/product-9.jpg",
        "category": "식품",
        "stock": 300,
    },
    {
        "name": "정관장 홍삼정 에브리타임 30포",
        "description": "6년근 홍삼 농축액을 담은 스틱형 건강기능식품입니다.",
        "price": 52000,
        "image_url": "/images/products/product-10.jpg",
        "category": "식품",
        "stock": 500,
    },
    {
        "name": "비비고 왕교자 만두 1.4kg",
        "description": "풍부한 속재료가 가득한 왕교자 만두. 간편하게 조리할 수 있습니다.",
        "price": 12900,
        "image_url": "/images/products/product-11.jpg",
        "category": "식품",
        "stock": 1000,
    },
    {
        "name": "스타벅스 캡슐 커피 믹스 60개입",
        "description": "스타벅스 원두를 사용한 캡슐 커피. 다양한 맛을 즐길 수 있습니다.",
        "price": 34900,
        "image_url": "/images/products/product-12.jpg",
        "category": "식품",
        "stock": 400,
    },
    # 생활용품 (Home & Living)
    {
        "name": "다이슨 V15 무선 청소기",
        "description": "레이저 먼지 감지 기술이 탑재된 최신 무선 청소기입니다.",
        "price": 1190000,
        "image_url": "/images/products/product-13.jpg",
        "category": "생활용품",
        "stock": 25,
    },
    {
        "name": "쿠쿠 IH 전기압력밥솥 10인용",
        "description": "IH 가열 방식으로 맛있는 밥을 짓는 전기압력밥솥입니다.",
        "price": 289000,
        "image_url": "/images/products/product-14.jpg",
        "category": "생활용품",
        "stock": 40,
    },
    {
        "name": "코웨이 아이콘 정수기 렌탈",
        "description": "슬림한 디자인의 직수형 정수기. 냉온수 기능을 제공합니다.",
        "price": 39900,
        "image_url": "/images/products/product-15.jpg",
        "category": "생활용품",
        "stock": 100,
    },
    {
        "name": "일룸 데스커 모션 데스크",
        "description": "전동 높이 조절이 가능한 스탠딩 데스크. 인체공학적 설계입니다.",
        "price": 699000,
        "image_url": "/images/products/product-16.jpg",
        "category": "생활용품",
        "stock": 15,
    },
    # 뷰티 (Beauty)
    {
        "name": "설화수 자음생 크림 60ml",
        "description": "인삼 성분이 함유된 프리미엄 안티에이징 크림입니다.",
        "price": 170000,
        "image_url": "/images/products/product-17.jpg",
        "category": "뷰티",
        "stock": 70,
    },
    {
        "name": "이니스프리 그린티 세럼 80ml",
        "description": "제주 녹차 성분으로 피부를 촉촉하게 가꿔주는 세럼입니다.",
        "price": 25000,
        "image_url": "/images/products/product-18.jpg",
        "category": "뷰티",
        "stock": 300,
    },
    {
        "name": "라네즈 립 슬리핑 마스크 20g",
        "description": "자는 동안 입술을 촉촉하게 케어하는 립 마스크입니다.",
        "price": 18000,
        "image_url": "/images/products/product-19.jpg",
        "category": "뷰티",
        "stock": 500,
    },
    {
        "name": "에스티로더 더블웨어 파운데이션",
        "description": "24시간 지속력의 풀커버 파운데이션. 다양한 피부톤에 맞는 색상을 제공합니다.",
        "price": 64000,
        "image_url": "/images/products/product-20.jpg",
        "category": "뷰티",
        "stock": 120,
    },
]


async def seed():
    """시드 데이터 삽입"""
    print("========================================")
    print("  시드 데이터 삽입 시작")
    print(f"  DB: {settings.DB_TYPE}")
    print("========================================")

    # 데이터베이스 초기화
    await init_database()

    try:
        # 1. 기존 데이터 삭제
        print("\n[Seed] 기존 데이터 삭제 중...")
        await query("DELETE FROM order_items")
        await query("DELETE FROM orders")
        await query("DELETE FROM cart_items")
        await query("DELETE FROM reviews")
        await query("DELETE FROM products")
        await query("DELETE FROM users")
        print("[Seed] 기존 데이터 삭제 완료")

        # 2. 테스트 사용자 생성
        print("\n[Seed] 테스트 사용자 생성 중...")
        salt = bcrypt.gensalt(rounds=10)
        password_hash = bcrypt.hashpw(
            TEST_USER["password"].encode("utf-8"), salt
        ).decode("utf-8")

        result = await query(
            "INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)",
            [TEST_USER["email"], password_hash, TEST_USER["name"]],
        )
        print(f"[Seed] 테스트 사용자 생성 완료: {TEST_USER['email']} (ID: {result['insertId']})")

        # 3. 상품 데이터 삽입
        print("\n[Seed] 상품 데이터 삽입 중...")
        for i, product in enumerate(PRODUCTS, 1):
            await query(
                """INSERT INTO products (name, description, price, image_url, category, stock)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    product["name"],
                    product["description"],
                    product["price"],
                    product["image_url"],
                    product["category"],
                    product["stock"],
                ],
            )
            print(f"  [{i:2d}/20] {product['name']} - {product['price']:,}원 ({product['category']})")

        print(f"\n[Seed] 상품 {len(PRODUCTS)}개 삽입 완료")

        # 4. 결과 확인
        users = await query("SELECT COUNT(*) as count FROM users")
        products = await query("SELECT COUNT(*) as count FROM products")
        print("\n========================================")
        print("  시드 데이터 삽입 완료!")
        print(f"  사용자: {users[0]['count']}명")
        print(f"  상품: {products[0]['count']}개")
        print("========================================")

    except Exception as e:
        print(f"\n[Seed] 오류 발생: {e}")
        raise

    finally:
        await close_database()


if __name__ == "__main__":
    asyncio.run(seed())
