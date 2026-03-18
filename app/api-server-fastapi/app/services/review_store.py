"""
리뷰 저장소 서비스 추상화
- local 모드: SQLite/MySQL의 reviews 테이블 사용
- dynamodb 모드: AWS DynamoDB 사용
"""

import uuid
import json
from datetime import datetime

from app.config.settings import settings


async def get_reviews(product_id) -> list:
    """
    상품의 리뷰 목록 조회
    :param product_id: 상품 ID
    :returns: 리뷰 배열
    """
    if settings.REVIEW_STORE == "dynamodb":
        return await _get_reviews_from_dynamodb(product_id)
    else:
        return await _get_reviews_from_db(product_id)


async def create_review(review: dict) -> dict:
    """
    리뷰 생성
    :param review: 리뷰 데이터 (productId, userId, userName, rating, content, imageUrls)
    :returns: 생성된 리뷰
    """
    if settings.REVIEW_STORE == "dynamodb":
        return await _create_review_in_dynamodb(review)
    else:
        return await _create_review_in_db(review)


# ========================================
# 로컬 DB (SQLite/MySQL) 구현
# ========================================

async def _get_reviews_from_db(product_id) -> list:
    """DB에서 리뷰 조회"""
    from app.config.database import query

    reviews = await query(
        "SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC",
        [product_id],
    )

    # snake_case -> camelCase 변환 및 image_urls JSON 파싱
    return [
        {
            "id": review["id"],
            "productId": review["product_id"],
            "userId": review["user_id"],
            "userName": review["user_name"],
            "rating": review["rating"],
            "content": review["content"],
            "imageUrls": json.loads(review["image_urls"]) if review["image_urls"] else [],
            "createdAt": review["created_at"],
        }
        for review in reviews
    ]


async def _create_review_in_db(review: dict) -> dict:
    """DB에 리뷰 생성"""
    from app.config.database import query

    image_urls_json = json.dumps(review.get("imageUrls", []))

    result = await query(
        """INSERT INTO reviews (product_id, user_id, user_name, rating, content, image_urls)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [
            review["productId"],
            review["userId"],
            review["userName"],
            review["rating"],
            review["content"],
            image_urls_json,
        ],
    )

    # 생성된 리뷰 반환 (camelCase)
    return {
        "id": result["insertId"],
        "productId": review["productId"],
        "userId": review["userId"],
        "userName": review["userName"],
        "rating": review["rating"],
        "content": review["content"],
        "imageUrls": review.get("imageUrls", []),
        "createdAt": datetime.utcnow().isoformat(),
    }


# ========================================
# DynamoDB 구현
# ========================================

async def _get_reviews_from_dynamodb(product_id) -> list:
    """DynamoDB에서 리뷰 조회"""
    from app.config.aws import get_dynamodb_resource

    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(settings.DYNAMODB_TABLE)

    response = table.query(
        KeyConditionExpression="productId = :pid",
        ExpressionAttributeValues={":pid": str(product_id)},
        ScanIndexForward=False,  # 최신순 정렬 (내림차순)
    )

    # DynamoDB 결과를 통일된 형식으로 변환 (camelCase)
    return [
        {
            "id": item.get("reviewId"),
            "productId": int(item["productId"]),
            "userId": item.get("userId"),
            "userName": item.get("userName"),
            "rating": item.get("rating"),
            "content": item.get("content"),
            "imageUrls": item.get("imageUrls", []),
            "createdAt": item.get("createdAt"),
        }
        for item in response.get("Items", [])
    ]


async def _create_review_in_dynamodb(review: dict) -> dict:
    """DynamoDB에 리뷰 생성"""
    from app.config.aws import get_dynamodb_resource

    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(settings.DYNAMODB_TABLE)

    now = datetime.utcnow().isoformat()
    review_id = str(uuid.uuid4())

    # Sort Key: createdAt#userId 형식
    sort_key = f"{now}#{review['userId']}"

    item = {
        "productId": str(review["productId"]),
        "createdAt#userId": sort_key,
        "reviewId": review_id,
        "userId": review["userId"],
        "userName": review["userName"],
        "rating": review["rating"],
        "content": review["content"],
        "imageUrls": review.get("imageUrls", []),
        "createdAt": now,
    }

    table.put_item(Item=item)

    return {
        "id": review_id,
        "productId": int(review["productId"]),
        "userId": review["userId"],
        "userName": review["userName"],
        "rating": review["rating"],
        "content": review["content"],
        "imageUrls": review.get("imageUrls", []),
        "createdAt": now,
    }
