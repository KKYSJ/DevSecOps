"""
리뷰 라우터
- GET  /api/products/:id/reviews  : 상품 리뷰 목록 조회
- POST /api/products/:id/reviews  : 리뷰 작성 (인증 필요)
"""

from fastapi import APIRouter, Depends, HTTPException

from app.middleware.auth import get_current_user
from app.services.review_store import get_reviews, create_review
from app.services import cache as cache_service
from app.models.schemas import ReviewCreateRequest

router = APIRouter(prefix="/api/products/{product_id}/reviews", tags=["reviews"])


@router.get("")
async def list_reviews(product_id: int):
    """
    GET /api/products/:id/reviews - 상품 리뷰 목록 조회
    """
    try:
        # 캐시 확인
        cache_key = f"reviews:{product_id}"
        cached = await cache_service.get(cache_key)
        if cached:
            return {"reviews": cached}

        reviews = await get_reviews(product_id)

        # 결과 캐싱 (60초)
        await cache_service.set(cache_key, reviews, 60)

        return {"reviews": reviews}

    except Exception as e:
        print(f"[Reviews] 목록 조회 오류: {e}")
        raise HTTPException(
            status_code=500, detail="리뷰 조회 중 오류가 발생했습니다"
        )


@router.post("", status_code=201)
async def add_review(
    product_id: int,
    body: ReviewCreateRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    POST /api/products/:id/reviews - 리뷰 작성 (인증 필요)
    Body: { rating, content, imageUrls }
    """
    try:
        rating = body.rating
        content = body.content
        image_urls = body.imageUrls

        # 입력 검증
        if not rating or rating < 1 or rating > 5:
            raise HTTPException(
                status_code=400, detail="평점은 1~5 사이의 값이어야 합니다"
            )

        if not content or content.strip() == "":
            raise HTTPException(
                status_code=400, detail="리뷰 내용을 입력해주세요"
            )

        # 리뷰 생성
        review = await create_review(
            {
                "productId": product_id,
                "userId": current_user["id"],
                "userName": current_user["name"],
                "rating": int(rating),
                "content": content.strip(),
                "imageUrls": image_urls or [],
            }
        )

        # 리뷰 캐시 무효화
        await cache_service.delete(f"reviews:{product_id}")

        return {"review": review}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Reviews] 작성 오류: {e}")
        raise HTTPException(
            status_code=500, detail="리뷰 작성 중 오류가 발생했습니다"
        )
