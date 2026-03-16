"""
상품 라우터
- GET /api/products       : 상품 목록 조회 (카테고리, 검색 필터)
- GET /api/products/:id   : 상품 상세 조회
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from app.config.database import query
from app.services import cache as cache_service
from app.models.schemas import to_camel

router = APIRouter(prefix="/api/products", tags=["products"])


@router.get("")
async def get_products(
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    """
    GET /api/products - 상품 목록 조회
    Query: ?category=전자기기&search=노트북
    """
    try:
        # 캐시 키 생성
        cache_key = f"products:{category or 'all'}:{search or ''}"

        # 캐시 확인
        cached = await cache_service.get(cache_key)
        if cached:
            return {"products": cached}

        # SQL 쿼리 동적 생성
        sql = "SELECT * FROM products WHERE 1=1"
        params = []

        # 카테고리 필터
        if category:
            sql += " AND category = ?"
            params.append(category)

        # 검색어 필터 (상품명, 설명에서 검색)
        if search:
            sql += " AND (name LIKE ? OR description LIKE ?)"
            search_pattern = f"%{search}%"
            params.append(search_pattern)
            params.append(search_pattern)

        sql += " ORDER BY created_at DESC"

        rows = await query(sql, params)
        products = [to_camel(row) for row in rows]

        # 결과 캐싱 (60초)
        await cache_service.set(cache_key, products, 60)

        return {"products": products}

    except Exception as e:
        print(f"[Products] 목록 조회 오류: {e}")
        raise HTTPException(
            status_code=500, detail="상품 목록 조회 중 오류가 발생했습니다"
        )


@router.get("/{product_id}")
async def get_product(product_id: int):
    """
    GET /api/products/:id - 상품 상세 조회
    """
    try:
        # 캐시 확인
        cache_key = f"product:{product_id}"
        cached = await cache_service.get(cache_key)
        if cached:
            return {"product": cached}

        products = await query("SELECT * FROM products WHERE id = ?", [product_id])

        if len(products) == 0:
            raise HTTPException(status_code=404, detail="상품을 찾을 수 없습니다")

        product = to_camel(products[0])

        # 결과 캐싱 (120초)
        await cache_service.set(cache_key, product, 120)

        return {"product": product}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Products] 상세 조회 오류: {e}")
        raise HTTPException(
            status_code=500, detail="상품 조회 중 오류가 발생했습니다"
        )
