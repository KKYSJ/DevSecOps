"""
장바구니 라우터
- GET    /api/cart          : 장바구니 조회
- POST   /api/cart          : 장바구니에 상품 추가
- PUT    /api/cart/:itemId  : 장바구니 수량 변경
- DELETE /api/cart/:itemId  : 장바구니 항목 삭제
- DELETE /api/cart          : 장바구니 전체 삭제

모든 엔드포인트는 인증 필요
"""

from fastapi import APIRouter, Depends, HTTPException

from app.config.database import query
from app.middleware.auth import get_current_user
from app.models.schemas import CartAddRequest, CartUpdateRequest

router = APIRouter(prefix="/api/cart", tags=["cart"])


@router.get("")
async def get_cart(current_user: dict = Depends(get_current_user)):
    """
    GET /api/cart - 장바구니 조회
    상품 정보를 JOIN하여 반환
    """
    try:
        rows = await query(
            """SELECT ci.id, ci.product_id AS productId, ci.quantity,
                      p.name AS productName, p.price AS productPrice,
                      p.image_url AS productImageUrl, p.stock
               FROM cart_items ci
               JOIN products p ON ci.product_id = p.id
               WHERE ci.user_id = ?""",
            [current_user["id"]],
        )

        return {"items": rows}

    except Exception as e:
        print(f"[Cart] 조회 오류: {e}")
        raise HTTPException(
            status_code=500, detail="장바구니 조회 중 오류가 발생했습니다"
        )


@router.post("", status_code=201)
async def add_to_cart(
    body: CartAddRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    POST /api/cart - 장바구니에 상품 추가
    Body: { productId, quantity }
    """
    try:
        product_id = body.productId
        quantity = body.quantity

        # 입력 검증
        if not product_id:
            raise HTTPException(
                status_code=400, detail="상품 ID를 입력해주세요"
            )

        if quantity < 1:
            raise HTTPException(
                status_code=400, detail="수량은 1 이상이어야 합니다"
            )

        # 상품 존재 여부 확인
        products = await query("SELECT * FROM products WHERE id = ?", [product_id])
        if len(products) == 0:
            raise HTTPException(status_code=404, detail="상품을 찾을 수 없습니다")

        # 재고 확인
        if products[0]["stock"] < quantity:
            raise HTTPException(status_code=400, detail="재고가 부족합니다")

        # 이미 장바구니에 있는지 확인
        existing = await query(
            "SELECT * FROM cart_items WHERE user_id = ? AND product_id = ?",
            [current_user["id"], product_id],
        )

        if len(existing) > 0:
            # 이미 있으면 수량 추가
            new_quantity = existing[0]["quantity"] + quantity
            await query(
                "UPDATE cart_items SET quantity = ? WHERE id = ?",
                [new_quantity, existing[0]["id"]],
            )
            item = {
                "id": existing[0]["id"],
                "product_id": product_id,
                "quantity": new_quantity,
            }
        else:
            # 없으면 새로 추가
            result = await query(
                "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
                [current_user["id"], product_id, quantity],
            )
            item = {
                "id": result["insertId"],
                "product_id": product_id,
                "quantity": quantity,
            }

        return {"item": item}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Cart] 추가 오류: {e}")
        raise HTTPException(
            status_code=500, detail="장바구니 추가 중 오류가 발생했습니다"
        )


@router.put("/{item_id}")
async def update_cart_item(
    item_id: int,
    body: CartUpdateRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    PUT /api/cart/:itemId - 장바구니 수량 변경
    Body: { quantity }
    """
    try:
        quantity = body.quantity

        # 입력 검증
        if not quantity or quantity < 1:
            raise HTTPException(
                status_code=400, detail="수량은 1 이상이어야 합니다"
            )

        # 장바구니 항목 확인 (본인 것인지)
        items = await query(
            "SELECT * FROM cart_items WHERE id = ? AND user_id = ?",
            [item_id, current_user["id"]],
        )

        if len(items) == 0:
            raise HTTPException(
                status_code=404, detail="장바구니 항목을 찾을 수 없습니다"
            )

        # 재고 확인
        products = await query(
            "SELECT stock FROM products WHERE id = ?", [items[0]["product_id"]]
        )
        if products[0]["stock"] < quantity:
            raise HTTPException(status_code=400, detail="재고가 부족합니다")

        # 수량 업데이트
        await query(
            "UPDATE cart_items SET quantity = ? WHERE id = ?", [quantity, item_id]
        )

        item = {
            "id": item_id,
            "product_id": items[0]["product_id"],
            "quantity": quantity,
        }
        return {"item": item}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Cart] 수량 변경 오류: {e}")
        raise HTTPException(
            status_code=500, detail="수량 변경 중 오류가 발생했습니다"
        )


@router.delete("/{item_id}")
async def delete_cart_item(
    item_id: int,
    current_user: dict = Depends(get_current_user),
):
    """
    DELETE /api/cart/:itemId - 장바구니 항목 삭제
    """
    try:
        # 본인 항목인지 확인 후 삭제
        result = await query(
            "DELETE FROM cart_items WHERE id = ? AND user_id = ?",
            [item_id, current_user["id"]],
        )

        if result["changes"] == 0:
            raise HTTPException(
                status_code=404, detail="장바구니 항목을 찾을 수 없습니다"
            )

        return {"success": True}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Cart] 삭제 오류: {e}")
        raise HTTPException(
            status_code=500, detail="장바구니 삭제 중 오류가 발생했습니다"
        )


@router.delete("")
async def clear_cart(current_user: dict = Depends(get_current_user)):
    """
    DELETE /api/cart - 장바구니 전체 삭제
    """
    try:
        await query(
            "DELETE FROM cart_items WHERE user_id = ?", [current_user["id"]]
        )
        return {"success": True}

    except Exception as e:
        print(f"[Cart] 전체 삭제 오류: {e}")
        raise HTTPException(
            status_code=500, detail="장바구니 비우기 중 오류가 발생했습니다"
        )
