"""
주문 라우터
- POST /api/orders  : 장바구니에서 주문 생성
- GET  /api/orders  : 주문 내역 조회

모든 엔드포인트는 인증 필요
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from app.config.database import query
from app.config.settings import settings
from app.middleware.auth import get_current_user
from app.services.queue import send_order_message

router = APIRouter(prefix="/api/orders", tags=["orders"])


@router.post("", status_code=201)
async def create_order(current_user: dict = Depends(get_current_user)):
    """
    POST /api/orders - 주문 생성
    장바구니의 모든 상품을 주문으로 전환
    """
    try:
        # 1. 장바구니 항목 조회 (상품 정보 포함)
        cart_items = await query(
            """SELECT ci.id, ci.product_id, ci.quantity,
                      p.name, p.price, p.stock
               FROM cart_items ci
               JOIN products p ON ci.product_id = p.id
               WHERE ci.user_id = ?""",
            [current_user["id"]],
        )

        # 장바구니가 비어있으면 에러
        if len(cart_items) == 0:
            raise HTTPException(
                status_code=400, detail="장바구니가 비어있습니다"
            )

        # 2. 재고 확인
        for item in cart_items:
            if item["stock"] < item["quantity"]:
                raise HTTPException(
                    status_code=400,
                    detail=f"'{item['name']}' 상품의 재고가 부족합니다 (재고: {item['stock']}, 요청: {item['quantity']})",
                )

        # 3. 총 금액 계산
        total_amount = sum(item["price"] * item["quantity"] for item in cart_items)

        # 4. 주문 생성
        order_result = await query(
            "INSERT INTO orders (user_id, total_amount, status) VALUES (?, ?, ?)",
            [current_user["id"], total_amount, "pending"],
        )

        order_id = order_result["insertId"]

        # 5. 주문 항목 생성 및 재고 차감
        for item in cart_items:
            # 주문 항목 추가
            await query(
                "INSERT INTO order_items (order_id, product_id, product_name, quantity, price) VALUES (?, ?, ?, ?, ?)",
                [order_id, item["product_id"], item["name"], item["quantity"], item["price"]],
            )

            # 재고 차감
            await query(
                "UPDATE products SET stock = stock - ? WHERE id = ?",
                [item["quantity"], item["product_id"]],
            )

        # 6. 장바구니 비우기
        await query("DELETE FROM cart_items WHERE user_id = ?", [current_user["id"]])

        # 7. SQS/SNS 메시지 전송 (AWS 모드일 때)
        if settings.QUEUE_TYPE == "sqs":
            await send_order_message(order_id, current_user, cart_items, total_amount)

        # 8. 생성된 주문 정보 반환
        order = {
            "id": order_id,
            "userId": current_user["id"],
            "totalAmount": total_amount,
            "status": "pending",
            "createdAt": datetime.utcnow().isoformat(),
            "items": [
                {
                    "productId": item["product_id"],
                    "productName": item["name"],
                    "quantity": item["quantity"],
                    "price": item["price"],
                }
                for item in cart_items
            ],
        }

        return {"order": order}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Orders] 주문 생성 오류: {e}")
        raise HTTPException(
            status_code=500, detail="주문 처리 중 오류가 발생했습니다"
        )


@router.get("")
async def get_orders(current_user: dict = Depends(get_current_user)):
    """
    GET /api/orders - 주문 내역 조회
    """
    try:
        # 주문 목록 조회
        orders = await query(
            "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC",
            [current_user["id"]],
        )

        # 각 주문의 항목 조회
        orders_with_items = []
        for order in orders:
            items = await query(
                "SELECT * FROM order_items WHERE order_id = ?",
                [order["id"]],
            )

            orders_with_items.append(
                {
                    "id": order["id"],
                    "userId": order["user_id"],
                    "totalAmount": order["total_amount"],
                    "status": order["status"],
                    "createdAt": order["created_at"],
                    "items": [
                        {
                            "id": item["id"],
                            "orderId": item["order_id"],
                            "productId": item["product_id"],
                            "productName": item["product_name"],
                            "quantity": item["quantity"],
                            "price": item["price"],
                        }
                        for item in items
                    ],
                }
            )

        return {"orders": orders_with_items}

    except Exception as e:
        print(f"[Orders] 목록 조회 오류: {e}")
        raise HTTPException(
            status_code=500, detail="주문 내역 조회 중 오류가 발생했습니다"
        )
