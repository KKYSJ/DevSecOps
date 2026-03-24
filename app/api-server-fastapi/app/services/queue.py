"""
메시지 큐 서비스 추상화
- sync 모드: 동기 처리 (로그만 출력)
- sqs 모드: AWS SQS에 메시지 전송
- sns 모드: AWS SNS에 알림 발행
"""

import json
from datetime import datetime

from app.config.settings import settings


async def send_order_message(order_id: int, user: dict, items: list, total_amount: int):
    """
    주문 메시지 전송
    :param order_id: 주문 ID
    :param user: 사용자 정보 {id, email, name}
    :param items: 주문 항목 리스트
    :param total_amount: 총 금액
    """
    if settings.QUEUE_TYPE != "sqs":
        print(f"[Queue] 동기 모드 - 주문 #{order_id} 처리 완료")
        return

    try:
        message = {
            "orderId": order_id,
            "userId": user["id"],
            "userEmail": user.get("email", ""),
            "userName": user.get("name", ""),
            "items": [
                {
                    "productId": item["product_id"],
                    "productName": item["name"],
                    "quantity": item["quantity"],
                    "price": item["price"],
                }
                for item in items
            ],
            "totalAmount": total_amount,
            "createdAt": datetime.utcnow().isoformat(),
        }

        # SQS에 주문 메시지 전송
        if settings.SQS_QUEUE_URL:
            from app.config.aws import get_sqs_client

            sqs = get_sqs_client()
            sqs.send_message(
                QueueUrl=settings.SQS_QUEUE_URL,
                MessageBody=json.dumps(message),
                MessageAttributes={
                    "orderType": {
                        "DataType": "String",
                        "StringValue": "NEW_ORDER",
                    }
                },
            )
            print(f"[Orders] SQS 메시지 전송 완료 - 주문 #{order_id}")

        # SNS에 주문 알림 발행
        if settings.SNS_TOPIC_ARN:
            from app.config.aws import get_sns_client

            sns = get_sns_client()
            sns.publish(
                TopicArn=settings.SNS_TOPIC_ARN,
                Subject=f"새 주문 알림 - 주문 #{order_id}",
                Message=json.dumps(
                    {
                        "orderId": order_id,
                        "userId": user["id"],
                        "userName": user.get("name", ""),
                        "totalAmount": total_amount,
                        "itemCount": len(items),
                        "createdAt": datetime.utcnow().isoformat(),
                    }
                ),
            )
            print(f"[Orders] SNS 알림 발행 완료 - 주문 #{order_id}")

    except Exception as e:
        # 큐 전송 실패해도 주문 자체는 성공으로 처리
        print(f"[Orders] SQS/SNS 전송 오류: {e}")
