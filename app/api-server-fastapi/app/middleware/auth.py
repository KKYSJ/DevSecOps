"""
JWT 인증 미들웨어
- Authorization 헤더에서 Bearer 토큰 추출
- 토큰 검증 후 사용자 정보 반환
"""

import jwt
from fastapi import Header, HTTPException

from app.config.settings import settings


async def get_current_user(authorization: str = Header(None)) -> dict:
    """
    인증 미들웨어 (FastAPI Depends 패턴)
    - 인증 필요한 라우트에 Depends(get_current_user)로 적용
    - 성공 시 {"id": ..., "email": ..., "name": ...} 반환

    :param authorization: Authorization 헤더 값
    :returns: 사용자 정보 dict
    :raises HTTPException: 인증 실패 시
    """
    # Authorization 헤더 확인
    if not authorization:
        raise HTTPException(status_code=401, detail="인증 토큰이 필요합니다")

    # Bearer 토큰 추출
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0] != "Bearer":
        raise HTTPException(
            status_code=401,
            detail="올바른 토큰 형식이 아닙니다 (Bearer <token>)",
        )

    token = parts[1]

    try:
        # 토큰 검증
        decoded = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])

        return {
            "id": decoded["id"],
            "email": decoded["email"],
            "name": decoded["name"],
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다")
    except Exception:
        raise HTTPException(
            status_code=500, detail="인증 처리 중 오류가 발생했습니다"
        )
