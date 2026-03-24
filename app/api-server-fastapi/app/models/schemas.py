"""
Pydantic 스키마 모델
- 요청/응답 데이터 검증용
"""

from pydantic import BaseModel, EmailStr
from typing import Optional, List


# ========================================
# Auth 스키마
# ========================================

class SignupRequest(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None


# ========================================
# Cart 스키마
# ========================================

class CartAddRequest(BaseModel):
    productId: Optional[int] = None
    quantity: int = 1


class CartUpdateRequest(BaseModel):
    quantity: Optional[int] = None


# ========================================
# Review 스키마
# ========================================

class ReviewCreateRequest(BaseModel):
    rating: Optional[int] = None
    content: Optional[str] = None
    imageUrls: Optional[List[str]] = []


# ========================================
# Upload 스키마
# ========================================

class PresignedRequest(BaseModel):
    fileName: Optional[str] = None
    fileType: Optional[str] = None


# ========================================
# 유틸리티 함수
# ========================================

def to_camel(row: dict) -> dict:
    """
    snake_case 딕셔너리 키를 camelCase로 변환
    :param row: snake_case 키를 가진 딕셔너리
    :returns: camelCase 키로 변환된 딕셔너리
    """
    if not row:
        return row

    result = {}
    for key, value in row.items():
        # snake_case -> camelCase
        parts = key.split("_")
        camel_key = parts[0] + "".join(word.capitalize() for word in parts[1:])
        result[camel_key] = value

    return result
