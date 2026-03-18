"""
인증 라우터
- POST /api/auth/signup  : 회원가입
- POST /api/auth/login   : 로그인
- GET  /api/auth/me      : 현재 사용자 정보 조회
"""

import re
from datetime import datetime, timedelta

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException

from app.config.settings import settings
from app.config.database import query
from app.middleware.auth import get_current_user
from app.models.schemas import SignupRequest, LoginRequest

router = APIRouter(prefix="/api/auth", tags=["auth"])


def generate_token(user: dict) -> str:
    """
    JWT 토큰 생성
    :param user: 사용자 정보
    :returns: JWT 토큰 문자열
    """
    payload = {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "exp": datetime.utcnow() + timedelta(hours=24),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")


@router.post("/signup", status_code=201)
async def signup(body: SignupRequest):
    """
    POST /api/auth/signup - 회원가입
    Body: { email, password, name }
    """
    try:
        email = body.email
        password = body.password
        name = body.name

        # 입력 검증
        if not email or not password or not name:
            raise HTTPException(
                status_code=400, detail="이메일, 비밀번호, 이름은 필수 항목입니다"
            )

        # 이메일 형식 검증
        email_regex = r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
        if not re.match(email_regex, email):
            raise HTTPException(
                status_code=400, detail="올바른 이메일 형식이 아닙니다"
            )

        # 비밀번호 길이 검증
        if len(password) < 6:
            raise HTTPException(
                status_code=400, detail="비밀번호는 6자 이상이어야 합니다"
            )

        # 이메일 중복 확인
        existing = await query("SELECT id FROM users WHERE email = ?", [email])
        if len(existing) > 0:
            raise HTTPException(
                status_code=409, detail="이미 등록된 이메일입니다"
            )

        # 비밀번호 해싱
        salt = bcrypt.gensalt(rounds=10)
        password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

        # 사용자 생성
        result = await query(
            "INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)",
            [email, password_hash, name],
        )

        user = {"id": result["insertId"], "email": email, "name": name}
        token = generate_token(user)

        return {
            "token": token,
            "user": {"id": user["id"], "email": user["email"], "name": user["name"]},
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Auth] 회원가입 오류: {e}")
        raise HTTPException(
            status_code=500, detail="회원가입 처리 중 오류가 발생했습니다"
        )


@router.post("/login")
async def login(body: LoginRequest):
    """
    POST /api/auth/login - 로그인
    Body: { email, password }
    """
    try:
        email = body.email
        password = body.password

        # 입력 검증
        if not email or not password:
            raise HTTPException(
                status_code=400, detail="이메일과 비밀번호를 입력해주세요"
            )

        # 사용자 조회
        users = await query("SELECT * FROM users WHERE email = ?", [email])
        if len(users) == 0:
            raise HTTPException(
                status_code=401, detail="이메일 또는 비밀번호가 일치하지 않습니다"
            )

        user = users[0]

        # 비밀번호 검증
        is_match = bcrypt.checkpw(
            password.encode("utf-8"), user["password_hash"].encode("utf-8")
        )
        if not is_match:
            raise HTTPException(
                status_code=401, detail="이메일 또는 비밀번호가 일치하지 않습니다"
            )

        token = generate_token(user)

        return {
            "token": token,
            "user": {"id": user["id"], "email": user["email"], "name": user["name"]},
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Auth] 로그인 오류: {e}")
        raise HTTPException(
            status_code=500, detail="로그인 처리 중 오류가 발생했습니다"
        )


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """
    GET /api/auth/me - 현재 사용자 정보 조회 (인증 필요)
    """
    try:
        users = await query(
            "SELECT id, email, name, created_at FROM users WHERE id = ?",
            [current_user["id"]],
        )

        if len(users) == 0:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다")

        user = users[0]
        return {
            "user": {
                "id": user["id"],
                "email": user["email"],
                "name": user["name"],
                "createdAt": user["created_at"],
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Auth] 사용자 조회 오류: {e}")
        raise HTTPException(
            status_code=500, detail="사용자 정보 조회 중 오류가 발생했습니다"
        )
