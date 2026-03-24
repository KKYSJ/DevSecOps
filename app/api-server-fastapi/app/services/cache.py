"""
캐시 서비스 추상화
- memory 모드: 인메모리 dict 사용 (로컬 개발용)
- redis 모드: Redis 사용
"""

import json
import time
import asyncio
from typing import Any, Optional

from app.config.settings import settings

# ========================================
# 인메모리 캐시 구현
# ========================================

# 메모리 캐시 저장소: { key: { "value": ..., "expire_at": ... } }
_memory_cache: dict = {}

# ========================================
# Redis 클라이언트 (lazy initialization)
# ========================================

_redis_client = None


async def _get_redis_client():
    """Redis 클라이언트 반환 (lazy init)"""
    global _redis_client
    if _redis_client is None:
        import redis.asyncio as aioredis

        _redis_client = aioredis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            decode_responses=True,
        )
        print("[Cache] Redis 클라이언트 생성 완료")
    return _redis_client


# ========================================
# 만료된 항목 자동 정리
# ========================================

def _cleanup_expired():
    """만료된 메모리 캐시 항목 정리"""
    now = time.time()
    expired_keys = [
        key for key, entry in _memory_cache.items()
        if entry.get("expire_at") and entry["expire_at"] < now
    ]
    for key in expired_keys:
        del _memory_cache[key]


# ========================================
# 통합 인터페이스
# ========================================

async def get(key: str) -> Optional[Any]:
    """
    캐시에서 값 조회
    :param key: 캐시 키
    :returns: 캐시된 값 또는 None
    """
    if settings.CACHE_TYPE == "redis":
        client = await _get_redis_client()
        value = await client.get(key)
        return json.loads(value) if value else None
    else:
        # 메모리 캐시
        entry = _memory_cache.get(key)
        if not entry:
            return None

        # 만료 확인
        if entry.get("expire_at") and entry["expire_at"] < time.time():
            del _memory_cache[key]
            return None

        return entry["value"]


async def set(key: str, value: Any, ttl: int = 300):
    """
    캐시에 값 저장
    :param key: 캐시 키
    :param value: 저장할 값
    :param ttl: TTL (초), 기본 300초 (5분)
    """
    if settings.CACHE_TYPE == "redis":
        client = await _get_redis_client()
        await client.set(key, json.dumps(value, default=str), ex=ttl)
    else:
        # 메모리 캐시
        _memory_cache[key] = {
            "value": value,
            "expire_at": time.time() + ttl,
        }


async def delete(key: str):
    """
    캐시에서 값 삭제
    :param key: 캐시 키
    """
    if settings.CACHE_TYPE == "redis":
        client = await _get_redis_client()
        await client.delete(key)
    else:
        _memory_cache.pop(key, None)
