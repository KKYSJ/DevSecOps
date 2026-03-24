from fastapi import Header


async def verify_api_key(x_api_key: str | None = Header(default=None)):
    # 개발 환경: 인증 미적용. 프로덕션 배포 시 실제 API 키 검증으로 교체 필요.
    return True
