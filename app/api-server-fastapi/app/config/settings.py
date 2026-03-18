"""
환경 설정 모듈
- .env 파일에서 설정값을 읽어 전역으로 제공
"""

import os
from dotenv import load_dotenv
from pathlib import Path

# .env 파일 로드 (프로젝트 루트)
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)


class Settings:
    """애플리케이션 설정"""

    # 서버
    PORT: int = int(os.getenv("PORT", "8000"))

    # 데이터베이스
    DB_TYPE: str = os.getenv("DB_TYPE", "sqlite")
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_USER: str = os.getenv("DB_USER", "root")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")
    DB_NAME: str = os.getenv("DB_NAME", "ecommerce")

    # 스토리지
    STORAGE_TYPE: str = os.getenv("STORAGE_TYPE", "local")
    S3_BUCKET: str = os.getenv("S3_BUCKET", "")
    S3_REGION: str = os.getenv("S3_REGION", "ap-northeast-2")

    # 리뷰 저장소
    REVIEW_STORE: str = os.getenv("REVIEW_STORE", "local")
    DYNAMODB_TABLE: str = os.getenv("DYNAMODB_TABLE", "Reviews")
    DYNAMODB_REGION: str = os.getenv("DYNAMODB_REGION", "ap-northeast-2")

    # 캐시
    CACHE_TYPE: str = os.getenv("CACHE_TYPE", "memory")
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))

    # 큐
    QUEUE_TYPE: str = os.getenv("QUEUE_TYPE", "sync")
    SQS_QUEUE_URL: str = os.getenv("SQS_QUEUE_URL", "")
    SNS_TOPIC_ARN: str = os.getenv("SNS_TOPIC_ARN", "")

    # JWT
    JWT_SECRET: str = os.getenv("JWT_SECRET", "ecommerce-jwt-secret-key-2024")

    # 경로
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    UPLOADS_DIR: Path = BASE_DIR / "uploads"
    DB_PATH: Path = DATA_DIR / "ecommerce.db"


settings = Settings()
