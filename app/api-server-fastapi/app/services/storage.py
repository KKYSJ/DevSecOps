"""
파일 스토리지 서비스 추상화
- local 모드: 로컬 디스크(uploads/)에 파일 저장
- s3 모드: AWS S3 버킷에 파일 업로드
"""

import uuid
import os
from pathlib import Path

from app.config.settings import settings

UPLOADS_DIR = settings.UPLOADS_DIR


async def upload_file(file_data: bytes, filename: str, content_type: str) -> str:
    """
    파일 업로드
    :param file_data: 파일 바이너리 데이터
    :param filename: 원본 파일명
    :param content_type: MIME 타입
    :returns: 업로드된 파일의 URL
    """
    if settings.STORAGE_TYPE == "s3":
        return await _upload_to_s3(file_data, filename, content_type)
    else:
        return _upload_to_local(file_data, filename)


def _upload_to_local(file_data: bytes, filename: str) -> str:
    """로컬 디스크에 파일 저장"""
    # uploads 디렉토리가 없으면 생성
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # 고유한 파일명 생성 (UUID + 원본 확장자)
    ext = Path(filename).suffix
    new_filename = f"{uuid.uuid4()}{ext}"
    file_path = UPLOADS_DIR / new_filename

    # 파일 저장
    with open(file_path, "wb") as f:
        f.write(file_data)

    # 접근 가능한 URL 반환
    return f"/uploads/{new_filename}"


async def _upload_to_s3(file_data: bytes, filename: str, content_type: str) -> str:
    """S3에 파일 업로드"""
    from app.config.aws import get_s3_client

    s3 = get_s3_client()
    ext = Path(filename).suffix
    key = f"uploads/{uuid.uuid4()}{ext}"

    s3.put_object(
        Bucket=settings.S3_BUCKET,
        Key=key,
        Body=file_data,
        ContentType=content_type,
    )

    # S3 URL 반환
    return f"https://{settings.S3_BUCKET}.s3.{settings.S3_REGION}.amazonaws.com/{key}"


async def get_presigned_url(file_name: str, file_type: str) -> dict:
    """
    S3 Pre-signed URL 생성
    - 클라이언트에서 직접 S3에 업로드할 수 있는 임시 URL 생성
    :param file_name: 파일명
    :param file_type: MIME 타입
    :returns: {"uploadUrl": str, "fileUrl": str}
    """
    if settings.STORAGE_TYPE != "s3":
        raise ValueError("Pre-signed URL은 S3 모드에서만 사용 가능합니다")

    from app.config.aws import get_s3_client

    s3 = get_s3_client()
    ext = Path(file_name).suffix
    key = f"uploads/{uuid.uuid4()}{ext}"

    # 15분 유효한 pre-signed URL 생성
    upload_url = s3.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": settings.S3_BUCKET,
            "Key": key,
            "ContentType": file_type,
        },
        ExpiresIn=900,  # 15분
    )

    file_url = f"https://{settings.S3_BUCKET}.s3.{settings.S3_REGION}.amazonaws.com/{key}"

    return {"uploadUrl": upload_url, "fileUrl": file_url}
