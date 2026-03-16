"""
파일 업로드 라우터
- POST /api/upload            : 파일 업로드 (multipart)
- POST /api/upload/presigned  : S3 Pre-signed URL 생성

모든 엔드포인트는 인증 필요
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File

from app.middleware.auth import get_current_user
from app.services.storage import upload_file, get_presigned_url
from app.models.schemas import PresignedRequest

router = APIRouter(prefix="/api/upload", tags=["upload"])

# 허용되는 이미지 MIME 타입
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB


@router.post("")
async def upload(
    file: UploadFile = File(None),
    current_user: dict = Depends(get_current_user),
):
    """
    POST /api/upload - 파일 업로드
    - local 모드: uploads/ 디렉토리에 저장
    - s3 모드: S3 버킷에 업로드
    """
    try:
        if not file:
            raise HTTPException(status_code=400, detail="파일을 선택해주세요")

        # 이미지 파일만 허용
        if file.content_type not in ALLOWED_TYPES:
            raise HTTPException(
                status_code=400,
                detail="이미지 파일만 업로드 가능합니다 (JPEG, PNG, GIF, WebP)",
            )

        # 파일 크기 확인
        file_data = await file.read()
        if len(file_data) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400, detail="파일 크기는 5MB 이하여야 합니다"
            )

        # 스토리지 서비스를 통해 파일 업로드
        file_url = await upload_file(file_data, file.filename, file.content_type)

        return {"fileUrl": file_url}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[Upload] 업로드 오류: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e) or "파일 업로드 중 오류가 발생했습니다",
        )


@router.post("/presigned")
async def presigned(
    body: PresignedRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    POST /api/upload/presigned - S3 Pre-signed URL 생성
    Body: { fileName, fileType }
    - S3 모드에서만 동작
    - 클라이언트가 직접 S3에 업로드할 수 있는 임시 URL 반환
    """
    try:
        file_name = body.fileName
        file_type = body.fileType

        if not file_name or not file_type:
            raise HTTPException(
                status_code=400, detail="파일명과 파일 타입을 입력해주세요"
            )

        result = await get_presigned_url(file_name, file_type)

        return {
            "uploadUrl": result["uploadUrl"],
            "fileUrl": result["fileUrl"],
        }

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"[Upload] Pre-signed URL 생성 오류: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e) or "Pre-signed URL 생성 중 오류가 발생했습니다",
        )
