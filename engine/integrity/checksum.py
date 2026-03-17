"""
파일 무결성 검증을 위한 SHA256 체크섬 유틸리티.
"""

import hashlib
import logging
import os

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 65536  # 64KB 청크로 읽기


def compute(path: str) -> str:
    """파일의 SHA256 체크섬을 계산합니다.

    Args:
        path: 체크섬을 계산할 파일 경로

    Returns:
        소문자 16진수 SHA256 해시 문자열 (64자)

    Raises:
        FileNotFoundError: 파일이 존재하지 않는 경우
        PermissionError: 파일을 읽을 권한이 없는 경우
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {path}")

    sha256 = hashlib.sha256()

    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(_CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
    except PermissionError as e:
        logger.error("파일 읽기 권한 없음: %s", path)
        raise

    checksum = sha256.hexdigest()
    logger.debug("체크섬 계산 완료: path=%s, sha256=%s", path, checksum)
    return checksum


def verify(path: str, expected: str) -> bool:
    """파일의 체크섬이 예상값과 일치하는지 확인합니다.

    Args:
        path: 검증할 파일 경로
        expected: 예상되는 SHA256 체크섬 (대소문자 무관)

    Returns:
        체크섬이 일치하면 True, 그렇지 않으면 False
    """
    try:
        actual = compute(path)
        matches = actual.lower() == expected.lower().strip()
        if not matches:
            logger.warning(
                "체크섬 불일치: path=%s, expected=%s, actual=%s",
                path, expected, actual
            )
        else:
            logger.debug("체크섬 일치: path=%s", path)
        return matches
    except (FileNotFoundError, PermissionError) as e:
        logger.error("체크섬 검증 실패: %s", e)
        return False


def compute_string(content: str | bytes) -> str:
    """문자열 또는 바이트의 SHA256 체크섬을 계산합니다.

    Args:
        content: 체크섬을 계산할 문자열 또는 바이트

    Returns:
        소문자 16진수 SHA256 해시 문자열 (64자)
    """
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def compute_directory(directory: str, extensions: list[str] = None) -> dict[str, str]:
    """디렉토리 내 모든 파일의 체크섬을 계산합니다.

    Args:
        directory: 체크섬을 계산할 디렉토리 경로
        extensions: 필터링할 파일 확장자 목록 (예: [".py", ".json"]), None이면 모든 파일

    Returns:
        {파일 경로: SHA256 체크섬} dict
    """
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"디렉토리를 찾을 수 없습니다: {directory}")

    checksums = {}
    for root, dirs, files in os.walk(directory):
        # 숨김 디렉토리 제외
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in sorted(files):
            if extensions:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in extensions:
                    continue

            file_path = os.path.join(root, filename)
            try:
                checksum = compute(file_path)
                # 상대 경로로 저장
                rel_path = os.path.relpath(file_path, directory)
                checksums[rel_path] = checksum
            except Exception as e:
                logger.warning("파일 체크섬 계산 실패: %s (%s)", file_path, e)

    return checksums
