"""
보안 도구 바이너리 및 스캔 결과의 무결성을 검증합니다.
"""

import json
import logging
import os
import shutil
from typing import Optional

from engine.integrity.checksum import compute, verify, compute_string

logger = logging.getLogger(__name__)

# 알려진 도구 바이너리 이름 목록
_TOOL_BINARIES = {
    "sonarqube": ["sonar-scanner"],
    "semgrep": ["semgrep"],
    "trivy": ["trivy"],
    "depcheck": ["dependency-check", "dependency-check.sh", "dependency-check.bat"],
    "tfsec": ["tfsec"],
    "checkov": ["checkov"],
    "zap": ["zap.sh", "zap.bat", "zaproxy"],
}


def verify_tool_binary(tool_name: str, binary_path: Optional[str] = None, expected_checksum: Optional[str] = None) -> dict:
    """도구 바이너리의 존재 여부 및 체크섬을 검증합니다.

    Args:
        tool_name: 검증할 도구 이름
        binary_path: 바이너리 경로 (None이면 PATH에서 자동 탐색)
        expected_checksum: 예상 SHA256 체크섬 (None이면 체크섬 검증 생략)

    Returns:
        {
            "tool": tool_name,
            "found": bool,
            "path": str or None,
            "checksum": str or None,
            "checksum_valid": bool or None,  # expected_checksum이 없으면 None
            "error": str or None,
        }
    """
    result = {
        "tool": tool_name,
        "found": False,
        "path": None,
        "checksum": None,
        "checksum_valid": None,
        "error": None,
    }

    try:
        # 바이너리 경로 탐색
        if binary_path and os.path.isfile(binary_path):
            resolved_path = binary_path
        else:
            # PATH에서 탐색
            binary_names = _TOOL_BINARIES.get(tool_name.lower(), [tool_name])
            resolved_path = None
            for binary_name in binary_names:
                found = shutil.which(binary_name)
                if found:
                    resolved_path = found
                    break

        if not resolved_path:
            result["error"] = f"도구 바이너리를 찾을 수 없습니다: {tool_name}"
            logger.warning(result["error"])
            return result

        result["found"] = True
        result["path"] = resolved_path

        # 체크섬 계산
        checksum = compute(resolved_path)
        result["checksum"] = checksum

        # 체크섬 검증
        if expected_checksum:
            is_valid = checksum.lower() == expected_checksum.lower().strip()
            result["checksum_valid"] = is_valid
            if not is_valid:
                result["error"] = (
                    f"체크섬 불일치: expected={expected_checksum}, actual={checksum}"
                )
                logger.error("도구 무결성 검증 실패: %s - %s", tool_name, result["error"])
            else:
                logger.info("도구 무결성 검증 성공: %s (%s)", tool_name, resolved_path)
        else:
            logger.info("도구 발견: %s (%s, checksum=%s)", tool_name, resolved_path, checksum)

    except Exception as e:
        result["error"] = str(e)
        logger.error("도구 검증 중 오류: %s - %s", tool_name, e)

    return result


def verify_scan_result(result_data: dict, expected_checksum: Optional[str] = None) -> dict:
    """스캔 결과 JSON 데이터의 무결성을 검증합니다.

    Args:
        result_data: 검증할 스캔 결과 dict
        expected_checksum: 예상 SHA256 체크섬 (None이면 체크섬만 계산)

    Returns:
        {
            "checksum": str,
            "checksum_valid": bool or None,
            "error": str or None,
        }
    """
    result = {
        "checksum": None,
        "checksum_valid": None,
        "error": None,
    }

    try:
        # dict를 JSON 문자열로 직렬화 (정렬하여 일관성 보장)
        json_str = json.dumps(result_data, sort_keys=True, ensure_ascii=False)
        checksum = compute_string(json_str)
        result["checksum"] = checksum

        if expected_checksum:
            is_valid = checksum.lower() == expected_checksum.lower().strip()
            result["checksum_valid"] = is_valid
            if not is_valid:
                result["error"] = (
                    f"스캔 결과 체크섬 불일치: expected={expected_checksum}, actual={checksum}"
                )
    except Exception as e:
        result["error"] = str(e)
        logger.error("스캔 결과 검증 실패: %s", e)

    return result


def verify_all_tools(tool_checksums: dict[str, str] = None) -> list[dict]:
    """지원하는 모든 도구의 무결성을 검증합니다.

    Args:
        tool_checksums: {tool_name: expected_checksum} dict (None이면 체크섬 검증 생략)

    Returns:
        각 도구의 검증 결과 목록
    """
    if tool_checksums is None:
        tool_checksums = {}

    results = []
    for tool_name in _TOOL_BINARIES:
        expected = tool_checksums.get(tool_name)
        result = verify_tool_binary(tool_name, expected_checksum=expected)
        results.append(result)

    # 요약 로깅
    found_count = sum(1 for r in results if r["found"])
    logger.info("도구 검증 완료: %d/%d 도구 발견", found_count, len(results))

    return results


def load_checksum_manifest(manifest_path: str) -> dict[str, str]:
    """체크섬 매니페스트 파일을 로드합니다.

    매니페스트 파일 형식:
    {
        "tools": {"sonarqube": "sha256_hash", ...},
        "scan_results": {"scan_id": "sha256_hash", ...}
    }

    Args:
        manifest_path: 매니페스트 JSON 파일 경로

    Returns:
        {파일 이름/도구 이름: SHA256 체크섬} dict
    """
    if not os.path.isfile(manifest_path):
        logger.warning("체크섬 매니페스트 파일을 찾을 수 없습니다: %s", manifest_path)
        return {}

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        checksums = {}
        checksums.update(manifest.get("tools", {}))
        checksums.update(manifest.get("scan_results", {}))
        checksums.update(manifest.get("files", {}))

        logger.info("체크섬 매니페스트 로드 완료: %d 항목", len(checksums))
        return checksums

    except (json.JSONDecodeError, OSError) as e:
        logger.error("체크섬 매니페스트 로드 실패: %s - %s", manifest_path, e)
        return {}


def save_checksum_manifest(checksums: dict[str, str], manifest_path: str) -> bool:
    """체크섬 매니페스트 파일을 저장합니다.

    Args:
        checksums: {이름: SHA256 체크섬} dict
        manifest_path: 저장할 파일 경로

    Returns:
        저장 성공 여부
    """
    try:
        os.makedirs(os.path.dirname(os.path.abspath(manifest_path)), exist_ok=True)
        manifest = {"checksums": checksums}
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        logger.info("체크섬 매니페스트 저장 완료: %s (%d 항목)", manifest_path, len(checksums))
        return True
    except OSError as e:
        logger.error("체크섬 매니페스트 저장 실패: %s - %s", manifest_path, e)
        return False
