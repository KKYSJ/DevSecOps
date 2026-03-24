"""
보안 취약점 수정 완료 코드
- 이전 SAST 스캔에서 발견된 취약점을 모두 패치
- SecureFlow 파이프라인 검증 목적 (성공 시나리오)
"""

import os
import hashlib
import subprocess
import sqlite3
import secrets
from fastapi import APIRouter, Request, HTTPException
from markupsafe import escape

router = APIRouter()

# ── 1. SQL Injection (CWE-89) → 파라미터 바인딩으로 수정
@router.get("/users/search")
def search_user(username: str):
    conn = sqlite3.connect("data/app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return {"users": cursor.fetchall()}


# ── 2. OS Command Injection (CWE-78) → 화이트리스트 + shlex 사용
@router.get("/system/ping")
def ping_host(host: str):
    import re
    if not re.match(r'^[\w.\-]+$', host):
        raise HTTPException(status_code=400, detail="Invalid host format")
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True, text=True, timeout=5
    )
    return {"output": result.stdout}


# ── 3. Path Traversal (CWE-22) → 경로 검증
SAFE_DIR = os.path.abspath("data/public")

@router.get("/files/read")
def read_file(filepath: str):
    full_path = os.path.abspath(os.path.join(SAFE_DIR, filepath))
    if not full_path.startswith(SAFE_DIR):
        raise HTTPException(status_code=403, detail="Access denied")
    with open(full_path, "r") as f:
        return {"content": f.read()}


# ── 4. Hardcoded Secret (CWE-798) → 환경변수 사용
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "")


# ── 5. Weak Hash - MD5 (CWE-327) → SHA-256 사용
@router.post("/auth/hash")
def hash_password(password: str):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return {"hash": f"{salt}:{hashed}"}


# ── 6. SSRF (CWE-918) → URL 화이트리스트
import urllib.request

ALLOWED_DOMAINS = ["api.example.com", "internal.service.local"]

@router.get("/fetch")
def fetch_url(url: str):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=403, detail="Domain not allowed")
    response = urllib.request.urlopen(url, timeout=5)
    return {"data": response.read().decode()[:500]}


# ── 7. Unsafe Deserialization (CWE-502) → JSON 사용
import json
import base64

@router.post("/deserialize")
def deserialize_data(data: str):
    try:
        obj = json.loads(base64.b64decode(data).decode())
    except (json.JSONDecodeError, Exception):
        raise HTTPException(status_code=400, detail="Invalid data format")
    return {"result": str(obj)}


# ── 8. XSS Reflected (CWE-79) → 이스케이프 처리
@router.get("/greet")
def greet(name: str):
    safe_name = escape(name)
    return {"message": f"Hello {safe_name}"}


# ── 9. Insecure Random (CWE-330) → secrets 모듈 사용
@router.get("/token/generate")
def generate_token():
    token = secrets.token_hex(16)
    return {"token": token}


# ── 10. Binding to all interfaces (CWE-1327) → localhost로 변경
def start_server():
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000)


# ── 11. SSL verification 활성화 (CWE-295)
import requests

def call_external_api():
    resp = requests.get("https://api.example.com", verify=True)
    return resp.json()
