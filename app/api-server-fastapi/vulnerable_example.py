"""
보안 취약점 테스트용 코드 (SAST 탐지 대상)
- 실제 서비스에서 사용 금지
- SecureFlow 파이프라인 검증 목적
"""

import os
import hashlib
import subprocess
import sqlite3
from fastapi import APIRouter, Request

router = APIRouter()

# [SAST] 하드코딩된 시크릿 키
SECRET_KEY = "super_secret_key_12345"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "admin123!"


# [SAST] SQL Injection
@router.get("/users/search")
def search_user(username: str):
    conn = sqlite3.connect("data/ecommerce.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return {"users": results}


# [SAST] OS Command Injection
@router.get("/system/ping")
def ping_host(host: str):
    result = os.popen("ping -c 1 " + host).read()
    return {"output": result}


# [SAST] Command Injection via subprocess
@router.post("/system/exec")
def exec_command(cmd: str):
    output = subprocess.check_output(cmd, shell=True)
    return {"result": output.decode()}


# [SAST] Path Traversal
@router.get("/files/read")
def read_file(filepath: str):
    with open(filepath, "r") as f:
        content = f.read()
    return {"content": content}


# [SAST] XSS (reflected)
@router.get("/greet")
def greet(name: str):
    html = f"<h1>Hello {name}</h1>"
    return {"html": html}


# [SAST] 취약한 해시 알고리즘 (MD5)
@router.post("/auth/hash")
def hash_password(password: str):
    hashed = hashlib.md5(password.encode()).hexdigest()
    return {"hash": hashed}


# [SAST] 취약한 랜덤 생성
import random
@router.get("/token/generate")
def generate_token():
    token = str(random.randint(100000, 999999))
    return {"token": token}


# [SAST] SSRF
import urllib.request
@router.get("/fetch")
def fetch_url(url: str):
    response = urllib.request.urlopen(url)
    return {"data": response.read().decode()[:500]}


# [SAST] 안전하지 않은 역직렬화
import pickle
import base64
@router.post("/deserialize")
def deserialize_data(data: str):
    obj = pickle.loads(base64.b64decode(data))
    return {"result": str(obj)}
