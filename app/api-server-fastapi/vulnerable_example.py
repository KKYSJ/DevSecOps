"""
보안 취약점 테스트용 코드 (SAST 동시탐지 대상)
- SonarQube + Semgrep 양쪽에서 탐지되도록 설계
- SecureFlow 파이프라인 검증 목적
"""

import os
import hashlib
import subprocess
import sqlite3
from fastapi import APIRouter, Request

router = APIRouter()

# ── 1. SQL Injection (CWE-89) ──────────────────────────
# SonarQube: pythonsecurity:S3649 / Semgrep: python.lang.security.audit.sqli
@router.get("/users/search")
def search_user(username: str):
    conn = sqlite3.connect("data/app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return {"users": cursor.fetchall()}


# ── 2. OS Command Injection (CWE-78) ──────────────────
# SonarQube: python:S5131 / Semgrep: python.lang.security.audit.dangerous-system-call
@router.get("/system/ping")
def ping_host(host: str):
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return {"output": output.decode()}


# ── 3. Path Traversal (CWE-22) ────────────────────────
# SonarQube: python:S5144 / Semgrep: python.lang.security.audit.path-traversal
@router.get("/files/read")
def read_file(filepath: str):
    with open(filepath, "r") as f:
        return {"content": f.read()}


# ── 4. Hardcoded Secret (CWE-798) ─────────────────────
# SonarQube: python:S2068 / Semgrep: python.lang.security.audit.hardcoded-password
DB_PASSWORD = "admin123!"
SECRET_KEY = "super_secret_key_12345"


# ── 5. Weak Hash - MD5 (CWE-327) ─────────────────────
# SonarQube: python:S4790 / Semgrep: python.lang.security.insecure-hash-algorithms
@router.post("/auth/hash")
def hash_password(password: str):
    return {"hash": hashlib.md5(password.encode()).hexdigest()}
