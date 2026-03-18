"""
데이터베이스 추상화 모듈
- SQLite (로컬 개발)와 MySQL (AWS RDS) 모두 지원
- query() 함수로 SQL 실행을 통일된 인터페이스로 제공
"""

import os
import json
from pathlib import Path
from typing import Any

from app.config.settings import settings

# 데이터베이스 연결 객체
_sqlite_db = None
_mysql_pool = None


async def init_database():
    """
    데이터베이스 초기화
    - SQLite: aiosqlite
    - MySQL: aiomysql 커넥션 풀
    """
    global _sqlite_db, _mysql_pool

    if settings.DB_TYPE == "sqlite":
        import aiosqlite

        # data 디렉토리 생성
        settings.DATA_DIR.mkdir(parents=True, exist_ok=True)

        _sqlite_db = await aiosqlite.connect(str(settings.DB_PATH))
        _sqlite_db.row_factory = aiosqlite.Row

        # WAL 모드 활성화 (성능 향상)
        await _sqlite_db.execute("PRAGMA journal_mode=WAL")

        # 테이블 생성
        await _create_tables_sqlite()
        print("[DB] SQLite 데이터베이스 초기화 완료 (aiosqlite)")

    elif settings.DB_TYPE == "mysql":
        import aiomysql

        _mysql_pool = await aiomysql.create_pool(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            user=settings.DB_USER,
            password=settings.DB_PASSWORD,
            db=settings.DB_NAME,
            charset="utf8mb4",
            autocommit=True,
            minsize=1,
            maxsize=10,
        )

        # 테이블 생성
        await _create_tables_mysql()
        print("[DB] MySQL 데이터베이스 초기화 완료")

    else:
        raise ValueError(f"지원하지 않는 DB_TYPE: {settings.DB_TYPE}")


async def close_database():
    """데이터베이스 연결 종료"""
    global _sqlite_db, _mysql_pool

    if _sqlite_db:
        await _sqlite_db.close()
        _sqlite_db = None

    if _mysql_pool:
        _mysql_pool.close()
        await _mysql_pool.wait_closed()
        _mysql_pool = None


async def _create_tables_sqlite():
    """SQLite 테이블 생성"""
    tables = [
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price INTEGER NOT NULL,
            image_url TEXT,
            category TEXT,
            stock INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS cart_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )""",
        """CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total_amount INTEGER NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""",
        """CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            price INTEGER NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )""",
        """CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            rating INTEGER NOT NULL,
            content TEXT,
            image_urls TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""",
    ]

    for sql in tables:
        await _sqlite_db.execute(sql)
    await _sqlite_db.commit()


async def _create_tables_mysql():
    """MySQL 테이블 생성"""
    tables = [
        """CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(100) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            price INT NOT NULL,
            image_url VARCHAR(500),
            category VARCHAR(100),
            stock INT DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS cart_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            product_id INT NOT NULL,
            quantity INT DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )""",
        """CREATE TABLE IF NOT EXISTS orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            total_amount INT NOT NULL,
            status VARCHAR(50) DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""",
        """CREATE TABLE IF NOT EXISTS order_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            order_id INT NOT NULL,
            product_id INT NOT NULL,
            product_name VARCHAR(255) NOT NULL,
            quantity INT NOT NULL,
            price INT NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )""",
        """CREATE TABLE IF NOT EXISTS reviews (
            id INT AUTO_INCREMENT PRIMARY KEY,
            product_id INT NOT NULL,
            user_id INT NOT NULL,
            user_name VARCHAR(100) NOT NULL,
            rating INT NOT NULL,
            content TEXT,
            image_urls TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""",
    ]

    async with _mysql_pool.acquire() as conn:
        async with conn.cursor() as cur:
            for sql in tables:
                await cur.execute(sql)


async def query(sql: str, params: list = None) -> Any:
    """
    SQL 쿼리 실행 (통합 인터페이스)
    - SELECT: List[dict] 반환
    - INSERT: {"insertId": id, "changes": count} 반환
    - UPDATE/DELETE: {"changes": count} 반환

    :param sql: SQL 쿼리 (? 플레이스홀더 사용)
    :param params: 파라미터 리스트
    :returns: 쿼리 결과
    """
    if params is None:
        params = []

    if settings.DB_TYPE == "sqlite":
        return await _query_sqlite(sql, params)
    else:
        return await _query_mysql(sql, params)


async def _query_sqlite(sql: str, params: list) -> Any:
    """SQLite 쿼리 실행"""
    trimmed = sql.strip().upper()

    if trimmed.startswith("SELECT") or trimmed.startswith("WITH"):
        cursor = await _sqlite_db.execute(sql, params)
        columns = [description[0] for description in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    elif trimmed.startswith("INSERT"):
        cursor = await _sqlite_db.execute(sql, params)
        await _sqlite_db.commit()
        return {"insertId": cursor.lastrowid, "changes": cursor.rowcount}

    else:
        cursor = await _sqlite_db.execute(sql, params)
        await _sqlite_db.commit()
        return {"changes": cursor.rowcount}


async def _query_mysql(sql: str, params: list) -> Any:
    """MySQL 쿼리 실행"""
    import aiomysql

    trimmed = sql.strip().upper()

    # MySQL은 %s 플레이스홀더를 사용하므로 ? 를 %s 로 변환
    sql_mysql = sql.replace("?", "%s")

    async with _mysql_pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(sql_mysql, params)

            if trimmed.startswith("SELECT") or trimmed.startswith("WITH"):
                rows = await cur.fetchall()
                return list(rows)

            elif trimmed.startswith("INSERT"):
                return {"insertId": cur.lastrowid, "changes": cur.rowcount}

            else:
                return {"changes": cur.rowcount}
