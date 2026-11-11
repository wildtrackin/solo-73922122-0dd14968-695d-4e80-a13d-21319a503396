"""SQLite 连接与建表。

多个 uvicorn 进程共享同一个数据库文件：
- WAL 模式允许读写并发；
- 所有写操作在 IMMEDIATE 事务中完成，天然串行化；
- 设备码/令牌等敏感字段仅存 HMAC 哈希。
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from .config import get_settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS authorizations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id          TEXT NOT NULL,
    device_name        TEXT NOT NULL,
    device_code_hash   TEXT NOT NULL UNIQUE,
    user_code_hash     TEXT NOT NULL UNIQUE,
    user_code_masked   TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    decided_at         INTEGER,
    decided_by         TEXT,
    claimed_at         INTEGER
);

CREATE TABLE IF NOT EXISTS tokens (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    authorization_id  INTEGER NOT NULL UNIQUE,
    client_id         TEXT NOT NULL,
    token_hash        TEXT NOT NULL UNIQUE,
    approver          TEXT NOT NULL,
    issued_at         INTEGER NOT NULL,
    FOREIGN KEY (authorization_id) REFERENCES authorizations (id)
);
"""

# 旧版本数据库的增量迁移列（保留既有授权数据）
_MIGRATION_COLUMNS = ("user_code_masked TEXT NOT NULL DEFAULT ''",)


def init_db() -> None:
    """进程启动时执行，确保表结构存在（重启后数据保留）。"""
    conn = connect()
    try:
        conn.executescript(_SCHEMA)
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(authorizations)")}
        for column_def in _MIGRATION_COLUMNS:
            column_name = column_def.split()[0]
            if column_name not in existing_cols:
                conn.execute(f"ALTER TABLE authorizations ADD COLUMN {column_def}")
    finally:
        conn.close()


def connect() -> sqlite3.Connection:
    settings = get_settings()
    db_dir = os.path.dirname(settings.db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(
        settings.db_path,
        timeout=30.0,
        isolation_level=None,  # autocommit，事务由 helper 显式控制
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextmanager
def read_cursor() -> Iterator[sqlite3.Cursor]:
    conn = connect()
    try:
        yield conn.cursor()
    finally:
        conn.close()


@contextmanager
def write_transaction() -> Iterator[sqlite3.Cursor]:
    """IMMEDIATE 事务：进入即拿写锁，并发写在进程/数据库层面等价串行执行。

    配合 busy_timeout，多进程并发批准/拒绝/领取会排队而不是报错。
    """
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn.cursor()
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
