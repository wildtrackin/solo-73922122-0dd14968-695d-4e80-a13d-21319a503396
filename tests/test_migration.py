"""旧版数据库（无 user_code_masked 列）的启动迁移测试。"""

from __future__ import annotations

import importlib
import sqlite3


def test_init_db_migrates_legacy_schema(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    monkeypatch.setenv("DEVICE_AUTH_DB", str(db_path))
    monkeypatch.setenv("SERVER_PEPPER", "test-pepper-fixed")

    # 手工构造旧版表结构（缺少 user_code_masked 列）并写入一条历史授权
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE authorizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT NOT NULL,
            device_name TEXT NOT NULL,
            device_code_hash TEXT NOT NULL UNIQUE,
            user_code_hash TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            decided_at INTEGER,
            decided_by TEXT,
            claimed_at INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            authorization_id INTEGER NOT NULL UNIQUE,
            client_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            approver TEXT NOT NULL,
            issued_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO authorizations (client_id, device_name, device_code_hash, user_code_hash, "
        "status, created_at, expires_at) VALUES ('legacy-term', '旧设备', 'h1', 'h2', 'pending', 1, 9999999999)"
    )
    conn.commit()
    conn.close()

    from app import config, db, main, security, store  # noqa: F401

    importlib.reload(config)
    importlib.reload(security)
    importlib.reload(db)
    importlib.reload(store)
    importlib.reload(main)

    db.init_db()  # 不应报错，且历史数据保留

    cols = {row[1] for row in sqlite3.connect(db_path).execute("PRAGMA table_info(authorizations)")}
    assert "user_code_masked" in cols

    from fastapi.testclient import TestClient

    with TestClient(main.app) as c:
        items = c.get("/api/admin/authorizations").json()["items"]
        assert len(items) == 1
        assert items[0]["client_id"] == "legacy-term"
        # 迁移产生的默认空掩码不影响新流程
        auth = c.post(
            "/api/device/authorize", json={"client_id": "new-term", "device_name": "新设备"}
        ).json()
        items = c.get("/api/admin/authorizations").json()["items"]
        new_item = next(i for i in items if i["client_id"] == "new-term")
        assert new_item["user_code_masked"] == auth["user_code"][:2] + "****"
