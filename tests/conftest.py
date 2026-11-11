"""测试夹具：每个测试使用独立的临时 SQLite 数据库。"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

# 确保可以导入工作区中的 app 包（隔离环境运行时也能找到）
_WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _WORKSPACE not in sys.path:
    sys.path.insert(0, _WORKSPACE)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_device_auth.db"
    monkeypatch.setenv("DEVICE_AUTH_DB", str(db_path))
    monkeypatch.setenv("SERVER_PEPPER", "test-pepper-fixed")
    monkeypatch.setenv("AUTH_TTL_SECONDS", "300")

    # 配置使用 lru_cache，需要重新加载以读取新环境变量
    from app import config, db, main, security, store  # noqa: F401

    importlib.reload(config)
    importlib.reload(security)
    importlib.reload(db)
    importlib.reload(store)
    importlib.reload(main)

    with TestClient(main.app) as c:
        yield c

    assert db_path.exists()


@pytest.fixture()
def short_ttl_client(tmp_path, monkeypatch):
    """有效期 1 秒的客户端，用于过期测试。"""
    db_path = tmp_path / "test_short_ttl.db"
    monkeypatch.setenv("DEVICE_AUTH_DB", str(db_path))
    monkeypatch.setenv("SERVER_PEPPER", "test-pepper-fixed")
    monkeypatch.setenv("AUTH_TTL_SECONDS", "1")

    from app import config, db, main, security, store  # noqa: F401

    importlib.reload(config)
    importlib.reload(security)
    importlib.reload(db)
    importlib.reload(store)
    importlib.reload(main)

    with TestClient(main.app) as c:
        yield c


def make_authorization(c, client_id="term-1", device_name="巡检终端-01"):
    r = c.post("/api/device/authorize", json={"client_id": client_id, "device_name": device_name})
    assert r.status_code == 200
    return r.json()
