"""设备授权主流程与安全规则测试。"""

from __future__ import annotations

import sqlite3
import time

from tests.conftest import make_authorization


def test_authorize_returns_codes_and_ttl(client):
    data = make_authorization(client)
    assert data["expires_in"] == 300
    assert data["expires_at"] - data["created_at"] == 300
    assert len(data["device_code"]) >= 40
    assert len(data["user_code"]) == 6
    assert data["user_code"].isalnum()


def test_full_approve_claim_identity_flow(client):
    auth = make_authorization(client, client_id="term-9", device_name="机房A终端")

    # 初始轮询为 pending
    r = client.post("/api/device/poll", json={"client_id": "term-9", "device_code": auth["device_code"]})
    assert r.status_code == 200
    assert r.json()["status"] == "pending"

    # 批准前不能领取
    r = client.post("/api/device/token", json={"client_id": "term-9", "device_code": auth["device_code"]})
    assert r.status_code == 403
    assert r.json()["error"] == "authorization_pending"

    # 人工按短码核对并批准
    r = client.post("/api/admin/find", json={"user_code": auth["user_code"]})
    assert r.status_code == 200
    assert r.json()["device_name"] == "机房A终端"

    r = client.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-li", "decision": "approve"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "approved"
    assert r.json()["decided_by"] == "sec-admin-li"

    # 终端轮询看到 approved，然后领取令牌
    r = client.post("/api/device/poll", json={"client_id": "term-9", "device_code": auth["device_code"]})
    assert r.json()["status"] == "approved"

    r = client.post("/api/device/token", json={"client_id": "term-9", "device_code": auth["device_code"]})
    assert r.status_code == 200
    token_resp = r.json()
    assert token_resp["token_type"] == "Bearer"
    assert token_resp["approver"] == "sec-admin-li"
    access_token = token_resp["access_token"]

    # 令牌只能领取一次
    r = client.post("/api/device/token", json={"client_id": "term-9", "device_code": auth["device_code"]})
    assert r.status_code == 409
    assert r.json()["error"] == "token_already_claimed"

    # 凭令牌调用身份接口
    r = client.get("/api/identity", headers={"Authorization": f"Bearer {access_token}"})
    assert r.status_code == 200
    identity = r.json()
    assert identity["client_id"] == "term-9"
    assert identity["approver"] == "sec-admin-li"
    assert identity["device_name"] == "机房A终端"

    # 无令牌 / 错令牌被拒
    assert client.get("/api/identity").status_code == 401
    r = client.get("/api/identity", headers={"Authorization": "Bearer nope-not-a-token"})
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_token"


def test_deny_flow_is_terminal(client):
    auth = make_authorization(client, client_id="term-2")
    r = client.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-zhang", "decision": "deny"},
    )
    assert r.json()["status"] == "denied"

    r = client.post("/api/device/poll", json={"client_id": "term-2", "device_code": auth["device_code"]})
    assert r.json()["status"] == "denied"

    r = client.post("/api/device/token", json={"client_id": "term-2", "device_code": auth["device_code"]})
    assert r.status_code == 403
    assert r.json()["error"] == "access_denied"

    # 拒绝后不可再批准
    r = client.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-zhang", "decision": "approve"},
    )
    assert r.status_code == 409
    assert r.json()["error"] == "not_pending"


def test_wrong_client_cannot_query_or_change(client):
    auth = make_authorization(client, client_id="real-client")

    # 错客户端轮询：与设备码不存在同样的错误，不泄露信息
    r = client.post("/api/device/poll", json={"client_id": "attacker", "device_code": auth["device_code"]})
    assert r.status_code == 404
    assert r.json()["error"] == "invalid_device"

    # 错客户端不能领取
    r = client.post("/api/device/token", json={"client_id": "attacker", "device_code": auth["device_code"]})
    assert r.status_code == 404
    assert r.json()["error"] == "invalid_device"

    # 正确客户端仍可正常轮询，状态未受影响
    r = client.post("/api/device/poll", json={"client_id": "real-client", "device_code": auth["device_code"]})
    assert r.status_code == 200
    assert r.json()["status"] == "pending"

    # 不存在的设备码同样错误
    r = client.post("/api/device/poll", json={"client_id": "real-client", "device_code": "x" * 43})
    assert r.status_code == 404


def test_only_pending_can_be_decided(client):
    auth = make_authorization(client, client_id="term-3")
    client.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-zhang", "decision": "approve"},
    )
    # 已批准不能拒绝
    r = client.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-li", "decision": "deny"},
    )
    assert r.status_code == 409
    assert r.json()["error"] == "not_pending"

    # 错误短码
    r = client.post("/api/admin/find", json={"user_code": "ZZZZZZ"})
    assert r.status_code == 404
    assert r.json()["error"] == "invalid_user_code"


def test_expired_cannot_be_approved_or_claimed(short_ttl_client):
    c = short_ttl_client
    auth = make_authorization(c, client_id="term-exp")
    time.sleep(1.2)

    # 轮询显示 expired
    r = c.post("/api/device/poll", json={"client_id": "term-exp", "device_code": auth["device_code"]})
    assert r.json()["status"] == "expired"

    # 过期不可批准
    r = c.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-zhang", "decision": "approve"},
    )
    assert r.status_code == 403
    assert r.json()["error"] == "authorization_expired"

    # 过期不可领取
    r = c.post("/api/device/token", json={"client_id": "term-exp", "device_code": auth["device_code"]})
    assert r.status_code == 403
    assert r.json()["error"] == "authorization_expired"

    # 状态已固化为 expired，且不可恢复（即使此前没有调用过轮询）
    r = c.get("/api/admin/authorizations")
    assert r.json()["items"][0]["status"] == "expired"
    r = c.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-zhang", "decision": "deny"},
    )
    assert r.status_code == 403


def test_expiry_persisted_without_prior_poll(short_ttl_client):
    """不经过轮询，直接批准/领取过期授权：过期状态同样要落库固化。"""
    c = short_ttl_client
    auth = make_authorization(c, client_id="term-exp-nopoll")
    time.sleep(1.2)

    r = c.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-zhang", "decision": "approve"},
    )
    assert r.status_code == 403
    items = c.get("/api/admin/authorizations").json()["items"]
    assert items[0]["status"] == "expired"


def test_sensitive_values_only_stored_hashed(client, tmp_path):
    auth = make_authorization(client, client_id="term-hash")
    client.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-zhang", "decision": "approve"},
    )
    token = client.post(
        "/api/device/token", json={"client_id": "term-hash", "device_code": auth["device_code"]}
    ).json()["access_token"]

    # 直接检查 SQLite 文件与 WAL 原始字节，不允许出现明文
    db_files = list(tmp_path.glob("test_device_auth.db*"))
    blob = b"".join(p.read_bytes() for p in db_files)
    assert auth["device_code"].encode() not in blob
    assert auth["user_code"].encode() not in blob
    assert token.encode() not in blob

    # 数据库中保存的是 64 位十六进制哈希
    db_path = next(tmp_path.glob("test_device_auth.db"))
    conn = sqlite3.connect(db_path)
    auth_row = conn.execute("SELECT device_code_hash, user_code_hash FROM authorizations").fetchone()
    for value in auth_row:
        assert len(value) == 64 and int(value, 16) is not None
    token_hash = conn.execute("SELECT token_hash FROM tokens").fetchone()[0]
    assert len(token_hash) == 64


def test_persistence_across_app_restart(client, tmp_path):
    auth = make_authorization(client, client_id="term-persist")
    client.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-li", "decision": "approve"},
    )
    token_resp = client.post(
        "/api/device/token", json={"client_id": "term-persist", "device_code": auth["device_code"]}
    ).json()

    # 模拟重启：新建一个指向同一数据库文件的 TestClient
    from fastapi.testclient import TestClient

    from app import main as main_module

    with TestClient(main_module.app) as c2:
        r = c2.post("/api/device/poll", json={"client_id": "term-persist", "device_code": auth["device_code"]})
        assert r.json()["status"] == "approved"
        assert r.json()["claimed_at"] is not None
        # 重启后旧令牌仍然有效
        r = c2.get("/api/identity", headers={"Authorization": f"Bearer {token_resp['access_token']}"})
        assert r.status_code == 200
        assert r.json()["approver"] == "sec-admin-li"
        # 重启后仍不能重复领取
        r = c2.post(
            "/api/device/token", json={"client_id": "term-persist", "device_code": auth["device_code"]}
        )
        assert r.status_code == 409


def test_admin_list_masks_user_code(client):
    auth = make_authorization(client)
    r = client.get("/api/admin/authorizations")
    items = r.json()["items"]
    assert len(items) == 1
    masked = items[0]["user_code_masked"]
    assert "*" in masked
    # 仅保留前两位，其余打码；完整短码不得出现在列表接口
    assert masked == auth["user_code"][:2] + "*" * (len(auth["user_code"]) - 2)
    assert auth["user_code"] not in r.text
    # find 接口同样不回显完整短码
    r = client.post("/api/admin/find", json={"user_code": auth["user_code"]})
    assert auth["user_code"] not in r.text


def test_static_homepage_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "设备授权" in r.text
    r = client.get("/static/app.js")
    assert r.status_code == 200
