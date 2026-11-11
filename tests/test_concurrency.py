"""并发测试：批准/拒绝/轮询/领取在多线程下必须等价于串行执行。"""

from __future__ import annotations

import sqlite3
import threading

from tests.conftest import make_authorization


def test_concurrent_decisions_only_one_succeeds(client):
    results = []
    errors = []
    lock = threading.Lock()

    def worker(decision):
        try:
            r = client.post(
                "/api/admin/decide",
                json={
                    "user_code": auth["user_code"],
                    "approver": f"admin-{decision}",
                    "decision": decision,
                },
            )
            with lock:
                results.append((decision, r.status_code, r.json().get("status") or r.json().get("error")))
        except Exception as exc:  # pragma: no cover
            with lock:
                errors.append(exc)

    # 建立 5 个授权，每个被两个管理员同时做相反决策
    for i in range(5):
        auth = make_authorization(client, client_id=f"term-conc-{i}")
        t1 = threading.Thread(target=worker, args=("approve",))
        t2 = threading.Thread(target=worker, args=("deny",))
        t1.start(); t2.start(); t1.join(); t2.join()

    assert not errors
    # 每个授权恰好一次成功（200），另一次 409
    success = [r for r in results if r[1] == 200]
    conflicts = [r for r in results if r[1] == 409]
    assert len(success) == 5
    assert len(conflicts) == 5
    assert all(r[2] == "not_pending" for r in conflicts)

    # 数据库中不存在重复决策痕迹：每条记录状态唯一且 decided_by 只有一人
    conn = sqlite3.connect(_db_path(client))
    rows = conn.execute("SELECT status, decided_by FROM authorizations").fetchall()
    assert len(rows) == 5
    assert all(r[1].startswith("admin-") for r in rows)


def _db_path(c):
    from app import config

    return config.get_settings().db_path


def test_concurrent_claim_only_one_token(client):
    auth = make_authorization(client, client_id="term-claim")
    client.post(
        "/api/admin/decide",
        json={"user_code": auth["user_code"], "approver": "sec-admin-zhang", "decision": "approve"},
    )

    outcomes = []
    barrier = threading.Barrier(8)
    lock = threading.Lock()

    def claim():
        barrier.wait()
        r = client.post(
            "/api/device/token", json={"client_id": "term-claim", "device_code": auth["device_code"]}
        )
        with lock:
            outcomes.append((r.status_code, r.json()))

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    success = [o for o in outcomes if o[0] == 200]
    rejected = [o for o in outcomes if o[0] == 409]
    assert len(success) == 1
    assert len(rejected) == 7
    assert all(o[1]["error"] == "token_already_claimed" for o in rejected)

    # 令牌表恰好一行，授权的 claimed_at 已置位（状态与签发一并生效）
    conn = sqlite3.connect(_db_path(client))
    assert conn.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 1
    row = conn.execute("SELECT status, claimed_at, decided_by FROM authorizations").fetchone()
    assert row[0] == "approved"
    assert row[1] is not None
    assert row[2] == "sec-admin-zhang"

    # 唯一令牌可以通过身份接口
    token = success[0][1]["access_token"]
    r = client.get("/api/identity", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["approver"] == "sec-admin-zhang"


def test_concurrent_polls_never_block_writes(client):
    """大量轮询与一次批准并发：轮询结果只可能是 pending 或 approved，且最终一致。"""
    auth = make_authorization(client, client_id="term-poll")
    seen = []
    stop = threading.Event()
    lock = threading.Lock()

    def poller():
        while not stop.is_set():
            r = client.post(
                "/api/device/poll",
                json={"client_id": "term-poll", "device_code": auth["device_code"]},
            )
            with lock:
                seen.append(r.json()["status"])

    pollers = [threading.Thread(target=poller) for _ in range(4)]
    for t in pollers:
        t.start()

    approver = threading.Thread(
        target=lambda: client.post(
            "/api/admin/decide",
            json={"user_code": auth["user_code"], "approver": "sec-admin-li", "decision": "approve"},
        )
    )
    approver.start()
    approver.join()
    stop.set()
    for t in pollers:
        t.join()

    assert set(seen) <= {"pending", "approved"}
    assert "approved" in seen
    # 一旦出现 approved，后面不允许再回退到 pending
    first_approved = seen.index("approved")
    assert all(s == "approved" for s in seen[first_approved:])
