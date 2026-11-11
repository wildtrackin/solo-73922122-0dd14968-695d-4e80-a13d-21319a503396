"""授权与令牌的持久化操作（状态机）。

状态迁移：
    pending ──批准──> approved ──领取──> approved(claimed_at 置位, 写 token)
       │                │
       ├──拒绝──> denied │
       └──到期──> expired
批准/拒绝/领取/领取发令牌都在 IMMEDIATE 事务中完成，并发调用等价串行。
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from typing import Any

from . import security
from .config import get_settings
from .db import read_cursor, write_transaction


class AuthError(Exception):
    def __init__(self, code: str, message: str, http_status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


# ---------------------------------------------------------------------------
# 行对象与视图
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Authorization:
    id: int
    client_id: str
    device_name: str
    status: str
    created_at: int
    expires_at: int
    decided_at: int | None
    decided_by: str | None
    claimed_at: int | None
    user_code_masked: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "client_id": self.client_id,
            "device_name": self.device_name,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "claimed_at": self.claimed_at,
            "user_code_masked": self.user_code_masked,
        }


def _effective_status(row: Any, now: int | None = None) -> str:
    """pending 且超过有效期时，对外视为 expired。"""
    now = now if now is not None else int(time.time())
    if row["status"] == "pending" and now >= row["expires_at"]:
        return "expired"
    return row["status"]


def _to_view(row: Any, now: int | None = None) -> Authorization:
    now = now if now is not None else int(time.time())
    return Authorization(
        id=row["id"],
        client_id=row["client_id"],
        device_name=row["device_name"],
        status=_effective_status(row, now),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        decided_at=row["decided_at"],
        decided_by=row["decided_by"],
        claimed_at=row["claimed_at"],
        user_code_masked=row["user_code_masked"],
    )


# ---------------------------------------------------------------------------
# 终端侧
# ---------------------------------------------------------------------------


def create_authorization(client_id: str, device_name: str) -> dict[str, Any]:
    """终端发起：生成随机设备码、人工短码与有效期，全部敏感码只存哈希。"""
    settings = get_settings()
    now = int(time.time())

    # 哈希冲突概率可忽略；若 UNIQUE 冲突则整体换码并在新事务中重试
    for _ in range(3):
        device_code = security.generate_device_code()
        user_code = security.generate_user_code()
        try:
            with write_transaction() as cur:
                cur.execute(
                    """
                    INSERT INTO authorizations (
                        client_id, device_name, device_code_hash, user_code_hash,
                        user_code_masked, status, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        client_id,
                        device_name,
                        security.hash_value(device_code),
                        security.hash_value(user_code),
                        security.mask_user_code(user_code),
                        now,
                        now + settings.ttl_seconds,
                    ),
                )
            break
        except Exception as exc:  # pragma: no cover - 哈希冲突极罕见
            if "UNIQUE" in str(exc):
                continue
            raise
    else:  # pragma: no cover
        raise AuthError("server_error", "创建设备授权失败，请重试", 500)

    return {
        "client_id": client_id,
        "device_name": device_name,
        "device_code": device_code,
        "user_code": user_code,
        "created_at": now,
        "expires_at": now + settings.ttl_seconds,
        "expires_in": settings.ttl_seconds,
        "interval": settings.poll_interval,
    }


def _find_by_device_code(cur: Any, device_code: str) -> Any:
    cur.execute(
        "SELECT * FROM authorizations WHERE device_code_hash = ?",
        (security.hash_value(device_code),),
    )
    return cur.fetchone()


def poll_authorization(client_id: str, device_code: str) -> dict[str, Any]:
    """终端轮询。client_id 不匹配或设备码不存在一律返回 invalid_device，
    不向调用方泄露授权是否存在，也不允许查询/影响他人授权。"""
    with read_cursor() as cur:
        row = _find_by_device_code(cur, device_code)
        if row is None or not hmac_safe_equal(row["client_id"], client_id):
            raise AuthError("invalid_device", "设备码无效或与客户端身份不匹配", 404)

        now = int(time.time())
        status = _effective_status(row, now)
        result = {
            "status": status,
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "claimed_at": row["claimed_at"],
            "decided_by": row["decided_by"],
        }
        # 惰性过期落库，保证状态持久且后续操作一致
        if row["status"] == "pending" and status == "expired":
            _persist_expiry(row["id"])
        return result


def _persist_expiry(authorization_id: int) -> None:
    with write_transaction() as cur:
        cur.execute(
            "UPDATE authorizations SET status = 'expired' "
            "WHERE id = ? AND status = 'pending'",
            (authorization_id,),
        )


def claim_token(client_id: str, device_code: str) -> dict[str, Any]:
    """领取令牌：批准后仅可领取一次，状态置位与令牌插入同一事务提交。"""
    now = int(time.time())

    # 先在事务外读取并固化过期状态，避免异常回滚丢掉过期更新
    with read_cursor() as cur:
        row = _find_by_device_code(cur, device_code)
        if row is None or not hmac_safe_equal(row["client_id"], client_id):
            raise AuthError("invalid_device", "设备码无效或与客户端身份不匹配", 404)
        pre_status = _effective_status(row, now)
        if pre_status == "expired":
            _persist_expiry(row["id"])
            raise AuthError("authorization_expired", "设备授权已过期，无法领取令牌", 403)

    with write_transaction() as cur:
        # 加锁后重新读取，防止两次读取之间状态被其他进程改变
        row = _find_by_device_code(cur, device_code)
        status = _effective_status(row, now)
        if status == "pending":
            raise AuthError("authorization_pending", "设备授权尚未被批准", 403)
        if status == "denied":
            raise AuthError("access_denied", "设备授权已被拒绝，无法领取令牌", 403)
        if status == "expired":
            raise AuthError("authorization_expired", "设备授权已过期，无法领取令牌", 403)

        if row["claimed_at"] is not None:
            raise AuthError("token_already_claimed", "该授权的令牌已被领取，无法重复领取", 409)

        approver = row["decided_by"]
        access_token = security.generate_access_token()
        cur.execute(
            """
            INSERT INTO tokens (authorization_id, client_id, token_hash, approver, issued_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (row["id"], client_id, security.hash_value(access_token), approver, now),
        )
        cur.execute(
            "UPDATE authorizations SET claimed_at = ? WHERE id = ? AND claimed_at IS NULL",
            (now, row["id"]),
        )
        if cur.rowcount != 1:  # 并发下已被领取
            raise AuthError("token_already_claimed", "该授权的令牌已被领取，无法重复领取", 409)

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "approver": approver,
            "issued_at": now,
            "client_id": client_id,
            "device_name": row["device_name"],
        }


def resolve_token(access_token: str) -> dict[str, str]:
    """凭令牌换取身份信息；令牌哈希查不到即无效。"""
    with read_cursor() as cur:
        cur.execute(
            """
            SELECT t.approver AS approver, t.issued_at AS issued_at,
                   a.client_id AS client_id, a.device_name AS device_name,
                   a.id AS authorization_id
            FROM tokens t JOIN authorizations a ON a.id = t.authorization_id
            WHERE t.token_hash = ?
            """,
            (security.hash_value(access_token),),
        )
        row = cur.fetchone()
        if row is None:
            raise AuthError("invalid_token", "访问令牌无效", 401)
        return dict(row)


# ---------------------------------------------------------------------------
# 人工审批侧（网页）
# ---------------------------------------------------------------------------


def list_authorizations() -> list[dict[str, Any]]:
    with read_cursor() as cur:
        cur.execute("SELECT * FROM authorizations ORDER BY id DESC")
        rows = cur.fetchall()
    now = int(time.time())
    return [_to_view(row, now).to_dict() for row in rows]


def find_by_user_code(user_code: str) -> dict[str, Any]:
    """人工输入短码核对设备；短码错误同样不泄露任何授权信息。"""
    with read_cursor() as cur:
        cur.execute(
            "SELECT * FROM authorizations WHERE user_code_hash = ?",
            (security.hash_value(user_code.strip().upper()),),
        )
        row = cur.fetchone()
    if row is None:
        raise AuthError("invalid_user_code", "人工短码不存在，请核对后重试", 404)
    now = int(time.time())
    view = _to_view(row, now).to_dict()
    return view


def decide(user_code: str, approver: str, decision: str) -> dict[str, Any]:
    """批准或拒绝；只有待确认项可操作，过期即不可批准。"""
    if decision not in ("approve", "deny"):
        raise AuthError("invalid_decision", "决策只能是 approve 或 deny", 422)
    code = user_code.strip().upper()
    now = int(time.time())

    # 事务外读取：短码不存在直接返回；过期先独立固化，避免异常回滚
    with read_cursor() as cur:
        cur.execute(
            "SELECT * FROM authorizations WHERE user_code_hash = ?",
            (security.hash_value(code),),
        )
        row = cur.fetchone()
    if row is None:
        raise AuthError("invalid_user_code", "人工短码不存在，请核对后重试", 404)
    if _effective_status(row, now) == "expired":
        _persist_expiry(row["id"])
        raise AuthError("authorization_expired", "该授权已超过有效期，不可再操作", 403)

    with write_transaction() as cur:
        # 拿写锁后重新读取，串行化并发决策
        cur.execute(
            "SELECT * FROM authorizations WHERE user_code_hash = ?",
            (security.hash_value(code),),
        )
        row = cur.fetchone()
        effective = _effective_status(row, now)
        if effective == "expired":
            raise AuthError("authorization_expired", "该授权已超过有效期，不可再操作", 403)
        if effective != "pending":
            raise AuthError(
                "not_pending",
                f"该授权当前状态为 {effective}，仅待确认项可以批准或拒绝",
                409,
            )

        new_status = "approved" if decision == "approve" else "denied"
        cur.execute(
            "UPDATE authorizations SET status = ?, decided_at = ?, decided_by = ? "
            "WHERE id = ? AND status = 'pending'",
            (new_status, now, approver, row["id"]),
        )
        if cur.rowcount != 1:  # 并发下被其他管理员先处理
            raise AuthError("not_pending", "该授权已被其他管理员处理", 409)

        cur.execute("SELECT * FROM authorizations WHERE id = ?", (row["id"],))
        updated = cur.fetchone()
        return _to_view(updated, now).to_dict()


def hmac_safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
