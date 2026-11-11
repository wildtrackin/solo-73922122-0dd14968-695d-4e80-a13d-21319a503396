"""随机码生成与哈希工具。

设备码、人工短码、令牌在数据库中只保存 HMAC-SHA256 摘要，
明文仅通过接口响应一次性返回给提交方。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from .config import get_settings

# 去掉易混淆字符（I/L/O/0/1），方便人工录入短码
_USER_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_USER_CODE_LENGTH = 6


def _pepper() -> bytes:
    return get_settings().server_pepper.encode("utf-8")


def hash_value(value: str) -> str:
    """对敏感码值做带服务器盐的 HMAC-SHA256，返回十六进制摘要。"""
    return hmac.new(_pepper(), value.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_value(value: str, expected_digest: str) -> bool:
    return hmac.compare_digest(hash_value(value), expected_digest)


def generate_device_code() -> str:
    """终端持有的随机设备码，约 43 个 URL 安全字符。"""
    return secrets.token_urlsafe(32)


def generate_user_code() -> str:
    """人工短码：6 位大写字母数字，便于在网页中手工输入。"""
    return "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(_USER_CODE_LENGTH))


def generate_access_token() -> str:
    """批准后领取的访问令牌。"""
    return secrets.token_urlsafe(32)


def mask_user_code(user_code: str) -> str:
    """列表页只展示脱敏短码，完整值需人工输入后查询。"""
    if len(user_code) <= 2:
        return "**"
    return user_code[:2] + "*" * (len(user_code) - 2)
