"""运行配置，全部可通过环境变量覆盖。"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    db_path: str = field(default_factory=lambda: os.environ.get("DEVICE_AUTH_DB", "data/device_auth.db"))
    # HMAC 盐：生产环境必须通过环境变量注入固定值，否则重启后历史哈希无法核验
    server_pepper: str = field(default_factory=lambda: os.environ.get("SERVER_PEPPER", "dev-pepper-change-me"))
    ttl_seconds: int = field(default_factory=lambda: int(os.environ.get("AUTH_TTL_SECONDS", "300")))
    poll_interval: int = field(default_factory=lambda: int(os.environ.get("AUTH_POLL_INTERVAL", "5")))
    demo_identities: tuple[str, ...] = (
        "sec-admin-zhang",
        "sec-admin-li",
        "sec-oncall-wang",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
