"""FastAPI 入口：设备授权终端接口、人工审批接口、身份接口与演示页面。"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import store
from .config import get_settings
from .db import init_db
from .schemas import (
    DecisionRequest,
    DeviceAuthorizationRequest,
    PollRequest,
    TokenRequest,
    UserCodeLookupRequest,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # 每个进程启动时确保表结构存在，历史数据在 SQLite 文件中保留
    init_db()
    yield


app = FastAPI(
    title="内网设备授权登录系统",
    description="无浏览器巡检终端的人工确认设备授权（Device Authorization Grant）",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# 错误处理：统一 error code + message
# ---------------------------------------------------------------------------


@app.exception_handler(store.AuthError)
def auth_error_handler(_request, exc: store.AuthError) -> JSONResponse:
    return JSONResponse(status_code=exc.http_status, content={"error": exc.code, "message": exc.message})


# ---------------------------------------------------------------------------
# 终端侧接口
# ---------------------------------------------------------------------------


@app.post("/api/device/authorize")
def device_authorize(payload: DeviceAuthorizationRequest) -> dict:
    """终端发起：返回设备码、人工短码和有效期（明文仅此一次返回）。"""
    return store.create_authorization(payload.client_id, payload.device_name)


@app.post("/api/device/poll")
def device_poll(payload: PollRequest) -> dict:
    """终端轮询授权状态；client_id 与设备码不匹配时拒绝查询。"""
    return store.poll_authorization(payload.client_id, payload.device_code)


@app.post("/api/device/token")
def device_token(payload: TokenRequest) -> dict:
    """批准后一次性领取绑定批准者的令牌，状态与签发同事务生效。"""
    return store.claim_token(payload.client_id, payload.device_code)


# ---------------------------------------------------------------------------
# 身份接口
# ---------------------------------------------------------------------------


def _extract_bearer(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise store.AuthError("invalid_token", "需要 Bearer 访问令牌", 401)
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise store.AuthError("invalid_token", "访问令牌为空", 401)
    return token


@app.get("/api/identity")
def identity(access_token: str = Depends(_extract_bearer)) -> dict:
    """凭令牌调用的身份接口，返回令牌绑定的批准者与设备信息。"""
    info = store.resolve_token(access_token)
    return {
        "sub": info["client_id"],
        "client_id": info["client_id"],
        "device_name": info["device_name"],
        "approver": info["approver"],
        "authorization_id": info["authorization_id"],
        "issued_at": info["issued_at"],
        "scope": "inspection-terminal",
    }


# ---------------------------------------------------------------------------
# 人工审批接口（网页使用）
# ---------------------------------------------------------------------------


@app.get("/api/admin/identities")
def admin_identities() -> dict:
    """网页可切换的本地演示身份。"""
    return {"identities": list(get_settings().demo_identities)}


@app.get("/api/admin/authorizations")
def admin_list() -> dict:
    """全部授权列表（短码脱敏）。"""
    return {"items": store.list_authorizations()}


@app.post("/api/admin/find")
def admin_find(payload: UserCodeLookupRequest) -> dict:
    """输入人工短码核对设备详情。"""
    return store.find_by_user_code(payload.user_code)


@app.post("/api/admin/decide")
def admin_decide(payload: DecisionRequest) -> dict:
    """批准或拒绝，仅待确认项可操作。"""
    return store.decide(payload.user_code, payload.approver, payload.decision)
