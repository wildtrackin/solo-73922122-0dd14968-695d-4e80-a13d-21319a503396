"""请求/响应模型。"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class DeviceAuthorizationRequest(BaseModel):
    client_id: str = Field(min_length=1, max_length=128)
    device_name: str = Field(min_length=1, max_length=200)


class PollRequest(BaseModel):
    client_id: str = Field(min_length=1, max_length=128)
    device_code: str = Field(min_length=8, max_length=128)


class TokenRequest(BaseModel):
    client_id: str = Field(min_length=1, max_length=128)
    device_code: str = Field(min_length=8, max_length=128)


class UserCodeLookupRequest(BaseModel):
    user_code: str = Field(min_length=4, max_length=12)


class DecisionRequest(BaseModel):
    user_code: str = Field(min_length=4, max_length=12)
    approver: str = Field(min_length=1, max_length=128)
    decision: Literal["approve", "deny"]
