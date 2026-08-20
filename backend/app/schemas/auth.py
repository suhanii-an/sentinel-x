"""Authentication schemas."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import Role
from app.schemas.common import ORMModel

MIN_PASSWORD_LENGTH = 12


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - a scheme name, not a credential
    expires_at: dt.datetime
    user: CurrentUser


class CurrentUser(ORMModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    role: str
    is_active: bool
    last_login_at: dt.datetime | None = None


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=72)
    role: Role = Role.ANALYST
    email: str | None = Field(default=None, max_length=255)
    full_name: str | None = Field(default=None, max_length=255)


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=72)


TokenResponse.model_rebuild()
