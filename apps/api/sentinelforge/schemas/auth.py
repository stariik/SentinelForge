from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, EmailStr, Field, field_validator

from sentinelforge.models.enums import UserRole
from sentinelforge.schemas.common import ORMModel

# Long enough to resist offline guessing, with no composition rules. Length beats
# character-class requirements, which mostly produce "Passw0rd!" and a sticky note.
MIN_PASSWORD_LENGTH = 12


class LoginRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(max_length=4096)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - scheme name
    expires_at: dt.datetime


class UserCreateRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=1024)
    full_name: str = Field(default="", max_length=200)
    role: UserRole = UserRole.ANALYST

    @field_validator("password")
    @classmethod
    def _reject_trivial(cls, value: str) -> str:
        if value.strip() == "":
            raise ValueError("Password cannot be blank")
        if len(set(value)) < 5:
            raise ValueError("Password is not varied enough")
        return value


class UserResponse(ORMModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: str
    is_active: bool
    last_login_at: dt.datetime | None
    created_at: dt.datetime


class UserUpdateRequest(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    role: UserRole | None = None
    is_active: bool | None = None
