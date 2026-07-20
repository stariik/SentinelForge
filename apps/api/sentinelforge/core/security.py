"""Password hashing and JWT issuance.

Password storage uses bcrypt over a SHA-256 pre-hash. Two reasons:

1. bcrypt silently truncates input at 72 bytes. A user with a long passphrase would have
   only its first 72 bytes protecting the account, and would never be told.
2. bcrypt also truncates at the first NUL byte.

Hashing to a fixed 44-byte base64 digest first removes both failure modes without
capping password length. This is the same construction as passlib's `bcrypt_sha256`;
it is reimplemented here because passlib 1.7.4 is unmaintained and raises against
bcrypt 5.x (it reads the removed `bcrypt.__about__`).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import uuid
from typing import Any, Literal

import bcrypt
import jwt

from sentinelforge.core.config import get_settings

TokenType = Literal["access", "refresh"]


class TokenError(Exception):
    """Raised when a token is malformed, expired, or of an unexpected type."""


def _prehash(password: str) -> bytes:
    """SHA-256 → base64. Fixed 44 bytes, NUL-free, so bcrypt sees the whole password."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    settings = get_settings()
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    return bcrypt.hashpw(_prehash(password), salt).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time verification. Returns False rather than raising on a malformed hash."""
    try:
        return bcrypt.checkpw(_prehash(password), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def create_access_token(*, subject: uuid.UUID, role: str, email: str) -> tuple[str, dt.datetime]:
    settings = get_settings()
    expires_at = _now() + dt.timedelta(minutes=settings.access_token_ttl_minutes)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "role": role,
        "email": email,
        "type": "access",
        "iat": int(_now().timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, expires_at


def create_refresh_token(*, subject: uuid.UUID) -> tuple[str, uuid.UUID, dt.datetime]:
    """Returns (token, jti, expires_at). The jti is what logout and rotation deny-list."""
    settings = get_settings()
    jti = uuid.uuid4()
    expires_at = _now() + dt.timedelta(days=settings.refresh_token_ttl_days)
    payload: dict[str, Any] = {
        "sub": str(subject),
        "type": "refresh",
        "iat": int(_now().timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": str(jti),
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, jti, expires_at


def decode_token(token: str, *, expected_type: TokenType) -> dict[str, Any]:
    """Decode and validate a token, enforcing its declared type.

    Type checking matters: without it a refresh token — which is long-lived — would be
    accepted as an access token.
    """
    settings = get_settings()
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "sub", "type", "jti"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("Token is invalid") from exc

    if payload.get("type") != expected_type:
        raise TokenError(f"Expected a {expected_type} token")
    return payload
