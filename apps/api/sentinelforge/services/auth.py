"""Authentication: registration, credential verification, lockout, token lifecycle."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinelforge.core.config import get_settings
from sentinelforge.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from sentinelforge.models.enums import UserRole
from sentinelforge.models.user import RevokedToken, User


class AuthError(Exception):
    """Authentication failed. The message is deliberately uniform for the caller."""


class AccountLockedError(AuthError):
    def __init__(self, until: dt.datetime) -> None:
        super().__init__("Account is temporarily locked due to repeated failed logins")
        self.until = until


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    expires_at: dt.datetime
    token_type: str = "bearer"  # noqa: S105 - scheme name, not a credential


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _as_utc(value: dt.datetime | None) -> dt.datetime | None:
    """SQLite hands back naive datetimes; normalise before comparing."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def create_user(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str = "",
    role: UserRole = UserRole.ANALYST,
    is_active: bool = True,
) -> User:
    normalized = normalize_email(email)
    existing = db.scalar(select(User).where(User.email == normalized))
    if existing is not None:
        raise AuthError("A user with that email already exists")

    user = User(
        email=normalized,
        full_name=full_name,
        hashed_password=hash_password(password),
        role=role.value,
        is_active=is_active,
    )
    db.add(user)
    db.flush()
    return user


def authenticate(db: Session, *, email: str, password: str) -> User:
    """Verify credentials, applying and updating lockout state.

    Every failure path raises the same message. Distinguishing "no such user" from
    "wrong password" would turn the login form into an account-enumeration oracle.
    """
    settings = get_settings()
    normalized = normalize_email(email)
    user = db.scalar(select(User).where(User.email == normalized))

    if user is None:
        # Spend comparable time on the unknown-user path so response timing does not
        # reveal whether the address exists.
        verify_password(password, "$2b$12$" + "." * 53)
        raise AuthError("Incorrect email or password")

    locked_until = _as_utc(user.locked_until)
    if locked_until and locked_until > _now():
        raise AccountLockedError(locked_until)

    if not verify_password(password, user.hashed_password):
        user.failed_login_count += 1
        if user.failed_login_count >= settings.account_lockout_threshold:
            user.locked_until = _now() + dt.timedelta(minutes=settings.account_lockout_minutes)
            user.failed_login_count = 0
        db.flush()
        raise AuthError("Incorrect email or password")

    if not user.is_active:
        raise AuthError("Incorrect email or password")

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = _now()
    db.flush()
    return user


def issue_tokens(user: User) -> TokenPair:
    access, expires_at = create_access_token(subject=user.id, role=user.role, email=user.email)
    refresh, _jti, _refresh_exp = create_refresh_token(subject=user.id)
    return TokenPair(access_token=access, refresh_token=refresh, expires_at=expires_at)


def revoke_refresh_token(db: Session, token: str) -> None:
    """Deny-list a refresh token's jti. Silently ignores tokens that cannot be decoded."""
    try:
        payload = decode_token(token, expected_type="refresh")
    except TokenError:
        return
    jti = uuid.UUID(str(payload["jti"]))
    if db.scalar(select(RevokedToken).where(RevokedToken.jti == jti)) is not None:
        return
    db.add(
        RevokedToken(
            jti=jti,
            expires_at=dt.datetime.fromtimestamp(int(payload["exp"]), tz=dt.UTC),
        )
    )
    db.flush()


def rotate_refresh_token(db: Session, token: str) -> tuple[User, TokenPair]:
    """Exchange a refresh token for a new pair, revoking the presented one.

    Rotation means a stolen refresh token is single-use: whichever party redeems it
    first invalidates it for the other.
    """
    try:
        payload = decode_token(token, expected_type="refresh")
    except TokenError as exc:
        raise AuthError(str(exc)) from exc

    jti = uuid.UUID(str(payload["jti"]))
    if db.scalar(select(RevokedToken).where(RevokedToken.jti == jti)) is not None:
        raise AuthError("This refresh token has already been used")

    user = db.get(User, uuid.UUID(str(payload["sub"])))
    if user is None or not user.is_active:
        raise AuthError("Token is invalid")

    revoke_refresh_token(db, token)
    return user, issue_tokens(user)


def prune_expired_revocations(db: Session) -> int:
    """Drop deny-list rows whose tokens have expired anyway. Returns rows removed."""
    expired = db.scalars(select(RevokedToken).where(RevokedToken.expires_at < _now())).all()
    for row in expired:
        db.delete(row)
    db.flush()
    return len(expired)
