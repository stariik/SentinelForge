"""FastAPI dependencies for authentication and authorization.

Authorization fails closed: a route without an explicit role dependency is not
reachable by anonymous callers, because `get_current_user` is required to resolve a
`User` at all.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from sentinelforge.core.db import get_db
from sentinelforge.core.security import TokenError, decode_token
from sentinelforge.models.enums import UserRole
from sentinelforge.models.user import User

bearer_scheme = HTTPBearer(auto_error=False, description="JWT access token")

CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_client_ip(request: Request) -> str:
    """Best-effort client IP.

    `X-Forwarded-For` is only consulted because this app is expected to sit behind a
    reverse proxy in the compose stack. It is a spoofable header when exposed directly,
    so it is used for rate-limit keying and audit context, never for authorization.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    return request.client.host if request.client else "unknown"


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None or not credentials.credentials:
        raise CREDENTIALS_EXCEPTION

    try:
        payload = decode_token(credentials.credentials, expected_type="access")
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (KeyError, ValueError) as exc:
        raise CREDENTIALS_EXCEPTION from exc

    user = db.get(User, user_id)
    if user is None:
        raise CREDENTIALS_EXCEPTION
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled"
        )
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
DbSession = Annotated[Session, Depends(get_db)]


def require_role(*allowed: UserRole) -> Callable[[User], User]:
    """Build a dependency asserting the caller holds one of `allowed`."""

    allowed_values = {role.value for role in allowed}

    def _dependency(user: CurrentUser) -> User:
        if user.role not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This action requires the " + " or ".join(sorted(allowed_values)) + " role",
            )
        return user

    return _dependency


require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ADMIN, UserRole.ANALYST)

AdminUser = Annotated[User, Depends(require_admin)]
AnalystUser = Annotated[User, Depends(require_analyst)]
