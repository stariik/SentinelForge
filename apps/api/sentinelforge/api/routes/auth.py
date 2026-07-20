from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status

from sentinelforge.core.deps import CurrentUser, DbSession, get_client_ip
from sentinelforge.core.rate_limit import get_login_limiter
from sentinelforge.models.enums import AuditAction
from sentinelforge.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserResponse,
)
from sentinelforge.schemas.common import MessageResponse
from sentinelforge.services import audit
from sentinelforge.services.auth import (
    AccountLockedError,
    AuthError,
    authenticate,
    issue_tokens,
    revoke_refresh_token,
    rotate_refresh_token,
)

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest, request: Request, response: Response, db: DbSession
) -> TokenResponse:
    """Exchange credentials for an access/refresh token pair.

    Throttled per client IP *and* per account. The IP window blunts distributed
    guessing against many accounts; the account lockout blunts focused guessing
    against one.
    """
    client_ip = get_client_ip(request)
    limiter = get_login_limiter()

    if not limiter.check(f"login:{client_ip}"):
        retry_after = limiter.retry_after(f"login:{client_ip}")
        response.headers["Retry-After"] = str(retry_after)
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILURE,
            actor_email=payload.email[:320],
            detail={"reason": "rate_limited"},
            ip_address=client_ip,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again shortly.",
            headers={"Retry-After": str(retry_after)},
        )

    try:
        user = authenticate(db, email=payload.email, password=payload.password)
    except AccountLockedError as exc:
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILURE,
            actor_email=payload.email[:320],
            detail={"reason": "account_locked"},
            ip_address=client_ip,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=str(exc)) from exc
    except AuthError as exc:
        audit.record(
            db,
            action=AuditAction.LOGIN_FAILURE,
            actor_email=payload.email[:320],
            detail={"reason": "bad_credentials"},
            ip_address=client_ip,
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    tokens = issue_tokens(user)
    audit.record(
        db,
        action=AuditAction.LOGIN_SUCCESS,
        actor=user,
        entity_type="user",
        entity_id=user.id,
        ip_address=client_ip,
    )
    db.commit()
    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_at=tokens.expires_at,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: DbSession) -> TokenResponse:
    """Rotate a refresh token. The presented token is deny-listed on use."""
    try:
        _user, tokens = rotate_refresh_token(db, payload.refresh_token)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    db.commit()
    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_at=tokens.expires_at,
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    payload: RefreshRequest, request: Request, user: CurrentUser, db: DbSession
) -> MessageResponse:
    """Revoke the supplied refresh token.

    The access token remains valid until it expires — a documented limitation in the
    threat model, mitigated by keeping its TTL short.
    """
    revoke_refresh_token(db, payload.refresh_token)
    audit.record(
        db,
        action=AuditAction.LOGOUT,
        actor=user,
        entity_type="user",
        entity_id=user.id,
        ip_address=get_client_ip(request),
    )
    db.commit()
    return MessageResponse(message="Signed out. The refresh token has been revoked.")


@router.get("/me", response_model=UserResponse)
def me(user: CurrentUser) -> UserResponse:
    return UserResponse.model_validate(user)
