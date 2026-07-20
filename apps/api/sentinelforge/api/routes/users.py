from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import func, select

from sentinelforge.core.deps import AdminUser, DbSession, get_client_ip
from sentinelforge.models.enums import AuditAction
from sentinelforge.models.user import User
from sentinelforge.schemas.auth import UserCreateRequest, UserResponse, UserUpdateRequest
from sentinelforge.schemas.common import Page
from sentinelforge.services import audit
from sentinelforge.services.auth import AuthError, create_user

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=Page[UserResponse])
def list_users(
    admin: AdminUser, db: DbSession, limit: int = 50, offset: int = 0
) -> Page[UserResponse]:
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    total = db.scalar(select(func.count()).select_from(User)) or 0
    rows = db.scalars(
        select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return Page[UserResponse](
        items=[UserResponse.model_validate(u) for u in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create(
    payload: UserCreateRequest, request: Request, admin: AdminUser, db: DbSession
) -> UserResponse:
    """Create a user. Admin-only — there is no self-service registration by design."""
    try:
        user = create_user(
            db,
            email=str(payload.email),
            password=payload.password,
            full_name=payload.full_name,
            role=payload.role,
        )
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    audit.record(
        db,
        action=AuditAction.USER_CREATE,
        actor=admin,
        entity_type="user",
        entity_id=user.id,
        detail={"email": user.email, "role": user.role},
        ip_address=get_client_ip(request),
    )
    db.commit()
    return UserResponse.model_validate(user)


@router.patch("/{user_id}", response_model=UserResponse)
def update(
    user_id: uuid.UUID,
    payload: UserUpdateRequest,
    request: Request,
    admin: AdminUser,
    db: DbSession,
) -> UserResponse:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Guard against an admin removing the last admin and locking everyone out.
    demoting = payload.role is not None and payload.role.value != "admin" and user.is_admin
    deactivating = payload.is_active is False and user.is_admin
    if demoting or deactivating:
        remaining = (
            db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.role == "admin", User.is_active.is_(True), User.id != user.id)
            )
            or 0
        )
        if remaining == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This is the only active administrator; promote another first.",
            )

    changed: dict[str, object] = {}
    if payload.full_name is not None:
        user.full_name = payload.full_name
        changed["full_name"] = payload.full_name
    if payload.role is not None:
        user.role = payload.role.value
        changed["role"] = payload.role.value
    if payload.is_active is not None:
        user.is_active = payload.is_active
        changed["is_active"] = payload.is_active

    audit.record(
        db,
        action=AuditAction.USER_UPDATE,
        actor=admin,
        entity_type="user",
        entity_id=user.id,
        detail=changed,
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(user)
    return UserResponse.model_validate(user)
