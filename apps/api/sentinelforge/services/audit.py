"""Audit trail writer.

Every security-relevant mutation routes through `record()`. The function never raises
into the caller's transaction path for formatting reasons — an audit failure must not
be able to roll back the action it describes, but it also must not pass silently, so it
is logged at error level.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sentinelforge.models.audit import AuditLog
from sentinelforge.models.enums import AuditAction
from sentinelforge.models.user import User

logger = logging.getLogger(__name__)


def record(
    db: Session,
    *,
    action: AuditAction,
    actor: User | None = None,
    actor_email: str | None = None,
    entity_type: str = "",
    entity_id: str | uuid.UUID = "",
    detail: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditLog | None:
    """Append an audit record. Flushed with the caller's transaction, not committed here."""
    try:
        entry = AuditLog(
            actor_id=actor.id if actor else None,
            actor_email=(actor.email if actor else actor_email) or "",
            action=action.value,
            entity_type=entity_type,
            entity_id=str(entity_id),
            detail=detail or {},
            ip_address=ip_address,
        )
        db.add(entry)
        db.flush()
        return entry
    except Exception:
        logger.exception("Failed to write audit record for action=%s", action.value)
        return None


def list_entries(
    db: Session,
    *,
    actor_id: uuid.UUID | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AuditLog], int]:
    """Return a page of audit entries, newest first, plus the total count."""
    stmt = select(AuditLog)
    if actor_id is not None:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if entity_id:
        stmt = stmt.where(AuditLog.entity_id == entity_id)

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = (
        db.execute(stmt.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset))
        .scalars()
        .all()
    )
    return list(rows), total
