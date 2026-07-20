from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from sentinelforge.core.db import GUID, Base, JSONBType, UUIDPrimaryKeyMixin


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """Append-only record of security-relevant actions.

    `actor_email` is denormalised on purpose: if the user row is later deleted, the
    trail must still say who did the thing. A foreign key alone would leave a null.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_actor_action", "actor_id", "action"),
        Index("ix_audit_logs_entity", "entity_type", "entity_id"),
    )

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL")
    )
    actor_email: Mapped[str] = mapped_column(String(320), nullable=False, default="")

    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, default="")
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    detail: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(45))

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: dt.datetime.now(dt.UTC), index=True
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} by {self.actor_email}>"
