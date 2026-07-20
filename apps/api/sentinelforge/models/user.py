from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelforge.core.db import GUID, Base, TimestampMixin, UUIDPrimaryKeyMixin
from sentinelforge.models.enums import UserRole

if TYPE_CHECKING:
    from sentinelforge.models.rule import DetectionRule


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default=UserRole.ANALYST.value)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    # Lockout state lives on the row so it survives a restart — an in-memory counter
    # would reset the moment an attacker crashed or waited out a deploy.
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    rules: Mapped[list[DetectionRule]] = relationship(
        back_populates="created_by", foreign_keys="DetectionRule.created_by_id"
    )

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN.value

    def __repr__(self) -> str:
        return f"<User {self.email} role={self.role}>"


class RevokedToken(UUIDPrimaryKeyMixin, Base):
    """Denylist of refresh-token `jti` values invalidated by logout or rotation."""

    __tablename__ = "revoked_tokens"

    jti: Mapped[uuid.UUID] = mapped_column(GUID(), unique=True, index=True, nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: dt.datetime.now(dt.UTC)
    )
