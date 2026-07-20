from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelforge.core.db import GUID, Base, JSONBType, TimestampMixin, UUIDPrimaryKeyMixin
from sentinelforge.models.rule import rule_techniques

if TYPE_CHECKING:
    from sentinelforge.models.rule import DetectionRule


class AttackTechnique(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A MITRE ATT&CK technique, synced from the bundled versioned cache."""

    __tablename__ = "attack_techniques"

    technique_id: Mapped[str] = mapped_column(
        String(20), unique=True, nullable=False, index=True
    )  # e.g. "T1059.001"
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    tactics: Mapped[list[str]] = mapped_column(JSONBType, nullable=False, default=list)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    parent_technique_id: Mapped[str | None] = mapped_column(String(20), index=True)
    platforms: Mapped[list[str]] = mapped_column(JSONBType, nullable=False, default=list)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    url: Mapped[str | None] = mapped_column(String(500))
    attack_version: Mapped[str] = mapped_column(String(20), nullable=False, default="")

    rules: Mapped[list[DetectionRule]] = relationship(
        secondary=rule_techniques, back_populates="techniques"
    )

    def __repr__(self) -> str:
        return f"<AttackTechnique {self.technique_id} {self.name!r}>"


class CoverageSnapshot(UUIDPrimaryKeyMixin, Base):
    """Point-in-time record of ATT&CK coverage, so drift can be compared over time.

    `detail` holds the per-technique state and contributing rule ids, which is what
    makes a two-snapshot diff possible without recomputing history.
    """

    __tablename__ = "coverage_snapshots"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attack_version: Mapped[str] = mapped_column(String(20), nullable=False, default="")

    total_techniques: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    covered_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    partial_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uncovered_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    detail: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: dt.datetime.now(dt.UTC), index=True
    )
