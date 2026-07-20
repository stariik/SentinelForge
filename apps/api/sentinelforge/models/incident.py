from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelforge.core.db import GUID, Base, TimestampMixin, UUIDPrimaryKeyMixin
from sentinelforge.models.enums import Severity

if TYPE_CHECKING:
    from sentinelforge.models.event import EventDataset, NormalizedEvent


class IncidentScenario(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A curated narrative over a dataset, used for timeline replay."""

    __tablename__ = "incident_scenarios"

    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    narrative: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default=Severity.MEDIUM.value, index=True
    )
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    dataset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("event_datasets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    dataset: Mapped[EventDataset] = relationship(back_populates="scenarios")
    events: Mapped[list[IncidentEvent]] = relationship(
        back_populates="scenario",
        cascade="all, delete-orphan",
        order_by="IncidentEvent.sequence",
    )

    def __repr__(self) -> str:
        return f"<IncidentScenario {self.name!r}>"


class IncidentEvent(UUIDPrimaryKeyMixin, Base):
    """One beat in a scenario timeline, annotated for analyst review."""

    __tablename__ = "incident_events"
    __table_args__ = (Index("ix_incident_events_scenario_sequence", "scenario_id", "sequence"),)

    scenario_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("incident_scenarios.id", ondelete="CASCADE"), nullable=False
    )
    normalized_event_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)

    summary: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    analyst_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default=Severity.INFORMATIONAL.value
    )

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: dt.datetime.now(dt.UTC), nullable=False
    )

    scenario: Mapped[IncidentScenario] = relationship(back_populates="events")
    normalized_event: Mapped[NormalizedEvent] = relationship(back_populates="incident_events")
