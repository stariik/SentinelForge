from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelforge.core.db import GUID, Base, JSONBType, TimestampMixin, UUIDPrimaryKeyMixin
from sentinelforge.models.enums import DatasetFormat

if TYPE_CHECKING:
    from sentinelforge.models.incident import IncidentEvent, IncidentScenario
    from sentinelforge.models.rule import DetectionRule, RuleTest


class EventDataset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "event_datasets"

    name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_format: Mapped[str] = mapped_column(
        String(40), nullable=False, default=DatasetFormat.GENERIC_JSON.value
    )
    source_filename: Mapped[str | None] = mapped_column(String(500))
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    # Free-text pointer to the defensive scenario this dataset illustrates.
    scenario_hint: Mapped[str] = mapped_column(String(300), nullable=False, default="")

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL")
    )

    events: Mapped[list[NormalizedEvent]] = relationship(
        back_populates="dataset", cascade="all, delete-orphan", passive_deletes=True
    )
    tests: Mapped[list[RuleTest]] = relationship(back_populates="dataset")
    scenarios: Mapped[list[IncidentScenario]] = relationship(back_populates="dataset")

    def __repr__(self) -> str:
        return f"<EventDataset {self.name!r} events={self.event_count}>"


class NormalizedEvent(UUIDPrimaryKeyMixin, Base):
    """A source record projected onto SentinelForge's common schema.

    Normalization is additive: `raw_event` always holds the original record verbatim,
    so an analyst can see exactly what the source said rather than only our
    interpretation of it.
    """

    __tablename__ = "normalized_events"
    __table_args__ = (
        Index("ix_normalized_events_dataset_sequence", "dataset_id", "sequence"),
        Index("ix_normalized_events_dataset_timestamp", "dataset_id", "timestamp"),
    )

    dataset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("event_datasets.id", ondelete="CASCADE"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)

    timestamp: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    host: Mapped[str | None] = mapped_column(String(255), index=True)
    username: Mapped[str | None] = mapped_column(String(255), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45))
    process_name: Mapped[str | None] = mapped_column(String(500), index=True)
    parent_process: Mapped[str | None] = mapped_column(String(500))
    command_line: Mapped[str | None] = mapped_column(Text)
    event_id: Mapped[str | None] = mapped_column(String(50), index=True)
    log_source: Mapped[str | None] = mapped_column(String(100), index=True)
    action: Mapped[str | None] = mapped_column(String(100))
    file_hash: Mapped[str | None] = mapped_column(String(200))

    raw_event: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: dt.datetime.now(dt.UTC)
    )

    dataset: Mapped[EventDataset] = relationship(back_populates="events")
    incident_events: Mapped[list[IncidentEvent]] = relationship(back_populates="normalized_event")


class DetectionMatch(UUIDPrimaryKeyMixin, Base):
    """The outcome of evaluating one rule against one event.

    Only matches are persisted by default; non-matches are summarised in counts on the
    parent `RuleTest`, which keeps this table proportional to findings rather than to
    dataset size.
    """

    __tablename__ = "detection_matches"
    __table_args__ = (
        Index("ix_detection_matches_test_matched", "rule_test_id", "matched"),
        Index("ix_detection_matches_rule", "rule_id"),
    )

    rule_test_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("rule_tests.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
    )
    normalized_event_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("normalized_events.id", ondelete="CASCADE"), nullable=False, index=True
    )

    matched: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    matched_fields: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)
    # Serialised condition trace: which node matched, why, and against what value.
    explanation: Mapped[dict[str, Any]] = mapped_column(JSONBType, nullable=False, default=dict)

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: dt.datetime.now(dt.UTC)
    )

    rule_test: Mapped[RuleTest] = relationship(back_populates="matches")
    rule: Mapped[DetectionRule] = relationship()
    normalized_event: Mapped[NormalizedEvent] = relationship()
