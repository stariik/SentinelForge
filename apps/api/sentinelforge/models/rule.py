from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelforge.core.db import GUID, Base, JSONBType, TimestampMixin, UUIDPrimaryKeyMixin
from sentinelforge.models.enums import (
    RuleStatus,
    Severity,
    TestExpectation,
    ValidationStatus,
)

if TYPE_CHECKING:
    from sentinelforge.models.attack import AttackTechnique
    from sentinelforge.models.event import DetectionMatch, EventDataset
    from sentinelforge.models.user import User


rule_techniques = Table(
    "rule_techniques",
    Base.metadata,
    Column(
        "rule_id",
        GUID(),
        ForeignKey("detection_rules.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "technique_id",
        GUID(),
        ForeignKey("attack_techniques.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class DetectionRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        Index("ix_detection_rules_status_severity", "status", "severity"),
        Index("ix_detection_rules_logsource", "logsource_product", "logsource_category"),
    )

    # The `id:` declared inside the Sigma document. Distinct from our own primary key:
    # two rules imported from different sources can legitimately carry the same sigma_id,
    # so this is indexed but deliberately not unique.
    sigma_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), index=True)

    title: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=RuleStatus.DRAFT.value, index=True
    )
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default=Severity.MEDIUM.value, index=True
    )
    author: Mapped[str] = mapped_column(String(200), nullable=False, default="")

    logsource_category: Mapped[str | None] = mapped_column(String(100), index=True)
    logsource_product: Mapped[str | None] = mapped_column(String(100), index=True)
    logsource_service: Mapped[str | None] = mapped_column(String(100))

    tags: Mapped[list[str]] = mapped_column(JSONBType, nullable=False, default=list)
    # `references` collides with SQL reserved usage in several dialects; renamed here.
    rule_references: Mapped[list[str]] = mapped_column(JSONBType, nullable=False, default=list)
    falsepositives: Mapped[list[str]] = mapped_column(JSONBType, nullable=False, default=list)

    # Canonical YAML. Everything above is derived from this and refreshed on write,
    # so the document remains the single source of truth.
    content: Mapped[str] = mapped_column(Text, nullable=False)

    quality_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    quality_breakdown: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)
    validation_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ValidationStatus.VALID.value, index=True
    )
    validation_issues: Mapped[list[Any]] = mapped_column(JSONBType, nullable=False, default=list)

    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    archived_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    created_by: Mapped[User | None] = relationship(
        back_populates="rules", foreign_keys=[created_by_id]
    )
    versions: Mapped[list[RuleVersion]] = relationship(
        back_populates="rule",
        cascade="all, delete-orphan",
        order_by="desc(RuleVersion.version_number)",
    )
    tests: Mapped[list[RuleTest]] = relationship(
        back_populates="rule", cascade="all, delete-orphan"
    )
    techniques: Mapped[list[AttackTechnique]] = relationship(
        secondary=rule_techniques, back_populates="rules"
    )

    @property
    def is_archived(self) -> bool:
        return self.archived_at is not None

    def __repr__(self) -> str:
        return f"<DetectionRule {self.title!r} v{self.current_version}>"


class RuleVersion(UUIDPrimaryKeyMixin, Base):
    """Immutable snapshot of rule content.

    Restoring an older version appends a new version rather than rewinding, so the
    audit trail can never be rewritten from the application.
    """

    __tablename__ = "rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "version_number", name="uq_rule_version"),
        Index("ix_rule_versions_rule_version", "rule_id", "version_number"),
    )

    rule_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    change_summary: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: dt.datetime.now(dt.UTC)
    )

    rule: Mapped[DetectionRule] = relationship(back_populates="versions")


class RuleTest(UUIDPrimaryKeyMixin, Base):
    """One execution of one rule against one dataset."""

    __tablename__ = "rule_tests"
    __table_args__ = (Index("ix_rule_tests_rule_created", "rule_id", "created_at"),)

    rule_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
    )
    dataset_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("event_datasets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule_version_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    expectation: Mapped[str] = mapped_column(
        String(30), nullable=False, default=TestExpectation.EXPLORATORY.value
    )
    expected_match_count: Mapped[int | None] = mapped_column(Integer)

    events_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    events_matched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    execution_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    passed: Mapped[bool | None] = mapped_column(Boolean, index=True)
    result_label: Mapped[str] = mapped_column(String(30), nullable=False, default="exploratory")
    unresolved_fields: Mapped[list[str]] = mapped_column(JSONBType, nullable=False, default=list)
    error_message: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: dt.datetime.now(dt.UTC), index=True
    )

    rule: Mapped[DetectionRule] = relationship(back_populates="tests")
    dataset: Mapped[EventDataset] = relationship(back_populates="tests")
    matches: Mapped[list[DetectionMatch]] = relationship(
        back_populates="rule_test", cascade="all, delete-orphan"
    )
