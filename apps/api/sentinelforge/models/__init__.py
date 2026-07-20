"""SQLAlchemy models.

Imported as a package so that `Base.metadata` is fully populated before Alembic
autogenerate or `create_all` runs — a partially imported model graph is the classic
cause of "table missing" in migrations.
"""

from sentinelforge.core.db import Base
from sentinelforge.models.attack import AttackTechnique, CoverageSnapshot
from sentinelforge.models.audit import AuditLog
from sentinelforge.models.enums import (
    AuditAction,
    CoverageState,
    DatasetFormat,
    IssueSeverity,
    RuleStatus,
    Severity,
    TestExpectation,
    TestResultLabel,
    UserRole,
    ValidationStatus,
)
from sentinelforge.models.event import DetectionMatch, EventDataset, NormalizedEvent
from sentinelforge.models.incident import IncidentEvent, IncidentScenario
from sentinelforge.models.rule import DetectionRule, RuleTest, RuleVersion, rule_techniques
from sentinelforge.models.user import RevokedToken, User

__all__ = [
    "AttackTechnique",
    "AuditAction",
    "AuditLog",
    "Base",
    "CoverageSnapshot",
    "CoverageState",
    "DatasetFormat",
    "DetectionMatch",
    "DetectionRule",
    "EventDataset",
    "IncidentEvent",
    "IncidentScenario",
    "IssueSeverity",
    "NormalizedEvent",
    "RevokedToken",
    "RuleStatus",
    "RuleTest",
    "RuleVersion",
    "Severity",
    "TestExpectation",
    "TestResultLabel",
    "User",
    "UserRole",
    "ValidationStatus",
    "rule_techniques",
]
