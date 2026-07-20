"""Domain enumerations.

Stored as constrained strings rather than native PostgreSQL enum types: several of these
track the Sigma specification, which evolves independently of this project, and adding a
value should not require a schema migration.
"""

from __future__ import annotations

from enum import StrEnum


class UserRole(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"


class RuleStatus(StrEnum):
    """Sigma rule lifecycle states (`status:` in the rule body)."""

    DRAFT = "draft"
    EXPERIMENTAL = "experimental"
    TEST = "test"
    STABLE = "stable"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"


class Severity(StrEnum):
    """Sigma `level:` values."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationStatus(StrEnum):
    VALID = "valid"
    WARNINGS = "warnings"
    INVALID = "invalid"


class IssueSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class DatasetFormat(StrEnum):
    GENERIC_JSON = "generic_json"
    WINDOWS_EVENT_LOG = "windows_event_log"
    SYSMON = "sysmon"
    LINUX_AUTH = "linux_auth"
    WEB_ACCESS = "web_access"


class TestExpectation(StrEnum):
    """What the analyst asserts *before* the run — this is what makes a test a test."""

    SHOULD_MATCH = "should_match"
    SHOULD_NOT_MATCH = "should_not_match"
    EXPLORATORY = "exploratory"


class TestResultLabel(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"
    EXPLORATORY = "exploratory"
    ERROR = "error"


class CoverageState(StrEnum):
    COVERED = "covered"
    PARTIAL = "partial"
    UNCOVERED = "uncovered"


class AuditAction(StrEnum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    RULE_CREATE = "rule_create"
    RULE_UPDATE = "rule_update"
    RULE_DUPLICATE = "rule_duplicate"
    RULE_ARCHIVE = "rule_archive"
    RULE_RESTORE_VERSION = "rule_restore_version"
    RULE_DELETE = "rule_delete"
    RULE_IMPORT = "rule_import"
    RULE_EXPORT = "rule_export"
    DATASET_IMPORT = "dataset_import"
    DATASET_DELETE = "dataset_delete"
    TEST_RUN = "test_run"
    COVERAGE_SNAPSHOT = "coverage_snapshot"
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
