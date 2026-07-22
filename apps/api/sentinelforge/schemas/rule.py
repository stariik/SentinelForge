from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, Field

from sentinelforge.models.enums import RuleStatus, Severity, ValidationStatus
from sentinelforge.schemas.common import ORMModel

# Guards the request body before any parser sees it. The service layer enforces the
# same limit from settings; this is the cheap rejection at the edge.
MAX_RULE_CONTENT = 512 * 1024


class TechniqueRef(ORMModel):
    technique_id: str
    name: str
    tactics: list[str]
    url: str | None = None


class ValidationIssueOut(BaseModel):
    code: str
    severity: str
    message: str
    context: str = ""


class QualityCriterionOut(BaseModel):
    key: str
    label: str
    earned: int
    maximum: int
    reason: str


class RuleListItem(ORMModel):
    id: uuid.UUID
    title: str
    status: str
    severity: str
    author: str
    logsource_product: str | None
    logsource_category: str | None
    tags: list[str]
    quality_score: int
    validation_status: str
    is_demo: bool
    archived_at: dt.datetime | None
    current_version: int
    created_at: dt.datetime
    updated_at: dt.datetime
    techniques: list[TechniqueRef] = Field(default_factory=list)


class RuleDetail(RuleListItem):
    description: str
    sigma_id: uuid.UUID | None
    logsource_service: str | None
    rule_references: list[str]
    falsepositives: list[str]
    content: str
    quality_breakdown: list[QualityCriterionOut]
    validation_issues: list[ValidationIssueOut]


class RuleCreateRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_RULE_CONTENT)
    is_demo: bool = False
    change_summary: str = Field(default="Initial version", max_length=500)


class RuleUpdateRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_RULE_CONTENT)
    change_summary: str = Field(default="", max_length=500)


class RuleVersionOut(ORMModel):
    id: uuid.UUID
    version_number: int
    change_summary: str
    created_at: dt.datetime
    created_by_id: uuid.UUID | None


class RuleVersionDetail(RuleVersionOut):
    content: str


class RuleDiffResponse(BaseModel):
    rule_id: uuid.UUID
    from_version: int
    to_version: int
    diff: str
    identical: bool


class RuleValidationResponse(BaseModel):
    """Validate arbitrary content without persisting it — used by the editor."""

    validation_status: ValidationStatus
    issues: list[ValidationIssueOut]
    quality_score: int
    quality_breakdown: list[QualityCriterionOut]
    quality_caveat: str
    query_preview: str | None = None
    parse_error: str | None = None


class RuleValidateRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_RULE_CONTENT)


class ImportedRuleOut(BaseModel):
    filename: str
    rule_id: str
    title: str


class RejectedEntryOut(BaseModel):
    filename: str
    reason: str


class ImportReportOut(BaseModel):
    imported_count: int
    rejected_count: int
    imported: list[ImportedRuleOut]
    rejected: list[RejectedEntryOut]


class RuleFilterOptions(BaseModel):
    statuses: list[str]
    severities: list[str]
    logsource_products: list[str]
    logsource_categories: list[str]
    authors: list[str]


class RuleQueryParams(BaseModel):
    """Documented filter surface for the rule list endpoint."""

    search: str | None = Field(default=None, max_length=200)
    status: RuleStatus | None = None
    severity: Severity | None = None
    logsource_product: str | None = Field(default=None, max_length=100)
    logsource_category: str | None = Field(default=None, max_length=100)
    author: str | None = Field(default=None, max_length=200)
    tag: str | None = Field(default=None, max_length=100)
    technique_id: str | None = Field(default=None, max_length=20)
    include_archived: bool = False
    untested: bool = False


def rule_detail_from_model(rule: Any) -> RuleDetail:
    return RuleDetail.model_validate(rule)
