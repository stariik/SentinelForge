"""Detection rule lifecycle: create, update, version, diff, restore, search."""

from __future__ import annotations

import datetime as dt
import difflib
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import String, func, or_, select
from sqlalchemy.orm import Session, selectinload

from sentinelforge.models.enums import RuleStatus, Severity
from sentinelforge.models.rule import DetectionRule, RuleTest, RuleVersion
from sentinelforge.models.user import User
from sentinelforge.services import attack, quality, sigma_service


class RuleNotFoundError(LookupError):
    pass


class VersionNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class RuleFilters:
    search: str | None = None
    status: str | None = None
    severity: str | None = None
    logsource_product: str | None = None
    logsource_category: str | None = None
    author: str | None = None
    tag: str | None = None
    technique_id: str | None = None
    include_archived: bool = False
    only_demo: bool | None = None
    untested: bool | None = None


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _test_counts(db: Session, rule_id: uuid.UUID) -> tuple[int, int]:
    total = db.scalar(select(func.count()).select_from(RuleTest).where(RuleTest.rule_id == rule_id))
    passing = db.scalar(
        select(func.count())
        .select_from(RuleTest)
        .where(RuleTest.rule_id == rule_id, RuleTest.passed.is_(True))
    )
    return int(total or 0), int(passing or 0)


def apply_content(db: Session, rule: DetectionRule, content: str) -> DetectionRule:
    """Re-derive every stored field from rule YAML.

    The YAML document is the source of truth; the columns exist so the database can
    filter and aggregate. Recomputing them all on every write is what stops the two
    from drifting apart.
    """
    metadata = sigma_service.extract_metadata(content)
    validation_status, issues = sigma_service.validate(content)

    rule.content = content
    rule.title = metadata.title
    rule.description = metadata.description
    rule.status = metadata.status
    rule.severity = metadata.severity
    rule.author = metadata.author
    rule.logsource_category = metadata.logsource_category
    rule.logsource_product = metadata.logsource_product
    rule.logsource_service = metadata.logsource_service
    rule.tags = metadata.tags
    rule.rule_references = metadata.references
    rule.falsepositives = metadata.falsepositives
    rule.validation_status = validation_status.value
    rule.validation_issues = [i.as_dict() for i in issues]

    try:
        rule.sigma_id = uuid.UUID(metadata.sigma_id) if metadata.sigma_id else None
    except ValueError:
        # A non-UUID `id:` is a validator finding, not a reason to reject the rule.
        rule.sigma_id = None

    rule.techniques = attack.ensure_techniques(db, metadata.technique_ids)

    test_count, passing_count = _test_counts(db, rule.id) if rule.id is not None else (0, 0)
    result = quality.score_rule(
        content, metadata, test_count=test_count, passing_test_count=passing_count
    )
    rule.quality_score = result.score
    rule.quality_breakdown = result.as_list()
    return rule


def recompute_quality(db: Session, rule: DetectionRule) -> DetectionRule:
    """Refresh only the quality score — used after a test run changes coverage."""
    metadata = sigma_service.extract_metadata(rule.content)
    test_count, passing_count = _test_counts(db, rule.id)
    result = quality.score_rule(
        rule.content, metadata, test_count=test_count, passing_test_count=passing_count
    )
    rule.quality_score = result.score
    rule.quality_breakdown = result.as_list()
    db.flush()
    return rule


def create_rule(
    db: Session,
    *,
    content: str,
    user: User | None,
    is_demo: bool = False,
    change_summary: str = "Initial version",
) -> DetectionRule:
    rule = DetectionRule(
        id=uuid.uuid4(),
        content=content,
        is_demo=is_demo,
        current_version=1,
        created_by_id=user.id if user else None,
    )
    apply_content(db, rule, content)
    db.add(rule)
    db.flush()

    db.add(
        RuleVersion(
            rule_id=rule.id,
            version_number=1,
            content=content,
            change_summary=change_summary,
            created_by_id=user.id if user else None,
        )
    )
    db.flush()
    return rule


def update_rule(
    db: Session,
    rule: DetectionRule,
    *,
    content: str,
    user: User | None,
    change_summary: str = "",
) -> DetectionRule:
    """Update rule content, appending a version only when the content actually changed."""
    if content == rule.content:
        apply_content(db, rule, content)  # metadata may still need refreshing
        db.flush()
        return rule

    apply_content(db, rule, content)
    rule.current_version += 1
    db.add(
        RuleVersion(
            rule_id=rule.id,
            version_number=rule.current_version,
            content=content,
            change_summary=change_summary or f"Updated to version {rule.current_version}",
            created_by_id=user.id if user else None,
        )
    )
    db.flush()
    return rule


def duplicate_rule(db: Session, rule: DetectionRule, *, user: User | None) -> DetectionRule:
    """Copy a rule, retitling it so the two are distinguishable in a list view."""
    document = sigma_service.load_yaml_documents(rule.content)[0]
    original_title = str(document.get("title", rule.title))

    content = rule.content
    new_title = f"{original_title} (copy)"
    if "title:" in content:
        content = content.replace(f"title: {original_title}", f"title: {new_title}", 1)
        if new_title not in content:  # quoted or folded title styles
            content = f"title: {new_title}\n" + "\n".join(
                line for line in content.splitlines() if not line.startswith("title:")
            )
    # A duplicate must not reuse the source rule's Sigma id.
    content = "\n".join(line for line in content.splitlines() if not line.strip().startswith("id:"))
    content = content.replace(f"title: {new_title}", f"title: {new_title}\nid: {uuid.uuid4()}", 1)

    return create_rule(
        db,
        content=content,
        user=user,
        is_demo=rule.is_demo,
        change_summary=f"Duplicated from '{original_title}'",
    )


def archive_rule(db: Session, rule: DetectionRule) -> DetectionRule:
    rule.archived_at = _now()
    db.flush()
    return rule


def unarchive_rule(db: Session, rule: DetectionRule) -> DetectionRule:
    rule.archived_at = None
    db.flush()
    return rule


def delete_rule(db: Session, rule: DetectionRule) -> None:
    db.delete(rule)
    db.flush()


def get_rule(db: Session, rule_id: uuid.UUID) -> DetectionRule:
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise RuleNotFoundError(f"No rule with id {rule_id}")
    return rule


def get_version(db: Session, rule: DetectionRule, version_number: int) -> RuleVersion:
    version = db.scalar(
        select(RuleVersion).where(
            RuleVersion.rule_id == rule.id, RuleVersion.version_number == version_number
        )
    )
    if version is None:
        raise VersionNotFoundError(f"Rule has no version {version_number}")
    return version


def diff_versions(db: Session, rule: DetectionRule, from_version: int, to_version: int) -> str:
    """Unified diff between two versions of a rule."""
    left = get_version(db, rule, from_version)
    right = get_version(db, rule, to_version)
    return "".join(
        difflib.unified_diff(
            left.content.splitlines(keepends=True),
            right.content.splitlines(keepends=True),
            fromfile=f"version {from_version}",
            tofile=f"version {to_version}",
            n=3,
        )
    )


def restore_version(
    db: Session, rule: DetectionRule, version_number: int, *, user: User | None
) -> DetectionRule:
    """Restore old content by appending it as a NEW version.

    History is never rewritten or truncated — restoring version 2 over version 5
    produces version 6. An audit trail you can rewind is not an audit trail.
    """
    version = get_version(db, rule, version_number)
    return update_rule(
        db,
        rule,
        content=version.content,
        user=user,
        change_summary=f"Restored content from version {version_number}",
    )


def search_rules(
    db: Session, filters: RuleFilters, *, limit: int = 50, offset: int = 0
) -> tuple[list[DetectionRule], int]:
    stmt = select(DetectionRule)

    if not filters.include_archived:
        stmt = stmt.where(DetectionRule.archived_at.is_(None))
    if filters.search:
        pattern = f"%{filters.search.strip()}%"
        stmt = stmt.where(
            or_(
                DetectionRule.title.ilike(pattern),
                DetectionRule.description.ilike(pattern),
            )
        )
    if filters.status:
        stmt = stmt.where(DetectionRule.status == filters.status)
    if filters.severity:
        stmt = stmt.where(DetectionRule.severity == filters.severity)
    if filters.logsource_product:
        stmt = stmt.where(DetectionRule.logsource_product == filters.logsource_product)
    if filters.logsource_category:
        stmt = stmt.where(DetectionRule.logsource_category == filters.logsource_category)
    if filters.author:
        stmt = stmt.where(DetectionRule.author.ilike(f"%{filters.author.strip()}%"))
    if filters.only_demo is not None:
        stmt = stmt.where(DetectionRule.is_demo.is_(filters.only_demo))
    if filters.tag:
        # Portable across PostgreSQL and SQLite by matching the serialised JSON array.
        # On PostgreSQL a JSONB containment operator would use a GIN index; this
        # substring match is correct but does a scan. Documented in the roadmap.
        stmt = stmt.where(DetectionRule.tags.cast(String).ilike(f'%"{filters.tag.strip()}"%'))
    if filters.technique_id:
        stmt = stmt.where(
            DetectionRule.techniques.any(technique_id=filters.technique_id.strip().upper())
        )
    if filters.untested:
        tested = select(RuleTest.rule_id).distinct()
        stmt = stmt.where(DetectionRule.id.not_in(tested))

    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)

    rows = db.scalars(
        stmt.options(selectinload(DetectionRule.techniques))
        .order_by(DetectionRule.updated_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return list(rows), total


def list_versions(db: Session, rule: DetectionRule) -> list[RuleVersion]:
    return list(
        db.scalars(
            select(RuleVersion)
            .where(RuleVersion.rule_id == rule.id)
            .order_by(RuleVersion.version_number.desc())
        ).all()
    )


def distinct_filter_values(db: Session) -> dict[str, list[Any]]:
    """Populate filter dropdowns from what is actually in the library."""
    products = db.scalars(
        select(DetectionRule.logsource_product)
        .where(DetectionRule.logsource_product.is_not(None))
        .distinct()
    ).all()
    categories = db.scalars(
        select(DetectionRule.logsource_category)
        .where(DetectionRule.logsource_category.is_not(None))
        .distinct()
    ).all()
    authors = db.scalars(
        select(DetectionRule.author).where(DetectionRule.author != "").distinct()
    ).all()
    return {
        "statuses": [s.value for s in RuleStatus],
        "severities": [s.value for s in Severity],
        "logsource_products": sorted(p for p in products if p),
        "logsource_categories": sorted(c for c in categories if c),
        "authors": sorted(a for a in authors if a),
    }
