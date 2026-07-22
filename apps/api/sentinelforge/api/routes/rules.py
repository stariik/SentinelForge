from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Query, Request, Response, UploadFile, status

from sentinelforge.core.config import get_settings
from sentinelforge.core.deps import AdminUser, AnalystUser, DbSession, get_client_ip
from sentinelforge.models.enums import AuditAction, RuleStatus, Severity
from sentinelforge.schemas.common import MessageResponse, Page
from sentinelforge.schemas.rule import (
    ImportReportOut,
    RuleCreateRequest,
    RuleDetail,
    RuleDiffResponse,
    RuleFilterOptions,
    RuleListItem,
    RuleUpdateRequest,
    RuleValidateRequest,
    RuleValidationResponse,
    RuleVersionDetail,
    RuleVersionOut,
)
from sentinelforge.services import audit, importer, quality, sigma_service
from sentinelforge.services import rules as rules_service
from sentinelforge.services.rules import RuleFilters, RuleNotFoundError, VersionNotFoundError
from sentinelforge.services.sigma_service import SigmaParseError

router = APIRouter(prefix="/rules", tags=["detection rules"])

MAX_UPLOAD_READ = 64 * 1024 * 1024  # absolute ceiling before settings check


def _get_or_404(db: DbSession, rule_id: uuid.UUID):  # type: ignore[no-untyped-def]
    try:
        return rules_service.get_rule(db, rule_id)
    except RuleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("", response_model=Page[RuleListItem])
def list_rules(
    user: AnalystUser,
    db: DbSession,
    search: Annotated[str | None, Query(max_length=200)] = None,
    rule_status: Annotated[RuleStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    logsource_product: Annotated[str | None, Query(max_length=100)] = None,
    logsource_category: Annotated[str | None, Query(max_length=100)] = None,
    author: Annotated[str | None, Query(max_length=200)] = None,
    tag: Annotated[str | None, Query(max_length=100)] = None,
    technique_id: Annotated[str | None, Query(max_length=20)] = None,
    include_archived: bool = False,
    untested: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[RuleListItem]:
    filters = RuleFilters(
        search=search,
        status=rule_status.value if rule_status else None,
        severity=severity.value if severity else None,
        logsource_product=logsource_product,
        logsource_category=logsource_category,
        author=author,
        tag=tag,
        technique_id=technique_id,
        include_archived=include_archived,
        untested=untested or None,
    )
    rows, total = rules_service.search_rules(db, filters, limit=limit, offset=offset)
    return Page[RuleListItem](
        items=[RuleListItem.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/filter-options", response_model=RuleFilterOptions)
def filter_options(user: AnalystUser, db: DbSession) -> RuleFilterOptions:
    return RuleFilterOptions.model_validate(rules_service.distinct_filter_values(db))


@router.post("/validate", response_model=RuleValidationResponse)
def validate_content(payload: RuleValidateRequest, user: AnalystUser) -> RuleValidationResponse:
    """Validate and score rule content without saving it.

    Powers live feedback in the rule editor, so an analyst sees problems before
    committing a version rather than after.
    """
    try:
        metadata = sigma_service.extract_metadata(payload.content)
    except SigmaParseError as exc:
        validation_status, issues = sigma_service.validate(payload.content)
        return RuleValidationResponse(
            validation_status=validation_status,
            issues=[i.as_dict() for i in issues],
            quality_score=0,
            quality_breakdown=[],
            quality_caveat=quality.SCORE_CAVEAT,
            parse_error=str(exc),
        )

    validation_status, issues = sigma_service.validate(payload.content)
    result = quality.score_rule(payload.content, metadata)

    try:
        preview = sigma_service.to_query(payload.content)
    except SigmaParseError:
        preview = None

    return RuleValidationResponse(
        validation_status=validation_status,
        issues=[i.as_dict() for i in issues],
        quality_score=result.score,
        quality_breakdown=result.as_list(),
        quality_caveat=quality.SCORE_CAVEAT,
        query_preview=preview,
    )


@router.post("", response_model=RuleDetail, status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: RuleCreateRequest, request: Request, user: AnalystUser, db: DbSession
) -> RuleDetail:
    try:
        rule = rules_service.create_rule(
            db,
            content=payload.content,
            user=user,
            is_demo=payload.is_demo,
            change_summary=payload.change_summary,
        )
    except SigmaParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    audit.record(
        db,
        action=AuditAction.RULE_CREATE,
        actor=user,
        entity_type="rule",
        entity_id=rule.id,
        detail={"title": rule.title},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(rule)
    return RuleDetail.model_validate(rule)


@router.get("/{rule_id:uuid}", response_model=RuleDetail)
def get_rule(rule_id: uuid.UUID, user: AnalystUser, db: DbSession) -> RuleDetail:
    return RuleDetail.model_validate(_get_or_404(db, rule_id))


@router.put("/{rule_id:uuid}", response_model=RuleDetail)
def update_rule(
    rule_id: uuid.UUID,
    payload: RuleUpdateRequest,
    request: Request,
    user: AnalystUser,
    db: DbSession,
) -> RuleDetail:
    rule = _get_or_404(db, rule_id)
    previous_version = rule.current_version
    try:
        rules_service.update_rule(
            db, rule, content=payload.content, user=user, change_summary=payload.change_summary
        )
    except SigmaParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    audit.record(
        db,
        action=AuditAction.RULE_UPDATE,
        actor=user,
        entity_type="rule",
        entity_id=rule.id,
        detail={"from_version": previous_version, "to_version": rule.current_version},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(rule)
    return RuleDetail.model_validate(rule)


@router.post("/{rule_id:uuid}/duplicate", response_model=RuleDetail, status_code=201)
def duplicate_rule(
    rule_id: uuid.UUID, request: Request, user: AnalystUser, db: DbSession
) -> RuleDetail:
    source = _get_or_404(db, rule_id)
    copy = rules_service.duplicate_rule(db, source, user=user)
    audit.record(
        db,
        action=AuditAction.RULE_DUPLICATE,
        actor=user,
        entity_type="rule",
        entity_id=copy.id,
        detail={"source_rule_id": str(source.id)},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(copy)
    return RuleDetail.model_validate(copy)


@router.post("/{rule_id:uuid}/archive", response_model=RuleDetail)
def archive_rule(
    rule_id: uuid.UUID, request: Request, user: AnalystUser, db: DbSession
) -> RuleDetail:
    rule = _get_or_404(db, rule_id)
    rules_service.archive_rule(db, rule)
    audit.record(
        db,
        action=AuditAction.RULE_ARCHIVE,
        actor=user,
        entity_type="rule",
        entity_id=rule.id,
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(rule)
    return RuleDetail.model_validate(rule)


@router.post("/{rule_id:uuid}/unarchive", response_model=RuleDetail)
def unarchive_rule(
    rule_id: uuid.UUID, request: Request, user: AnalystUser, db: DbSession
) -> RuleDetail:
    rule = _get_or_404(db, rule_id)
    rules_service.unarchive_rule(db, rule)
    db.commit()
    db.refresh(rule)
    return RuleDetail.model_validate(rule)


@router.delete("/{rule_id:uuid}", response_model=MessageResponse)
def delete_rule(
    rule_id: uuid.UUID, request: Request, admin: AdminUser, db: DbSession
) -> MessageResponse:
    """Permanently delete a rule and its history. Admin-only and irreversible.

    Archiving is the reversible option and is available to analysts; this is not.
    """
    rule = _get_or_404(db, rule_id)
    title = rule.title
    audit.record(
        db,
        action=AuditAction.RULE_DELETE,
        actor=admin,
        entity_type="rule",
        entity_id=rule.id,
        detail={"title": title, "versions": rule.current_version},
        ip_address=get_client_ip(request),
    )
    rules_service.delete_rule(db, rule)
    db.commit()
    return MessageResponse(message=f"Deleted rule '{title}' and its version history.")


# --------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------


@router.get("/{rule_id:uuid}/versions", response_model=list[RuleVersionOut])
def list_versions(rule_id: uuid.UUID, user: AnalystUser, db: DbSession) -> list[RuleVersionOut]:
    rule = _get_or_404(db, rule_id)
    return [RuleVersionOut.model_validate(v) for v in rules_service.list_versions(db, rule)]


@router.get("/{rule_id:uuid}/versions/{version_number}", response_model=RuleVersionDetail)
def get_version(
    rule_id: uuid.UUID, version_number: int, user: AnalystUser, db: DbSession
) -> RuleVersionDetail:
    rule = _get_or_404(db, rule_id)
    try:
        return RuleVersionDetail.model_validate(rules_service.get_version(db, rule, version_number))
    except VersionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{rule_id:uuid}/diff", response_model=RuleDiffResponse)
def diff_versions(
    rule_id: uuid.UUID,
    user: AnalystUser,
    db: DbSession,
    from_version: Annotated[int, Query(ge=1)],
    to_version: Annotated[int, Query(ge=1)],
) -> RuleDiffResponse:
    rule = _get_or_404(db, rule_id)
    try:
        diff = rules_service.diff_versions(db, rule, from_version, to_version)
    except VersionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return RuleDiffResponse(
        rule_id=rule.id,
        from_version=from_version,
        to_version=to_version,
        diff=diff,
        identical=diff == "",
    )


@router.post("/{rule_id:uuid}/versions/{version_number}/restore", response_model=RuleDetail)
def restore_version(
    rule_id: uuid.UUID,
    version_number: int,
    request: Request,
    user: AnalystUser,
    db: DbSession,
) -> RuleDetail:
    rule = _get_or_404(db, rule_id)
    try:
        rules_service.restore_version(db, rule, version_number, user=user)
    except VersionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    audit.record(
        db,
        action=AuditAction.RULE_RESTORE_VERSION,
        actor=user,
        entity_type="rule",
        entity_id=rule.id,
        detail={"restored_from": version_number, "new_version": rule.current_version},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(rule)
    return RuleDetail.model_validate(rule)


# --------------------------------------------------------------------------
# Import / export
# --------------------------------------------------------------------------


@router.post("/import/yaml", response_model=RuleDetail, status_code=201)
async def import_yaml(
    request: Request,
    user: AnalystUser,
    db: DbSession,
    file: Annotated[UploadFile, File(description="A single Sigma .yml/.yaml rule")],
) -> RuleDetail:
    settings = get_settings()
    raw = await file.read(settings.max_yaml_bytes + 1)
    if len(raw) > settings.max_yaml_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Rule file exceeds the {settings.max_yaml_bytes} byte limit",
        )
    filename = (file.filename or "uploaded.yml")[:200]
    if not filename.lower().endswith((".yml", ".yaml")):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only .yml and .yaml files are accepted",
        )
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="File is not valid UTF-8"
        ) from exc

    try:
        rule = importer.import_rule_yaml(db, content=content, user=user, filename=filename)
    except SigmaParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    audit.record(
        db,
        action=AuditAction.RULE_IMPORT,
        actor=user,
        entity_type="rule",
        entity_id=rule.id,
        detail={"filename": filename, "source": "yaml"},
        ip_address=get_client_ip(request),
    )
    db.commit()
    db.refresh(rule)
    return RuleDetail.model_validate(rule)


@router.post("/import/archive", response_model=ImportReportOut)
async def import_archive(
    request: Request,
    user: AnalystUser,
    db: DbSession,
    file: Annotated[UploadFile, File(description="ZIP archive containing Sigma rules")],
) -> ImportReportOut:
    settings = get_settings()
    raw = await file.read(settings.max_upload_bytes + 1)
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Archive exceeds the {settings.max_upload_bytes} byte limit",
        )

    try:
        report = importer.import_rule_archive(db, data=raw, user=user)
    except importer.ImportError_ as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    audit.record(
        db,
        action=AuditAction.RULE_IMPORT,
        actor=user,
        entity_type="rule_archive",
        detail={
            "filename": (file.filename or "")[:200],
            "imported": report.imported_count,
            "rejected": report.rejected_count,
        },
        ip_address=get_client_ip(request),
    )
    db.commit()
    return ImportReportOut.model_validate(report.as_dict())


@router.get("/{rule_id:uuid}/export", response_class=Response)
def export_rule(rule_id: uuid.UUID, request: Request, user: AnalystUser, db: DbSession) -> Response:
    rule = _get_or_404(db, rule_id)
    audit.record(
        db,
        action=AuditAction.RULE_EXPORT,
        actor=user,
        entity_type="rule",
        entity_id=rule.id,
        ip_address=get_client_ip(request),
    )
    db.commit()
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in rule.title.lower())[:80]
    return Response(
        content=rule.content,
        media_type="application/yaml",
        headers={"Content-Disposition": f'attachment; filename="{safe_name or "rule"}.yml"'},
    )


@router.post("/export/archive", response_class=Response)
def export_archive(
    request: Request,
    user: AnalystUser,
    db: DbSession,
    rule_ids: list[uuid.UUID] | None = None,
) -> Response:
    """Export selected rules (or the whole active library) as a ZIP."""
    if rule_ids:
        rows = [_get_or_404(db, rid) for rid in rule_ids[:500]]
    else:
        rows, _total = rules_service.search_rules(db, RuleFilters(), limit=500, offset=0)

    payload = importer.export_rules_archive(rows)
    audit.record(
        db,
        action=AuditAction.RULE_EXPORT,
        actor=user,
        entity_type="rule_archive",
        detail={"count": len(rows)},
        ip_address=get_client_ip(request),
    )
    db.commit()
    return Response(
        content=payload,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="sentinelforge-rules.zip"'},
    )
