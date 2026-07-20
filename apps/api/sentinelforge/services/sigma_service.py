"""Sigma rule parsing, validation, and conversion.

Everything here runs **in-process**. No `subprocess`, no shell, no temporary files.
Rule content arrives from uploads and public repositories, so it is treated as hostile
input even though the uploader is authenticated.

YAML is loaded with `safe_load` only, which cannot instantiate Python objects, and is
bounded on both document size and nesting depth before pySigma ever sees it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml
from sigma.backends.test import TextQueryTestBackend  # type: ignore[attr-defined]
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators

from sentinelforge.core.config import get_settings
from sentinelforge.models.enums import IssueSeverity, RuleStatus, Severity, ValidationStatus

# Sigma tags look like `attack.t1059.001` or `attack.defense_evasion`.
TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# ATT&CK v19 renamed Defense Evasion to Stealth (TA0005) and split out Defense
# Impairment (TA0112). Rules in the wild still carry the old tag, so it is mapped
# rather than dropped — silently losing a tactic tag would understate coverage.
TACTIC_TAG_ALIASES = {
    "defense_evasion": "stealth",
    "defense-evasion": "stealth",
}

_SIGMA_STATUS_TO_ENUM = {s.value: s for s in RuleStatus}
_SIGMA_LEVEL_TO_ENUM = {s.value: s for s in Severity}


class SigmaParseError(ValueError):
    """Rule content could not be parsed as a Sigma rule."""


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    severity: IssueSeverity
    message: str
    context: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "context": self.context,
        }


@dataclass
class RuleMetadata:
    title: str = ""
    sigma_id: str | None = None
    description: str = ""
    status: str = RuleStatus.DRAFT.value
    severity: str = Severity.MEDIUM.value
    author: str = ""
    logsource_category: str | None = None
    logsource_product: str | None = None
    logsource_service: str | None = None
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    tactic_names: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Safe loading
# --------------------------------------------------------------------------


def _max_depth(node: Any, depth: int = 0, limit: int = 100) -> int:
    """Depth of a parsed YAML structure, short-circuiting once the limit is passed."""
    if depth > limit:
        return depth
    if isinstance(node, dict):
        return max((_max_depth(v, depth + 1, limit) for v in node.values()), default=depth)
    if isinstance(node, list):
        return max((_max_depth(v, depth + 1, limit) for v in node), default=depth)
    return depth


def load_yaml_documents(content: str) -> list[Any]:
    """Parse YAML with hard bounds. Never uses `yaml.load`.

    `safe_load` refuses `!!python/...` tags outright, so arbitrary object construction
    is impossible. The size and depth caps address resource exhaustion, which
    `safe_load` does *not* protect against on its own.
    """
    settings = get_settings()

    encoded_size = len(content.encode("utf-8"))
    if encoded_size > settings.max_yaml_bytes:
        raise SigmaParseError(
            f"Rule document is {encoded_size} bytes, exceeding the "
            f"{settings.max_yaml_bytes} byte limit"
        )
    if not content.strip():
        raise SigmaParseError("Rule document is empty")

    try:
        documents = list(yaml.safe_load_all(content))
    except yaml.YAMLError as exc:
        raise SigmaParseError(f"Invalid YAML: {exc}") from exc

    documents = [d for d in documents if d is not None]
    if not documents:
        raise SigmaParseError("Rule document contains no YAML documents")

    for document in documents:
        if not isinstance(document, dict):
            raise SigmaParseError("Each Sigma document must be a mapping at the top level")
        if _max_depth(document, limit=settings.max_yaml_depth) > settings.max_yaml_depth:
            raise SigmaParseError(
                f"Rule structure nests deeper than the {settings.max_yaml_depth} level limit"
            )
    return documents


def parse_collection(content: str) -> SigmaCollection:
    """Parse into a pySigma collection after the safety checks have passed."""
    load_yaml_documents(content)
    try:
        collection = SigmaCollection.from_yaml(content)
    except SigmaError as exc:
        raise SigmaParseError(f"Not a valid Sigma rule: {exc}") from exc
    except Exception as exc:  # pySigma raises assorted types on malformed input
        raise SigmaParseError(f"Could not parse Sigma rule: {exc}") from exc

    if not collection.rules:
        raise SigmaParseError("No Sigma rules found in the document")
    return collection


def parse_rule(content: str) -> SigmaRule:
    """Parse and return the first rule in the document."""
    rule = parse_collection(content).rules[0]
    if not isinstance(rule, SigmaRule):
        raise SigmaParseError("Correlation rules must accompany the base rule they refer to")
    return rule


# --------------------------------------------------------------------------
# Metadata
# --------------------------------------------------------------------------


def extract_technique_ids(tags: list[str]) -> list[str]:
    """Pull `T####[.###]` identifiers out of Sigma `attack.*` tags, uppercased."""
    found: list[str] = []
    for tag in tags:
        match = TECHNIQUE_TAG_RE.match(tag.strip())
        if match:
            technique = match.group(1).upper()
            if technique not in found:
                found.append(technique)
    return found


def extract_tactic_names(tags: list[str]) -> list[str]:
    """Pull tactic shortnames out of `attack.*` tags, applying v19 renames."""
    found: list[str] = []
    for tag in tags:
        raw = tag.strip().lower()
        if not raw.startswith("attack."):
            continue
        value = raw.removeprefix("attack.")
        if TECHNIQUE_TAG_RE.match(raw):
            continue
        value = TACTIC_TAG_ALIASES.get(value, value).replace("_", "-")
        if value not in found:
            found.append(value)
    return found


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def extract_metadata(content: str) -> RuleMetadata:
    """Derive the searchable/filterable columns from rule YAML.

    Read from the raw document rather than the pySigma object so that fields pySigma
    does not model (or normalises away) still round-trip faithfully.
    """
    rule = parse_rule(content)
    document = load_yaml_documents(content)[0]

    logsource = document.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {}

    tags = [str(t) for t in _as_str_list(document.get("tags"))]
    raw_status = str(document.get("status", "")).lower().strip()
    raw_level = str(document.get("level", "")).lower().strip()

    return RuleMetadata(
        title=str(document.get("title", "")).strip() or rule.title or "Untitled rule",
        sigma_id=str(document["id"]).strip() if document.get("id") else None,
        description=str(document.get("description", "")).strip(),
        status=(_SIGMA_STATUS_TO_ENUM.get(raw_status, RuleStatus.DRAFT).value),
        severity=(_SIGMA_LEVEL_TO_ENUM.get(raw_level, Severity.MEDIUM).value),
        author=str(document.get("author", "")).strip(),
        logsource_category=(str(logsource["category"]) if logsource.get("category") else None),
        logsource_product=(str(logsource["product"]) if logsource.get("product") else None),
        logsource_service=(str(logsource["service"]) if logsource.get("service") else None),
        tags=tags,
        references=_as_str_list(document.get("references")),
        falsepositives=_as_str_list(document.get("falsepositives")),
        technique_ids=extract_technique_ids(tags),
        tactic_names=extract_tactic_names(tags),
    )


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

_PYSIGMA_SEVERITY_MAP = {
    "high": IssueSeverity.ERROR,
    "medium": IssueSeverity.WARNING,
    "low": IssueSeverity.INFO,
}


def _sentinelforge_checks(content: str) -> list[ValidationIssue]:
    """Checks specific to this platform, layered on top of pySigma's."""
    issues: list[ValidationIssue] = []
    settings = get_settings()
    document = load_yaml_documents(content)[0]

    detection = document.get("detection")
    if not isinstance(detection, dict) or set(detection) <= {"condition"}:
        issues.append(
            ValidationIssue(
                code="empty_detection",
                severity=IssueSeverity.ERROR,
                message="The rule defines no detection selections",
            )
        )

    # An over-long regex is the practical ReDoS lever available to a rule author.
    for match in re.finditer(r"\|re\s*:\s*(.+)", content):
        pattern = match.group(1).strip()
        if len(pattern) > settings.max_regex_length:
            issues.append(
                ValidationIssue(
                    code="regex_too_long",
                    severity=IssueSeverity.ERROR,
                    message=(
                        f"Regular expression is {len(pattern)} characters, over the "
                        f"{settings.max_regex_length} limit"
                    ),
                )
            )
        if re.search(r"\((?:[^()]*[+*]){2,}[^()]*\)[+*]", pattern):
            issues.append(
                ValidationIssue(
                    code="regex_nested_quantifier",
                    severity=IssueSeverity.WARNING,
                    message=(
                        "Nested quantifiers can backtrack catastrophically; "
                        "consider rewriting this pattern"
                    ),
                    context=pattern[:120],
                )
            )
    return issues


def validate(content: str) -> tuple[ValidationStatus, list[ValidationIssue]]:
    """Validate rule content, returning an overall status plus every issue found."""
    issues: list[ValidationIssue] = []

    try:
        collection = parse_collection(content)
    except SigmaParseError as exc:
        return ValidationStatus.INVALID, [
            ValidationIssue(code="parse_error", severity=IssueSeverity.ERROR, message=str(exc))
        ]

    try:
        validator = SigmaValidator(list(core_validators.values()))
        # Correlation rules are validated as part of the base rules they reference,
        # and the core validators only accept SigmaRule instances.
        plain_rules = (r for r in collection.rules if isinstance(r, SigmaRule))
        for issue in validator.validate_rules(plain_rules):
            severity_name = getattr(issue.severity, "name", str(issue.severity)).lower()
            issues.append(
                ValidationIssue(
                    code=type(issue).__name__,
                    severity=_PYSIGMA_SEVERITY_MAP.get(severity_name, IssueSeverity.INFO),
                    message=getattr(issue, "description", str(issue)),
                    context=str(issue)[:300],
                )
            )
    except Exception as exc:
        issues.append(
            ValidationIssue(
                code="validator_error",
                severity=IssueSeverity.INFO,
                message=f"Some validators could not run: {exc}",
            )
        )

    issues.extend(_sentinelforge_checks(content))

    if any(i.severity is IssueSeverity.ERROR for i in issues):
        return ValidationStatus.INVALID, issues
    if any(i.severity is IssueSeverity.WARNING for i in issues):
        return ValidationStatus.WARNINGS, issues
    return ValidationStatus.VALID, issues


# --------------------------------------------------------------------------
# Conversion
# --------------------------------------------------------------------------


def to_query(content: str) -> str:
    """Render the detection logic as a readable generic query.

    Uses pySigma's bundled text backend — a vendor-neutral rendering intended to help
    an analyst read the logic, not to be pasted into a specific SIEM. Adding a real
    target (`pysigma-backend-elasticsearch`, `-splunk`, …) is a one-line change here.
    """
    collection = parse_collection(content)
    try:
        queries = TextQueryTestBackend().convert(collection)
    except Exception as exc:
        raise SigmaParseError(f"Could not convert rule to a query: {exc}") from exc
    return "\n".join(str(q) for q in queries)
