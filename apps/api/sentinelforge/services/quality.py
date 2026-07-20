"""Explainable detection-rule quality scoring.

**What this score is:** a measure of rule *hygiene* — is it documented, mapped,
tested, and scoped to a log source an analyst can actually collect?

**What this score is not:** a measure of detection efficacy. A rule can score 100 and
detect nothing of value, or score 40 and be the most important rule you own. It is
deliberately transparent — every criterion returns the reason it awarded what it did,
so the number can be argued with rather than trusted blindly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinelforge.models.enums import RuleStatus
from sentinelforge.services.sigma_service import RuleMetadata, load_yaml_documents

SCORE_CAVEAT = (
    "This score measures rule hygiene — metadata, mappings, documentation and test "
    "coverage. It does not measure how effectively the rule detects real activity."
)


@dataclass(frozen=True)
class CriterionResult:
    key: str
    label: str
    earned: int
    maximum: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "earned": self.earned,
            "maximum": self.maximum,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class QualityResult:
    score: int
    criteria: list[CriterionResult]

    def as_list(self) -> list[dict[str, Any]]:
        return [c.as_dict() for c in self.criteria]


# Deliberately weighted toward the things that make a rule maintainable by someone
# other than its author: mappings, documentation, and tests.
WEIGHTS = {
    "metadata": 15,
    "logsource": 10,
    "detection_logic": 15,
    "attack_mapping": 15,
    "falsepositives": 10,
    "references": 10,
    "test_coverage": 15,
    "status": 5,
    "descriptive_text": 5,
}
MAX_SCORE = sum(WEIGHTS.values())


def _score_metadata(meta: RuleMetadata) -> CriterionResult:
    present = {
        "title": bool(meta.title.strip()),
        "id": bool(meta.sigma_id),
        "author": bool(meta.author.strip()),
        "description": bool(meta.description.strip()),
    }
    have = sum(present.values())
    earned = round(WEIGHTS["metadata"] * have / len(present))
    missing = [k for k, v in present.items() if not v]
    reason = "All required metadata present" if not missing else f"Missing: {', '.join(missing)}"
    return CriterionResult("metadata", "Required metadata", earned, WEIGHTS["metadata"], reason)


def _score_logsource(meta: RuleMetadata) -> CriterionResult:
    parts = [meta.logsource_product, meta.logsource_category, meta.logsource_service]
    filled = [p for p in parts if p]
    maximum = WEIGHTS["logsource"]
    if not filled:
        return CriterionResult(
            "logsource",
            "Log source",
            0,
            maximum,
            "No log source declared — the rule cannot be routed to a data source",
        )
    if len(filled) == 1:
        return CriterionResult(
            "logsource",
            "Log source",
            maximum // 2,
            maximum,
            f"Only one log source field set ({filled[0]}); narrow it further if possible",
        )
    return CriterionResult(
        "logsource",
        "Log source",
        maximum,
        maximum,
        f"Log source scoped to {' / '.join(filled)}",
    )


def _score_detection_logic(content: str) -> CriterionResult:
    maximum = WEIGHTS["detection_logic"]
    try:
        document = load_yaml_documents(content)[0]
    except Exception:
        return CriterionResult(
            "detection_logic", "Detection logic", 0, maximum, "Rule content could not be parsed"
        )

    detection = document.get("detection")
    if not isinstance(detection, dict):
        return CriterionResult(
            "detection_logic", "Detection logic", 0, maximum, "No detection block found"
        )

    selections = [k for k in detection if k != "condition"]
    condition = str(detection.get("condition", "")).strip()

    if not selections or not condition:
        return CriterionResult(
            "detection_logic",
            "Detection logic",
            0,
            maximum,
            "Detection block needs both a selection and a condition",
        )

    # A rule that only ever says "sel" with one field is usually too broad to survive
    # contact with production; one that filters is usually thought through.
    has_filter = any("filter" in s.lower() or "exclu" in s.lower() for s in selections)
    field_count = sum(len(v) for v in detection.values() if isinstance(v, dict))

    if has_filter and field_count >= 2:
        return CriterionResult(
            "detection_logic",
            "Detection logic",
            maximum,
            maximum,
            f"{len(selections)} selections with filtering and {field_count} field conditions",
        )
    if field_count >= 2:
        return CriterionResult(
            "detection_logic",
            "Detection logic",
            round(maximum * 0.8),
            maximum,
            f"{field_count} field conditions, but no exclusion/filter selection",
        )
    return CriterionResult(
        "detection_logic",
        "Detection logic",
        round(maximum * 0.5),
        maximum,
        "Only one field condition — likely to be noisy",
    )


def _score_attack(meta: RuleMetadata) -> CriterionResult:
    maximum = WEIGHTS["attack_mapping"]
    if meta.technique_ids:
        return CriterionResult(
            "attack_mapping",
            "ATT&CK mapping",
            maximum,
            maximum,
            f"Mapped to {', '.join(meta.technique_ids)}",
        )
    if meta.tactic_names:
        return CriterionResult(
            "attack_mapping",
            "ATT&CK mapping",
            maximum // 2,
            maximum,
            "Tactic tagged but no technique — add a T#### tag for coverage tracking",
        )
    return CriterionResult(
        "attack_mapping",
        "ATT&CK mapping",
        0,
        maximum,
        "No ATT&CK tags, so this rule contributes nothing to coverage reporting",
    )


def _score_falsepositives(meta: RuleMetadata) -> CriterionResult:
    maximum = WEIGHTS["falsepositives"]
    useful = [fp for fp in meta.falsepositives if fp.strip().lower() not in {"unknown", "none", ""}]
    if useful:
        return CriterionResult(
            "falsepositives",
            "False-positive notes",
            maximum,
            maximum,
            f"{len(useful)} documented false-positive scenario(s)",
        )
    if meta.falsepositives:
        return CriterionResult(
            "falsepositives",
            "False-positive notes",
            maximum // 3,
            maximum,
            "False positives listed as 'unknown' — the responder gets no help from that",
        )
    return CriterionResult(
        "falsepositives",
        "False-positive notes",
        0,
        maximum,
        "No false-positive guidance for whoever triages this alert",
    )


def _score_references(meta: RuleMetadata) -> CriterionResult:
    maximum = WEIGHTS["references"]
    count = len([r for r in meta.references if r.strip()])
    if count >= 2:
        return CriterionResult(
            "references", "References", maximum, maximum, f"{count} references provided"
        )
    if count == 1:
        return CriterionResult(
            "references", "References", maximum // 2, maximum, "One reference provided"
        )
    return CriterionResult(
        "references", "References", 0, maximum, "No references explaining the detected behaviour"
    )


def _score_tests(test_count: int, passing_count: int) -> CriterionResult:
    maximum = WEIGHTS["test_coverage"]
    if test_count == 0:
        return CriterionResult(
            "test_coverage",
            "Test coverage",
            0,
            maximum,
            "Never tested against a dataset — behaviour is unverified",
        )
    if passing_count == 0:
        return CriterionResult(
            "test_coverage",
            "Test coverage",
            maximum // 4,
            maximum,
            f"{test_count} test run(s), none currently passing",
        )
    if passing_count >= 2:
        return CriterionResult(
            "test_coverage",
            "Test coverage",
            maximum,
            maximum,
            f"{passing_count} passing test(s) of {test_count}",
        )
    return CriterionResult(
        "test_coverage",
        "Test coverage",
        round(maximum * 0.7),
        maximum,
        "One passing test — add a negative test to check for false positives",
    )


def _score_status(meta: RuleMetadata) -> CriterionResult:
    maximum = WEIGHTS["status"]
    mature = {RuleStatus.STABLE.value, RuleStatus.TEST.value}
    if meta.status in mature:
        return CriterionResult(
            "status",
            "Lifecycle status",
            maximum,
            maximum,
            f"Status '{meta.status}' indicates a reviewed rule",
        )
    if meta.status in {RuleStatus.DEPRECATED.value, RuleStatus.UNSUPPORTED.value}:
        return CriterionResult(
            "status",
            "Lifecycle status",
            0,
            maximum,
            f"Status '{meta.status}' — this rule should not be relied on",
        )
    return CriterionResult(
        "status",
        "Lifecycle status",
        maximum // 2,
        maximum,
        f"Status '{meta.status}' — not yet promoted",
    )


def _score_descriptive_text(meta: RuleMetadata) -> CriterionResult:
    maximum = WEIGHTS["descriptive_text"]
    title_ok = len(meta.title.strip()) >= 15 and " " in meta.title.strip()
    description_ok = len(meta.description.strip()) >= 40

    if title_ok and description_ok:
        return CriterionResult(
            "descriptive_text",
            "Meaningful title & description",
            maximum,
            maximum,
            "Title and description are substantive",
        )
    problems = []
    if not title_ok:
        problems.append("title is too short to be self-explanatory")
    if not description_ok:
        problems.append("description is under 40 characters")
    return CriterionResult(
        "descriptive_text",
        "Meaningful title & description",
        maximum // 2 if (title_ok or description_ok) else 0,
        maximum,
        "; ".join(problems),
    )


def score_rule(
    content: str,
    metadata: RuleMetadata,
    *,
    test_count: int = 0,
    passing_test_count: int = 0,
) -> QualityResult:
    """Score a rule out of 100 and explain every point awarded or withheld."""
    criteria = [
        _score_metadata(metadata),
        _score_logsource(metadata),
        _score_detection_logic(content),
        _score_attack(metadata),
        _score_falsepositives(metadata),
        _score_references(metadata),
        _score_tests(test_count, passing_test_count),
        _score_status(metadata),
        _score_descriptive_text(metadata),
    ]
    return QualityResult(score=sum(c.earned for c in criteria), criteria=criteria)
