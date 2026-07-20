"""Sigma parsing, validation, quality scoring, and conversion."""

from __future__ import annotations

import pytest

from sentinelforge.models.enums import IssueSeverity, RuleStatus, Severity, ValidationStatus
from sentinelforge.services import quality, sigma_service
from sentinelforge.services.sigma_service import SigmaParseError

GOOD_RULE = """
title: Suspicious PowerShell Encoded Command Execution
id: 6f3e2a10-6c1b-4f6a-9a1e-2f0d5c8b7a31
status: test
description: >
    Detects PowerShell started with an encoded command argument, a common way to
    obscure script content from casual inspection and log review.
author: SentinelForge Demo
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://learn.microsoft.com/powershell/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
    filter_known_good:
        ParentImage|endswith: '\\ConfigMgr.exe'
    condition: selection and not filter_known_good
falsepositives:
    - Administrative automation that legitimately base64-encodes parameters
    - Some software deployment tools invoke encoded commands
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""

MINIMAL_RULE = """
title: Bare
logsource:
    product: windows
detection:
    sel:
        Image: cmd.exe
    condition: sel
"""


class TestSafeLoading:
    def test_parses_valid_rule(self) -> None:
        rule = sigma_service.parse_rule(GOOD_RULE)
        assert rule.title.startswith("Suspicious PowerShell")

    def test_rejects_python_object_tag(self) -> None:
        """The headline YAML risk: `safe_load` must refuse to construct objects."""
        malicious = "title: x\ndetection: !!python/object/apply:os.system ['echo pwned']\n"
        with pytest.raises(SigmaParseError):
            sigma_service.load_yaml_documents(malicious)

    def test_rejects_malformed_yaml(self) -> None:
        with pytest.raises(SigmaParseError, match="Invalid YAML"):
            sigma_service.load_yaml_documents("title: [unclosed\n  bracket: yes")

    def test_rejects_empty_document(self) -> None:
        with pytest.raises(SigmaParseError):
            sigma_service.load_yaml_documents("   \n  \n")

    def test_rejects_oversized_document(self) -> None:
        oversized = "title: x\ndescription: " + ("A" * 600_000)
        with pytest.raises(SigmaParseError, match="exceeding"):
            sigma_service.load_yaml_documents(oversized)

    def test_rejects_deeply_nested_document(self) -> None:
        """Deep nesting is a resource-exhaustion vector that safe_load does not stop."""
        payload = "title: x\ndetection:\n"
        nested = "a: " + "{b: " * 60 + "1" + "}" * 60
        with pytest.raises(SigmaParseError, match="nests deeper"):
            sigma_service.load_yaml_documents(payload + "  " + nested)

    def test_rejects_non_mapping_document(self) -> None:
        with pytest.raises(SigmaParseError, match="mapping"):
            sigma_service.load_yaml_documents("- just\n- a\n- list")

    def test_rejects_non_sigma_yaml(self) -> None:
        with pytest.raises(SigmaParseError):
            sigma_service.parse_rule("some_key: some_value\nanother: thing")


class TestMetadata:
    def test_extracts_all_fields(self) -> None:
        meta = sigma_service.extract_metadata(GOOD_RULE)
        assert meta.title == "Suspicious PowerShell Encoded Command Execution"
        assert meta.sigma_id == "6f3e2a10-6c1b-4f6a-9a1e-2f0d5c8b7a31"
        assert meta.status == RuleStatus.TEST.value
        assert meta.severity == Severity.HIGH.value
        assert meta.author == "SentinelForge Demo"
        assert meta.logsource_product == "windows"
        assert meta.logsource_category == "process_creation"
        assert len(meta.references) == 2
        assert len(meta.falsepositives) == 2

    def test_extracts_technique_ids(self) -> None:
        meta = sigma_service.extract_metadata(GOOD_RULE)
        assert meta.technique_ids == ["T1059.001"]
        assert "execution" in meta.tactic_names

    def test_defaults_when_fields_absent(self) -> None:
        meta = sigma_service.extract_metadata(MINIMAL_RULE)
        assert meta.status == RuleStatus.DRAFT.value
        assert meta.severity == Severity.MEDIUM.value
        assert meta.technique_ids == []

    def test_subtechnique_and_parent_tags(self) -> None:
        assert sigma_service.extract_technique_ids(["attack.t1003"]) == ["T1003"]
        assert sigma_service.extract_technique_ids(["attack.T1218.011"]) == ["T1218.011"]
        assert sigma_service.extract_technique_ids(["attack.execution", "cve.2021.4034"]) == []

    def test_defense_evasion_tag_maps_to_v19_stealth(self) -> None:
        """ATT&CK v19 renamed Defense Evasion to Stealth.

        Rules in the wild still carry the old tag. Dropping it would silently
        understate coverage for one of the largest tactics in the matrix.
        """
        tactics = sigma_service.extract_tactic_names(["attack.defense_evasion"])
        assert tactics == ["stealth"]


class TestValidation:
    def test_good_rule_is_valid(self) -> None:
        status, issues = sigma_service.validate(GOOD_RULE)
        assert status is ValidationStatus.VALID, [i.message for i in issues]

    def test_unparseable_rule_is_invalid(self) -> None:
        status, issues = sigma_service.validate("title: [broken")
        assert status is ValidationStatus.INVALID
        assert issues[0].code == "parse_error"

    def test_dangling_detection_is_reported(self) -> None:
        rule = """
title: Dangling selection example
id: 3a1f6b2c-1111-2222-3333-444455556666
logsource: {product: windows}
detection:
    used: {Image: cmd.exe}
    never_referenced: {Image: powershell.exe}
    condition: used
"""
        _status, issues = sigma_service.validate(rule)
        assert any("not referenced" in i.message.lower() for i in issues)

    def test_missing_identifier_is_reported(self) -> None:
        _status, issues = sigma_service.validate(MINIMAL_RULE)
        assert any("identifier" in i.message.lower() for i in issues)

    def test_overlong_regex_rejected(self) -> None:
        rule = f"""
title: Overlong regex rule
id: 4b2f6c3d-1111-2222-3333-444455556666
logsource: {{product: windows}}
detection:
    sel:
        CommandLine|re: '{"a" * 1200}'
    condition: sel
"""
        status, issues = sigma_service.validate(rule)
        assert status is ValidationStatus.INVALID
        assert any(i.code == "regex_too_long" for i in issues)

    def test_nested_quantifier_warned(self) -> None:
        rule = """
title: Nested quantifier rule
id: 5c3f7d4e-1111-2222-3333-444455556666
logsource: {product: windows}
detection:
    sel:
        CommandLine|re: '(a+b+)+c'
    condition: sel
"""
        _status, issues = sigma_service.validate(rule)
        assert any(i.code == "regex_nested_quantifier" for i in issues)

    def test_empty_detection_rejected(self) -> None:
        # pySigma itself rejects a detection block with only a condition, so this
        # surfaces as a parse error rather than reaching our own check.
        status, _issues = sigma_service.validate(
            "title: x\nid: 6d4f8e5f-1111-2222-3333-444455556666\n"
            "logsource: {product: windows}\ndetection:\n    condition: sel\n"
        )
        assert status is ValidationStatus.INVALID

    def test_issue_severities_are_mapped(self) -> None:
        _status, issues = sigma_service.validate(MINIMAL_RULE)
        assert all(isinstance(i.severity, IssueSeverity) for i in issues)


class TestQualityScoring:
    def test_well_formed_rule_scores_high(self) -> None:
        meta = sigma_service.extract_metadata(GOOD_RULE)
        result = quality.score_rule(GOOD_RULE, meta, test_count=2, passing_test_count=2)
        assert result.score >= 90
        assert len(result.criteria) == 9
        assert sum(c.maximum for c in result.criteria) == quality.MAX_SCORE

    def test_minimal_rule_scores_low(self) -> None:
        meta = sigma_service.extract_metadata(MINIMAL_RULE)
        result = quality.score_rule(MINIMAL_RULE, meta)
        assert result.score < 40

    def test_every_criterion_explains_itself(self) -> None:
        """The score is only defensible if each point awarded has a stated reason."""
        meta = sigma_service.extract_metadata(MINIMAL_RULE)
        result = quality.score_rule(MINIMAL_RULE, meta)
        for criterion in result.criteria:
            assert criterion.reason.strip(), f"{criterion.key} gave no reason"
            assert 0 <= criterion.earned <= criterion.maximum

    def test_untested_rule_loses_test_points(self) -> None:
        meta = sigma_service.extract_metadata(GOOD_RULE)
        untested = quality.score_rule(GOOD_RULE, meta, test_count=0)
        tested = quality.score_rule(GOOD_RULE, meta, test_count=3, passing_test_count=3)
        assert tested.score > untested.score

    def test_score_never_exceeds_maximum(self) -> None:
        meta = sigma_service.extract_metadata(GOOD_RULE)
        result = quality.score_rule(GOOD_RULE, meta, test_count=99, passing_test_count=99)
        assert result.score <= quality.MAX_SCORE == 100

    def test_scoring_survives_unparseable_content(self) -> None:
        meta = sigma_service.extract_metadata(GOOD_RULE)
        result = quality.score_rule("title: [broken", meta)
        assert result.score >= 0  # must not raise


class TestConversion:
    def test_converts_to_readable_query(self) -> None:
        query = sigma_service.to_query(GOOD_RULE)
        assert "CommandLine" in query
        assert "Image" in query

    def test_conversion_failure_raises_parse_error(self) -> None:
        with pytest.raises(SigmaParseError):
            sigma_service.to_query("title: [broken")
