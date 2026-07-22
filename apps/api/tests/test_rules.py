"""Rule management: CRUD, versioning, diff/restore, search, import/export."""

from __future__ import annotations

import io
import uuid
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sentinelforge.models import DetectionRule, RuleVersion
from sentinelforge.services import importer
from sentinelforge.services import rules as rules_service
from sentinelforge.services.importer import ImportError_


def sample_rule(
    title: str = "Encoded PowerShell Command Execution", tag: str = "attack.t1059.001"
) -> str:
    return f"""
title: {title}
id: {uuid.uuid4()}
status: test
description: A demonstration rule used by the SentinelForge test suite for verification.
author: SentinelForge Tests
references:
    - https://attack.mitre.org/techniques/T1059/001/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ' -enc '
    filter_legit:
        ParentImage|endswith: '\\TrustedDeploy.exe'
    condition: selection and not filter_legit
falsepositives:
    - Deployment tooling that legitimately encodes commands
level: high
tags:
    - {tag}
"""


def make_zip(entries: dict[str, str | bytes], *, symlink_names: set[str] | None = None) -> bytes:
    buffer = io.BytesIO()
    symlink_names = symlink_names or set()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if name in symlink_names:
                # Unix mode bits live in the top 16 bits of external_attr.
                info.external_attr = (0o120777) << 16
            data = content.encode("utf-8") if isinstance(content, str) else content
            archive.writestr(info, data)
    return buffer.getvalue()


class TestRuleCrud:
    def test_create_rule_derives_metadata(self, client: TestClient, analyst_headers, api) -> None:
        response = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["title"] == "Encoded PowerShell Command Execution"
        assert body["severity"] == "high"
        assert body["logsource_product"] == "windows"
        assert body["current_version"] == 1
        assert body["quality_score"] > 0
        assert [t["technique_id"] for t in body["techniques"]] == ["T1059.001"]

    def test_create_rejects_invalid_yaml(self, client: TestClient, analyst_headers, api) -> None:
        response = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": "title: [broken"}
        )
        assert response.status_code == 422

    def test_get_rule(self, client: TestClient, analyst_headers, api) -> None:
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        ).json()
        response = client.get(f"{api}/rules/{created['id']}", headers=analyst_headers)
        assert response.status_code == 200
        assert response.json()["content"].strip().startswith("title:")

    def test_get_missing_rule_is_404(self, client: TestClient, analyst_headers, api) -> None:
        assert client.get(f"{api}/rules/{uuid.uuid4()}", headers=analyst_headers).status_code == 404

    def test_duplicate_creates_independent_rule(
        self, client: TestClient, analyst_headers, api
    ) -> None:
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        ).json()
        copy = client.post(f"{api}/rules/{created['id']}/duplicate", headers=analyst_headers).json()
        assert copy["id"] != created["id"]
        assert "(copy)" in copy["title"]
        assert copy["sigma_id"] != created["sigma_id"], "a copy must not reuse the Sigma id"

    def test_archive_hides_from_default_list(
        self, client: TestClient, analyst_headers, api
    ) -> None:
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        ).json()
        client.post(f"{api}/rules/{created['id']}/archive", headers=analyst_headers)

        visible = client.get(f"{api}/rules", headers=analyst_headers).json()
        assert created["id"] not in [r["id"] for r in visible["items"]]

        with_archived = client.get(
            f"{api}/rules?include_archived=true", headers=analyst_headers
        ).json()
        assert created["id"] in [r["id"] for r in with_archived["items"]]

    def test_analyst_cannot_delete(self, client: TestClient, analyst_headers, api) -> None:
        """Hard delete destroys version history, so it is admin-only."""
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        ).json()
        assert (
            client.delete(f"{api}/rules/{created['id']}", headers=analyst_headers).status_code
            == 403
        )

    def test_admin_can_delete(self, client: TestClient, admin_headers, api) -> None:
        created = client.post(
            f"{api}/rules", headers=admin_headers, json={"content": sample_rule()}
        ).json()
        assert (
            client.delete(f"{api}/rules/{created['id']}", headers=admin_headers).status_code == 200
        )
        assert client.get(f"{api}/rules/{created['id']}", headers=admin_headers).status_code == 404


class TestVersioning:
    def test_update_appends_version(self, client: TestClient, analyst_headers, api) -> None:
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        ).json()
        updated = client.put(
            f"{api}/rules/{created['id']}",
            headers=analyst_headers,
            json={"content": sample_rule("Renamed Detection Rule"), "change_summary": "retitle"},
        ).json()
        assert updated["current_version"] == 2
        assert updated["title"] == "Renamed Detection Rule"

        versions = client.get(
            f"{api}/rules/{created['id']}/versions", headers=analyst_headers
        ).json()
        assert [v["version_number"] for v in versions] == [2, 1]

    def test_identical_content_does_not_create_version(
        self, client: TestClient, analyst_headers, api
    ) -> None:
        content = sample_rule()
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": content}
        ).json()
        updated = client.put(
            f"{api}/rules/{created['id']}", headers=analyst_headers, json={"content": content}
        ).json()
        assert updated["current_version"] == 1

    def test_diff_shows_changes(self, client: TestClient, analyst_headers, api) -> None:
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        ).json()
        client.put(
            f"{api}/rules/{created['id']}",
            headers=analyst_headers,
            json={"content": sample_rule("A Completely Different Title")},
        )
        diff = client.get(
            f"{api}/rules/{created['id']}/diff?from_version=1&to_version=2",
            headers=analyst_headers,
        ).json()
        assert diff["identical"] is False
        assert "A Completely Different Title" in diff["diff"]
        assert diff["diff"].startswith("---")

    def test_restore_appends_rather_than_rewinds(
        self, client: TestClient, analyst_headers, api, db: Session
    ) -> None:
        """Restoring must not rewrite history — that is the whole point of the audit trail."""
        original = sample_rule("Original Title Goes Here")
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": original}
        ).json()
        client.put(
            f"{api}/rules/{created['id']}",
            headers=analyst_headers,
            json={"content": sample_rule("Second Title Goes Here")},
        )
        restored = client.post(
            f"{api}/rules/{created['id']}/versions/1/restore", headers=analyst_headers
        ).json()

        assert restored["current_version"] == 3, "restore should create a new version"
        assert restored["title"] == "Original Title Goes Here"

        stored = (
            db.query(RuleVersion).filter(RuleVersion.rule_id == uuid.UUID(created["id"])).count()
        )
        assert stored == 3

    def test_restore_missing_version_is_404(self, client: TestClient, analyst_headers, api) -> None:
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        ).json()
        assert (
            client.post(
                f"{api}/rules/{created['id']}/versions/99/restore", headers=analyst_headers
            ).status_code
            == 404
        )


class TestSearchAndFilter:
    @pytest.fixture(autouse=True)
    def _seed(self, client: TestClient, analyst_headers, api) -> None:
        client.post(
            f"{api}/rules",
            headers=analyst_headers,
            json={"content": sample_rule("Alpha Windows Detection Rule")},
        )
        client.post(
            f"{api}/rules",
            headers=analyst_headers,
            json={"content": sample_rule("Beta Linux Detection Rule", tag="attack.t1078")},
        )

    def test_search_by_title(self, client: TestClient, analyst_headers, api) -> None:
        found = client.get(f"{api}/rules?search=Alpha", headers=analyst_headers).json()
        assert found["total"] == 1
        assert found["items"][0]["title"].startswith("Alpha")

    def test_filter_by_severity(self, client: TestClient, analyst_headers, api) -> None:
        found = client.get(f"{api}/rules?severity=high", headers=analyst_headers).json()
        assert found["total"] == 2

    def test_filter_by_technique(self, client: TestClient, analyst_headers, api) -> None:
        found = client.get(f"{api}/rules?technique_id=T1078", headers=analyst_headers).json()
        assert found["total"] == 1
        assert found["items"][0]["title"].startswith("Beta")

    def test_filter_by_tag(self, client: TestClient, analyst_headers, api) -> None:
        found = client.get(f"{api}/rules?tag=attack.t1059.001", headers=analyst_headers).json()
        assert found["total"] == 1

    def test_untested_filter(self, client: TestClient, analyst_headers, api) -> None:
        found = client.get(f"{api}/rules?untested=true", headers=analyst_headers).json()
        assert found["total"] == 2, "no tests have been run yet"

    def test_pagination(self, client: TestClient, analyst_headers, api) -> None:
        page = client.get(f"{api}/rules?limit=1&offset=0", headers=analyst_headers).json()
        assert len(page["items"]) == 1
        assert page["total"] == 2

    def test_filter_options_reflect_library(self, client: TestClient, analyst_headers, api) -> None:
        options = client.get(f"{api}/rules/filter-options", headers=analyst_headers).json()
        assert "windows" in options["logsource_products"]
        assert "SentinelForge Tests" in options["authors"]


class TestValidateEndpoint:
    def test_returns_score_and_issues(self, client: TestClient, analyst_headers, api) -> None:
        response = client.post(
            f"{api}/rules/validate", headers=analyst_headers, json={"content": sample_rule()}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["quality_score"] > 0
        assert body["quality_caveat"]
        assert body["query_preview"]

    def test_reports_parse_error_without_500(
        self, client: TestClient, analyst_headers, api
    ) -> None:
        response = client.post(
            f"{api}/rules/validate", headers=analyst_headers, json={"content": "title: [broken"}
        )
        assert response.status_code == 200
        assert response.json()["parse_error"]
        assert response.json()["validation_status"] == "invalid"


class TestYamlImport:
    def test_imports_valid_file(self, client: TestClient, analyst_headers, api) -> None:
        response = client.post(
            f"{api}/rules/import/yaml",
            headers=analyst_headers,
            files={"file": ("rule.yml", sample_rule().encode(), "application/yaml")},
        )
        assert response.status_code == 201
        assert response.json()["title"] == "Encoded PowerShell Command Execution"

    def test_rejects_wrong_extension(self, client: TestClient, analyst_headers, api) -> None:
        response = client.post(
            f"{api}/rules/import/yaml",
            headers=analyst_headers,
            files={"file": ("rule.exe", sample_rule().encode(), "application/octet-stream")},
        )
        assert response.status_code == 415

    def test_rejects_oversized_file(self, client: TestClient, analyst_headers, api) -> None:
        oversized = ("title: x\ndescription: " + "A" * 600_000).encode()
        response = client.post(
            f"{api}/rules/import/yaml",
            headers=analyst_headers,
            files={"file": ("rule.yml", oversized, "application/yaml")},
        )
        assert response.status_code == 413

    def test_rejects_non_utf8(self, client: TestClient, analyst_headers, api) -> None:
        response = client.post(
            f"{api}/rules/import/yaml",
            headers=analyst_headers,
            files={"file": ("rule.yml", b"\xff\xfe\x00invalid", "application/yaml")},
        )
        assert response.status_code == 422


class TestArchiveImportSecurity:
    """The ZIP path is the sharpest input surface in the application."""

    def test_imports_multiple_rules(self, client: TestClient, analyst_headers, api) -> None:
        payload = make_zip(
            {
                "rules/one.yml": sample_rule("First Archive Detection Rule"),
                "rules/two.yml": sample_rule("Second Archive Detection Rule"),
                "README.md": "ignored, not a rule",
            }
        )
        response = client.post(
            f"{api}/rules/import/archive",
            headers=analyst_headers,
            files={"file": ("rules.zip", payload, "application/zip")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["imported_count"] == 2
        assert any(r["reason"] == "not a .yml/.yaml file" for r in body["rejected"])

    def test_rejects_path_traversal(self, client: TestClient, analyst_headers, api) -> None:
        payload = make_zip({"../../../../etc/passwd.yml": sample_rule()})
        body = client.post(
            f"{api}/rules/import/archive",
            headers=analyst_headers,
            files={"file": ("evil.zip", payload, "application/zip")},
        ).json()
        assert body["imported_count"] == 0
        assert "traversal" in body["rejected"][0]["reason"]

    def test_rejects_windows_style_traversal(
        self, client: TestClient, analyst_headers, api
    ) -> None:
        """Backslash separators must not slip past a POSIX-only check."""
        payload = make_zip({"..\\..\\windows\\system32\\evil.yml": sample_rule()})
        body = client.post(
            f"{api}/rules/import/archive",
            headers=analyst_headers,
            files={"file": ("evil.zip", payload, "application/zip")},
        ).json()
        assert body["imported_count"] == 0

    def test_rejects_absolute_path(self, client: TestClient, analyst_headers, api) -> None:
        payload = make_zip({"/etc/cron.d/evil.yml": sample_rule()})
        body = client.post(
            f"{api}/rules/import/archive",
            headers=analyst_headers,
            files={"file": ("evil.zip", payload, "application/zip")},
        ).json()
        assert body["imported_count"] == 0
        assert "absolute" in body["rejected"][0]["reason"]

    def test_rejects_symlink_entries(self, client: TestClient, analyst_headers, api) -> None:
        payload = make_zip({"link.yml": "/etc/passwd"}, symlink_names={"link.yml"})
        body = client.post(
            f"{api}/rules/import/archive",
            headers=analyst_headers,
            files={"file": ("evil.zip", payload, "application/zip")},
        ).json()
        assert body["imported_count"] == 0
        assert "symlink" in body["rejected"][0]["reason"]

    def test_rejects_zip_bomb_by_ratio(self, client: TestClient, analyst_headers, api) -> None:
        """10 MB of repeated bytes compresses to a few KB — a ~1000:1 ratio."""
        payload = make_zip({"bomb.yml": "A" * (10 * 1024 * 1024)})
        response = client.post(
            f"{api}/rules/import/archive",
            headers=analyst_headers,
            files={"file": ("bomb.zip", payload, "application/zip")},
        )
        assert response.status_code == 422
        assert "zip bomb" in response.json()["detail"]

    def test_rejects_too_many_entries(self, client: TestClient, analyst_headers, api) -> None:
        payload = make_zip({f"rule{i}.yml": "title: x" for i in range(600)})
        response = client.post(
            f"{api}/rules/import/archive",
            headers=analyst_headers,
            files={"file": ("many.zip", payload, "application/zip")},
        )
        assert response.status_code == 422
        assert "entries" in response.json()["detail"]

    def test_rejects_non_zip_content(self, client: TestClient, analyst_headers, api) -> None:
        response = client.post(
            f"{api}/rules/import/archive",
            headers=analyst_headers,
            files={"file": ("fake.zip", b"this is not a zip file at all", "application/zip")},
        )
        assert response.status_code == 422
        assert "not a ZIP" in response.json()["detail"]

    def test_malformed_rule_does_not_abort_batch(
        self, client: TestClient, analyst_headers, api
    ) -> None:
        payload = make_zip(
            {"good.yml": sample_rule("Good Archive Detection Rule"), "bad.yml": "title: [broken"}
        )
        body = client.post(
            f"{api}/rules/import/archive",
            headers=analyst_headers,
            files={"file": ("mixed.zip", payload, "application/zip")},
        ).json()
        assert body["imported_count"] == 1
        assert body["rejected_count"] == 1

    def test_oversized_archive_rejected(self, db: Session) -> None:
        with pytest.raises(ImportError_, match="over the"):
            importer.inspect_archive(b"PK\x03\x04" + b"\x00" * (11 * 1024 * 1024))


class TestExport:
    def test_export_single_rule_as_yaml(self, client: TestClient, analyst_headers, api) -> None:
        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        ).json()
        response = client.get(f"{api}/rules/{created['id']}/export", headers=analyst_headers)
        assert response.status_code == 200
        assert "attachment" in response.headers["content-disposition"]
        assert "title:" in response.text

    def test_export_archive_roundtrips(self, client: TestClient, analyst_headers, api) -> None:
        client.post(
            f"{api}/rules",
            headers=analyst_headers,
            json={"content": sample_rule("Roundtrip Detection Rule")},
        )
        response = client.post(f"{api}/rules/export/archive", headers=analyst_headers)
        assert response.status_code == 200

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            names = archive.namelist()
            assert names
            assert all(n.endswith(".yml") for n in names)

    def test_export_is_audited(self, client: TestClient, analyst_headers, api, db: Session) -> None:
        from sentinelforge.models import AuditLog

        created = client.post(
            f"{api}/rules", headers=analyst_headers, json={"content": sample_rule()}
        ).json()
        client.get(f"{api}/rules/{created['id']}/export", headers=analyst_headers)
        assert db.query(AuditLog).filter(AuditLog.action == "rule_export").count() == 1


class TestQualityRecompute:
    def test_service_recomputes_after_tests(self, db: Session, analyst_user) -> None:
        rule = rules_service.create_rule(db, content=sample_rule(), user=analyst_user)
        db.commit()
        before = rule.quality_score

        rules_service.recompute_quality(db, rule)
        assert rule.quality_score == before  # no tests yet, so unchanged
        assert db.query(DetectionRule).count() == 1
