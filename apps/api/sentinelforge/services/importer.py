"""Rule import: single Sigma YAML files and ZIP archives.

Archives are the sharpest input surface in the application — an analyst pulling a rule
pack off a public repository is handing this code bytes that nobody vetted. Every
defence here runs **before** decompression where possible, using header metadata, and
is re-checked while streaming because a ZIP header is attacker-controlled and can lie.

Nothing is ever written to disk. Entries are read into bounded memory buffers, so
path traversal cannot land a file anywhere even if a name check were missed.
"""

from __future__ import annotations

import io
import posixpath
import zipfile
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from sentinelforge.core.config import get_settings
from sentinelforge.models.rule import DetectionRule
from sentinelforge.models.user import User
from sentinelforge.services import rules as rules_service
from sentinelforge.services.sigma_service import SigmaParseError

ZIP_MAGIC = b"PK\x03\x04"
ALLOWED_SUFFIXES = (".yml", ".yaml")
# ZIP stores the symlink bit in the high 16 bits of external_attr (Unix st_mode).
S_IFLNK = 0o120000
S_IFMT = 0o170000


class ImportError_(ValueError):
    """Import could not proceed. Named with a trailing underscore to avoid shadowing."""


@dataclass
class ImportedRule:
    filename: str
    rule_id: str
    title: str


@dataclass
class RejectedEntry:
    filename: str
    reason: str


@dataclass
class ImportReport:
    imported: list[ImportedRule] = field(default_factory=list)
    rejected: list[RejectedEntry] = field(default_factory=list)

    @property
    def imported_count(self) -> int:
        return len(self.imported)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    def as_dict(self) -> dict[str, Any]:
        return {
            "imported_count": self.imported_count,
            "rejected_count": self.rejected_count,
            "imported": [
                {"filename": i.filename, "rule_id": i.rule_id, "title": i.title}
                for i in self.imported
            ],
            "rejected": [{"filename": r.filename, "reason": r.reason} for r in self.rejected],
        }


# --------------------------------------------------------------------------
# Single file
# --------------------------------------------------------------------------


def import_rule_yaml(
    db: Session, *, content: str, user: User | None, filename: str = "", is_demo: bool = False
) -> DetectionRule:
    """Import one Sigma YAML document. Raises `SigmaParseError` if it is not a rule."""
    return rules_service.create_rule(
        db,
        content=content,
        user=user,
        is_demo=is_demo,
        change_summary=f"Imported from {filename}" if filename else "Imported",
    )


# --------------------------------------------------------------------------
# Archive safety
# --------------------------------------------------------------------------


def _is_unsafe_path(name: str) -> str | None:
    """Return a rejection reason for a hostile archive entry name, else None."""
    if not name or name.endswith("/"):
        return "directory entry"

    # Normalise separators first: a Windows-style '..\\..\\x' must not slip past a
    # POSIX-only check.
    unified = name.replace("\\", "/")

    if unified.startswith("/"):
        return "absolute path"
    if len(unified) > 1 and unified[1] == ":":
        return "drive-qualified absolute path"
    if any(part == ".." for part in unified.split("/")):
        return "path traversal segment"

    # Belt and braces: even after the checks above, confirm the normalised path
    # cannot climb out of a notional extraction root.
    normalised = posixpath.normpath(unified)
    if normalised.startswith(("../", "/")) or normalised == "..":
        return "path escapes archive root"

    if not unified.lower().endswith(ALLOWED_SUFFIXES):
        return "not a .yml/.yaml file"
    return None


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return (info.external_attr >> 16) & S_IFMT == S_IFLNK


def inspect_archive(data: bytes) -> zipfile.ZipFile:
    """Open an archive after validating its shape. Raises `ImportError_` if hostile."""
    settings = get_settings()

    if len(data) > settings.max_upload_bytes:
        raise ImportError_(
            f"Archive is {len(data)} bytes, over the {settings.max_upload_bytes} byte limit"
        )
    if not data.startswith(ZIP_MAGIC):
        raise ImportError_("File is not a ZIP archive")

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ImportError_(f"Archive is corrupt or unreadable: {exc}") from exc

    entries = archive.infolist()
    if len(entries) > settings.max_zip_entries:
        raise ImportError_(
            f"Archive declares {len(entries)} entries, over the {settings.max_zip_entries} limit"
        )

    # Zip-bomb check from the central directory, before decompressing anything.
    declared_total = sum(e.file_size for e in entries)
    if declared_total > settings.max_zip_total_uncompressed_bytes:
        raise ImportError_(
            f"Archive expands to {declared_total} bytes, over the "
            f"{settings.max_zip_total_uncompressed_bytes} byte limit"
        )

    compressed_total = sum(e.compress_size for e in entries) or 1
    if declared_total / compressed_total > settings.max_zip_compression_ratio:
        raise ImportError_(
            f"Archive compression ratio {declared_total // compressed_total}:1 exceeds the "
            f"{settings.max_zip_compression_ratio}:1 limit, which indicates a zip bomb"
        )
    return archive


def import_rule_archive(
    db: Session, *, data: bytes, user: User | None, is_demo: bool = False
) -> ImportReport:
    """Import every safe Sigma rule in a ZIP archive.

    Individual bad entries are rejected and reported rather than aborting the import —
    one malformed rule in a pack of two hundred should not cost the analyst the other
    hundred and ninety-nine.
    """
    settings = get_settings()
    archive = inspect_archive(data)
    report = ImportReport()
    consumed = 0

    for info in archive.infolist():
        if _is_symlink(info):
            report.rejected.append(RejectedEntry(info.filename, "symlink entries are not allowed"))
            continue

        reason = _is_unsafe_path(info.filename)
        if reason is not None:
            if reason != "directory entry":
                report.rejected.append(RejectedEntry(info.filename, reason))
            continue

        if info.file_size > settings.max_yaml_bytes:
            report.rejected.append(
                RejectedEntry(info.filename, f"entry exceeds {settings.max_yaml_bytes} bytes")
            )
            continue

        # The header said file_size; read one byte past the cap to catch it lying.
        try:
            with archive.open(info) as handle:
                raw = handle.read(settings.max_yaml_bytes + 1)
        except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
            report.rejected.append(RejectedEntry(info.filename, f"unreadable entry: {exc}"))
            continue

        if len(raw) > settings.max_yaml_bytes:
            report.rejected.append(
                RejectedEntry(info.filename, "actual size exceeds the declared header size")
            )
            continue

        consumed += len(raw)
        if consumed > settings.max_zip_total_uncompressed_bytes:
            report.rejected.append(RejectedEntry(info.filename, "archive total size limit reached"))
            break

        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            report.rejected.append(RejectedEntry(info.filename, "entry is not valid UTF-8"))
            continue

        try:
            rule = import_rule_yaml(
                db, content=content, user=user, filename=info.filename, is_demo=is_demo
            )
        except SigmaParseError as exc:
            report.rejected.append(RejectedEntry(info.filename, str(exc)))
            continue

        report.imported.append(
            ImportedRule(filename=info.filename, rule_id=str(rule.id), title=rule.title)
        )

    return report


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------


def export_rules_archive(rules: list[DetectionRule]) -> bytes:
    """Bundle rules as a ZIP of YAML files with collision-safe names."""
    buffer = io.BytesIO()
    used: set[str] = set()

    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for rule in rules:
            stem = (
                "".join(
                    ch if ch.isalnum() or ch in "-_" else "_" for ch in rule.title.lower()
                ).strip("_")[:80]
                or "rule"
            )
            name = f"{stem}.yml"
            counter = 2
            while name in used:
                name = f"{stem}-{counter}.yml"
                counter += 1
            used.add(name)
            archive.writestr(name, rule.content)

    return buffer.getvalue()
