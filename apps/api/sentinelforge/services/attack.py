"""MITRE ATT&CK matrix access.

The matrix is read from a **versioned JSON snapshot committed to the repository**
(`sentinelforge/data/attack_enterprise.json`). Nothing here touches the network: the
brief requires that v1 never collect from external systems automatically, and a
detection platform whose ATT&CK mapping silently shifts under it is worse than one
that is explicitly a version behind.

Refresh it deliberately with `python scripts/refresh_attack.py`.
"""

from __future__ import annotations

import functools
import json
import pathlib
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinelforge.models.attack import AttackTechnique

CACHE_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "attack_enterprise.json"


@dataclass(frozen=True)
class Tactic:
    id: str
    shortname: str
    name: str
    description: str
    url: str | None


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_id: str | None
    platforms: list[str]
    description: str
    url: str | None


@dataclass(frozen=True)
class AttackMatrix:
    version: str
    generated_at: str
    source: str
    attribution: str
    tactics: list[Tactic]
    techniques: list[Technique]

    @functools.cached_property
    def by_id(self) -> dict[str, Technique]:
        return {t.id: t for t in self.techniques}

    def get(self, technique_id: str) -> Technique | None:
        return self.by_id.get(technique_id.upper())

    @functools.cached_property
    def tactic_order(self) -> list[str]:
        """Tactic shortnames in ATT&CK's canonical (kill-chain) order."""
        return [t.shortname for t in self.tactics]


class AttackCacheMissing(RuntimeError):
    pass


@functools.lru_cache(maxsize=1)
def load_matrix() -> AttackMatrix:
    """Load and cache the bundled matrix. Raises if the snapshot is absent."""
    if not CACHE_PATH.exists():
        raise AttackCacheMissing(
            f"ATT&CK cache not found at {CACHE_PATH}. "
            "Regenerate it with: python scripts/refresh_attack.py"
        )
    raw: dict[str, Any] = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    return AttackMatrix(
        version=raw.get("version", "unknown"),
        generated_at=raw.get("generated_at", ""),
        source=raw.get("source", ""),
        attribution=raw.get("attribution", ""),
        tactics=[
            Tactic(
                id=t["id"],
                shortname=t["shortname"],
                name=t["name"],
                description=t.get("description", ""),
                url=t.get("url"),
            )
            for t in raw.get("tactics", [])
        ],
        techniques=[
            Technique(
                id=t["id"],
                name=t["name"],
                tactics=t.get("tactics", []),
                is_subtechnique=t.get("is_subtechnique", False),
                parent_id=t.get("parent_id"),
                platforms=t.get("platforms", []),
                description=t.get("description", ""),
                url=t.get("url"),
            )
            for t in raw.get("techniques", [])
        ],
    )


def sync_techniques(db: Session) -> int:
    """Upsert every cached technique into the database. Idempotent.

    Returns the number of rows created or updated.
    """
    matrix = load_matrix()
    existing = {row.technique_id: row for row in db.scalars(select(AttackTechnique)).all()}
    touched = 0

    for technique in matrix.techniques:
        row = existing.get(technique.id)
        if row is None:
            db.add(
                AttackTechnique(
                    technique_id=technique.id,
                    name=technique.name,
                    tactics=list(technique.tactics),
                    is_subtechnique=technique.is_subtechnique,
                    parent_technique_id=technique.parent_id,
                    platforms=list(technique.platforms),
                    description=technique.description,
                    url=technique.url,
                    attack_version=matrix.version,
                )
            )
            touched += 1
        elif row.attack_version != matrix.version or row.name != technique.name:
            row.name = technique.name
            row.tactics = list(technique.tactics)
            row.is_subtechnique = technique.is_subtechnique
            row.parent_technique_id = technique.parent_id
            row.platforms = list(technique.platforms)
            row.description = technique.description
            row.url = technique.url
            row.attack_version = matrix.version
            touched += 1

    db.flush()
    return touched


def ensure_techniques(db: Session, technique_ids: list[str]) -> list[AttackTechnique]:
    """Resolve technique ids to rows, creating any that are in the cache but not the DB.

    Lets a rule be mapped correctly on import without requiring a full matrix sync
    to have run first. Ids absent from the cache are ignored — an unrecognised tag
    should not invent an ATT&CK technique that does not exist.
    """
    if not technique_ids:
        return []

    matrix = load_matrix()
    wanted = [tid.upper() for tid in technique_ids]

    rows = list(
        db.scalars(select(AttackTechnique).where(AttackTechnique.technique_id.in_(wanted))).all()
    )
    found = {row.technique_id for row in rows}

    for technique_id in wanted:
        if technique_id in found:
            continue
        technique = matrix.get(technique_id)
        if technique is None:
            continue
        row = AttackTechnique(
            technique_id=technique.id,
            name=technique.name,
            tactics=list(technique.tactics),
            is_subtechnique=technique.is_subtechnique,
            parent_technique_id=technique.parent_id,
            platforms=list(technique.platforms),
            description=technique.description,
            url=technique.url,
            attack_version=matrix.version,
        )
        db.add(row)
        rows.append(row)

    db.flush()
    return rows
