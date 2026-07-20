#!/usr/bin/env python3
"""Regenerate the bundled MITRE ATT&CK Enterprise cache.

SentinelForge never contacts MITRE at runtime. The application reads a versioned
JSON snapshot committed to the repository at
``apps/api/sentinelforge/data/attack_enterprise.json``. This script is the *only*
thing that talks to the network, and a maintainer runs it deliberately.

Usage
-----
    # download the current official bundle and regenerate the cache
    python scripts/refresh_attack.py

    # regenerate from a bundle already on disk (fully offline)
    python scripts/refresh_attack.py --bundle ./enterprise-attack.json

Source
------
https://github.com/mitre-attack/attack-stix-data (STIX 2.1)

ATT&CK(R) is a registered trademark of The MITRE Corporation. Data is used under the
ATT&CK Terms of Use: https://attack.mitre.org/resources/terms-of-use/
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import urllib.request

DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_OUTPUT = (
    pathlib.Path(__file__).resolve().parents[1]
    / "apps"
    / "api"
    / "sentinelforge"
    / "data"
    / "attack_enterprise.json"
)

# MITRE descriptions embed reference markers; they add bulk without adding meaning here.
CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
WHITESPACE_RE = re.compile(r"\s+")
DESCRIPTION_LIMIT = 400


def _clean(text: str, limit: int = DESCRIPTION_LIMIT) -> str:
    text = CITATION_RE.sub("", text or "")
    text = WHITESPACE_RE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _attack_url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def _is_live(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def build_cache(bundle: dict, source_url: str) -> dict:
    objects = bundle.get("objects", [])

    version = next(
        (o.get("x_mitre_version") for o in objects if o.get("type") == "x-mitre-collection"),
        "unknown",
    )

    tactics = []
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic" or not _is_live(obj):
            continue
        tactic_id = _attack_id(obj)
        shortname = obj.get("x_mitre_shortname")
        if not tactic_id or not shortname:
            continue
        tactics.append(
            {
                "id": tactic_id,
                "shortname": shortname,
                "name": obj["name"],
                "description": _clean(obj.get("description", ""), 240),
                "url": _attack_url(obj),
            }
        )
    tactics.sort(key=lambda t: t["id"])

    known_tactics = {t["shortname"] for t in tactics}

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _is_live(obj):
            continue
        if "enterprise-attack" not in obj.get("x_mitre_domains", ["enterprise-attack"]):
            continue
        technique_id = _attack_id(obj)
        if not technique_id:
            continue

        phases = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name") in known_tactics
        ]
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        techniques.append(
            {
                "id": technique_id,
                "name": obj["name"],
                "tactics": phases,
                "is_subtechnique": is_sub,
                "parent_id": technique_id.split(".")[0] if is_sub else None,
                "platforms": obj.get("x_mitre_platforms", []),
                "description": _clean(obj.get("description", "")),
                "url": _attack_url(obj),
            }
        )
    techniques.sort(key=lambda t: (t["id"].split(".")[0], t["id"]))

    return {
        "domain": "enterprise-attack",
        "version": version,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "source": source_url,
        "attribution": (
            "ATT&CK(R) is a registered trademark of The MITRE Corporation. Used under the "
            "ATT&CK Terms of Use: https://attack.mitre.org/resources/terms-of-use/"
        ),
        "tactic_count": len(tactics),
        "technique_count": len(techniques),
        "tactics": tactics,
        "techniques": techniques,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", type=pathlib.Path, help="local STIX bundle (skips download)")
    parser.add_argument("--url", default=DEFAULT_URL, help="STIX bundle URL")
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    if args.bundle:
        print(f"reading {args.bundle}", file=sys.stderr)
        raw = args.bundle.read_text(encoding="utf-8")
        source = str(args.bundle)
    else:
        print(f"downloading {args.url}", file=sys.stderr)
        with urllib.request.urlopen(args.url, timeout=300) as response:  # noqa: S310 - fixed https URL
            raw = response.read().decode("utf-8")
        source = args.url

    cache = build_cache(json.loads(raw), source)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(cache, indent=1, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )

    size_kb = args.output.stat().st_size / 1024
    print(
        f"wrote {args.output} — ATT&CK v{cache['version']}, "
        f"{cache['tactic_count']} tactics, {cache['technique_count']} techniques, {size_kb:.0f} KB",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
