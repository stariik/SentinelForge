# SentinelForge — Delivery Plan

Phased milestones. Each phase ends with **format → lint → typecheck → test**, and failures are
fixed before the next phase starts.

Status: `[ ]` todo · `[~]` in progress · `[x]` done

---

## Phase 0 — Foundation & design  `[x]`

- [x] Inspect repository (empty; git initialised)
- [x] Verify toolchain: Node 25.9, Python 3.14, gh authenticated, **no Docker locally**
- [x] Dependency compatibility probe on Python 3.14
  - [x] pySigma 1.4.0 parses rules and exposes a walkable condition AST
  - [x] passlib 1.7.4 **broken** with bcrypt 5.0 → use `bcrypt` directly
- [x] `ARCHITECTURE.md`
- [x] `TASKS.md`
- [x] Bundle versioned ATT&CK cache (v19.1 · 15 tactics · 697 techniques) + `scripts/refresh_attack.py`
- [x] Database schema contract → `docs/database.md`
- [x] API contract → generated OpenAPI at `/openapi.json` and `/docs`
- [x] Security risk register → `docs/threat-model.md`

## Phase 1 — Backend foundation  `[x]`

- [x] `pyproject.toml` with pinned dependencies; ruff + mypy config
- [x] Settings via `pydantic-settings`; refuse placeholder `SECRET_KEY` outside dev
- [x] `GUID` / `JSONBType` portability decorators (PostgreSQL ↔ SQLite)
- [x] All 12 SQLAlchemy models with indexes and constraints
- [x] Alembic environment + initial migration
- [x] Password hashing (bcrypt over SHA-256 pre-hash), JWT access/refresh, `jti` denylist
- [x] RBAC dependencies (`admin` / `analyst`), default-deny
- [x] Auth rate limiting + account lockout
- [x] Audit log service
- [x] Verify: ruff, mypy, pytest

## Phase 2 — Sigma core  `[x]`

- [x] Safe YAML loading (bounded size/depth, `safe_load` only)
- [x] Rule parsing → metadata extraction (title, id, status, level, logsource, tags, refs, FPs)
- [x] Validation via pySigma's 31 core validators + SentinelForge checks
- [x] Explainable quality score (9 weighted criteria, per-criterion reasons)
- [x] Sigma → query conversion, in-process (no subprocess)
- [x] Verify: ruff, mypy, pytest

## Phase 3 — Rule management  `[x]`

- [x] CRUD + duplicate + archive + hard delete
- [x] Immutable version history on every content change
- [x] Unified diff between any two versions
- [x] Restore a previous version (as a new version — history is never rewritten)
- [x] Single-file YAML import
- [x] ZIP import: traversal, symlink, entry-count, size and zip-bomb defences
- [x] YAML export (single + bulk)
- [x] Search/filter: title, status, severity, logsource, author, tags, technique
- [x] Verify: ruff, mypy, pytest

## Phase 4 — Ingestion & normalization  `[ ]`

- [ ] Normalized event schema
- [ ] Format detection + 5 parsers (generic JSON/JSONL, Windows EVTX-JSON, Sysmon, Linux auth, web access)
- [ ] Dataset upload with size/type/count limits; lossless `raw_event` retention
- [ ] Field taxonomy (Sigma field → normalized column → raw fallback)
- [ ] Verify: ruff, mypy, pytest

## Phase 5 — Detection engine  `[ ]`

- [ ] AST evaluator over pySigma condition tree
- [ ] All value types: String, Number, Null, Regex, CIDR, Compare, Expansion, keywords
- [ ] Match trace → human-readable condition explanation + matched fields
- [ ] Unresolved-field reporting (blind-rule detection)
- [ ] Test runs: counts, timing, expected vs actual, FP/FN labelling
- [ ] Correlation (functional minimum): `event_count` / `value_count` with group-by + timespan
- [ ] Run bounds (max events, time budget, regex complexity ceiling)
- [ ] Verify: ruff, mypy, pytest

## Phase 6 — ATT&CK coverage  `[ ]`

- [ ] Load cached matrix; tactic-alias map for the v19 *Defense Evasion → Stealth* rename
- [ ] Technique sync into DB
- [ ] Coverage states: covered / partial / uncovered, with rules per technique
- [ ] Coverage snapshots + two-snapshot comparison
- [ ] Explicit caveat that rule count ≠ detection efficacy
- [ ] Verify: ruff, mypy, pytest

## Phase 7 — Incident replay  `[ ]`

- [ ] Scenario + incident event models and API
- [ ] Timeline with detections joined per event
- [ ] Filters: host, user, severity, technique, detected/undetected
- [ ] Analyst notes
- [ ] Verify: ruff, mypy, pytest

## Phase 8 — Dashboard  `[ ]`

- [ ] Aggregate endpoint: active rules, untested, failing validation, severity mix,
      detection success rate, ATT&CK coverage, recent changes, recent runs, gaps,
      quality distribution
- [ ] Seeded data clearly labelled; no fabricated real-time claims
- [ ] Verify: ruff, mypy, pytest

## Phase 9 — Demo content  `[ ]`

- [ ] 3 synthetic datasets (PowerShell execution · brute force → success · web shell)
- [ ] 16 original demonstration rules, labelled educational
- [ ] Rule tests with expected outcomes
- [ ] Seed CLI (`python -m sentinelforge.seed`) — demo credentials only here, never by default
- [ ] Verify: ruff, mypy, pytest

## Phase 10 — Frontend  `[ ]`

- [ ] Next.js 16 + Tailwind 4 design system, dark/light via CSS variables
- [ ] Accessible primitives (button, input, table, dialog, badge, toast, tabs…)
- [ ] Auth flow + protected routes
- [ ] Dashboard with charts
- [ ] Rule list (filter/sort/paginate) + detail + editor + version diff
- [ ] Import / export UI
- [ ] Detection test runner + results view
- [ ] Incident replay timeline with playback controls
- [ ] ATT&CK heatmap + snapshot comparison
- [ ] Loading / empty / error states; destructive-action confirmation
- [ ] Verify: format, lint, typecheck, component tests, build

## Phase 11 — Test suite  `[ ]`

- [ ] Backend unit tests
- [ ] API integration tests
- [ ] Rule-validation tests
- [ ] Event-normalization tests
- [ ] Detection-engine tests
- [ ] Security tests: malformed YAML, oversized upload, ZIP traversal, zip bomb,
      invalid JSON, authz failure, rate limiting
- [ ] Frontend component tests
- [ ] End-to-end workflow test
- [ ] Verify: full suite green

## Phase 12 — Packaging & docs  `[ ]`

- [ ] Dockerfiles + `docker-compose.yml` (PostgreSQL 16)
- [x] GitHub Actions: backend lint, format, typecheck, and tests
- [x] `README.md`
- [ ] `docs/`: threat model, database, API, walkthrough, roadmap, portfolio, interview notes
- [ ] Screenshots section
- [ ] Security limitations documented

## Phase 13 — Publish  `[ ]`

- [x] `.gitignore`, `LICENSE`, `.env.example`
- [x] Commit history
- [ ] Create GitHub repository and push

---

## Deviations from the original brief

Recorded deliberately rather than silently.

| Brief item | Decision |
|---|---|
| "Redis when genuinely needed" | **Not used.** No workload currently justifies it; extension point documented in `ARCHITECTURE.md` §7 |
| "Execute external tools with fixed argument arrays" | **Stronger:** no subprocess at all. Sigma parsing/conversion is in-process, removing the injection class outright |
| "At least 12 demo rules" | 16 delivered |
| passlib for hashing | Replaced with `bcrypt` directly — passlib 1.7.4 is unmaintained and broken against bcrypt 5.x |
| Docker verification | Compose files authored and syntax-checked, but **not run** — Docker is unavailable in the build environment. Test suite runs on SQLite to stay hermetic |
