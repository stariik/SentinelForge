# SentinelForge API

FastAPI backend for SentinelForge's authenticated Sigma rule library.

From this directory:

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m alembic upgrade head
python -m uvicorn sentinelforge.main:app --reload
```

Copy `../../.env.example` to `.env` before applying migrations. PostgreSQL is the
deployment target; set `DATABASE_URL=sqlite:///./sentinelforge.db` for local SQLite.

Interactive API docs are generated at <http://localhost:8000/docs>. See the
[root README](../../README.md) for complete setup, administrator bootstrapping,
security notes, and project status.
