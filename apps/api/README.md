# SentinelForge API

FastAPI backend for the SentinelForge detection-engineering platform.

```bash
python -m venv .venv && .venv/Scripts/activate   # Windows
pip install -e ".[dev]"
alembic upgrade head
python -m sentinelforge.seed                     # optional demo data
uvicorn sentinelforge.main:app --reload
```

Interactive API docs: <http://localhost:8000/docs>

See the [root README](../../README.md) for full setup, and
[`docs/api.md`](../../docs/api.md) for the endpoint contract.
