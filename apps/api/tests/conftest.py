"""Shared pytest fixtures.

The whole suite runs on in-memory SQLite so it needs no containers and no network.
Environment variables are set before any SentinelForge module is imported, because
`get_settings()` is cached on first call.
"""

from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-for-hs256-signing")
os.environ.setdefault("DATABASE_URL", "sqlite://")
# Keep bcrypt cheap in tests; production cost is set by config default.
os.environ.setdefault("BCRYPT_ROUNDS", "10")

import uuid
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from sentinelforge.core.config import get_settings
from sentinelforge.core.db import build_engine, get_db, reset_engine_for_tests
from sentinelforge.core.rate_limit import reset_login_limiter
from sentinelforge.main import create_app
from sentinelforge.models import Base, User, UserRole
from sentinelforge.services.auth import create_user

# RFC 2606 reserves example.com for documentation and testing. `.test` is also
# reserved but email-validator rejects it as a special-use domain, which is correct.
ADMIN_EMAIL = "admin@example.com"
ANALYST_EMAIL = "analyst@example.com"
TEST_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def engine() -> Generator[Engine, None, None]:
    eng = build_engine("sqlite://")
    Base.metadata.create_all(eng)
    reset_engine_for_tests(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def db(engine: Engine) -> Generator[Session, None, None]:
    from sentinelforge.core.db import get_session_factory

    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _reset_limiter() -> Generator[None, None, None]:
    reset_login_limiter()
    yield
    reset_login_limiter()


@pytest.fixture
def client(engine: Engine, db: Session) -> Generator[TestClient, None, None]:
    app = create_app()

    def _override_get_db() -> Generator[Session, None, None]:
        yield db

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin_user(db: Session) -> User:
    user = create_user(
        db,
        email=ADMIN_EMAIL,
        password=TEST_PASSWORD,
        full_name="Test Admin",
        role=UserRole.ADMIN,
    )
    db.commit()
    return user


@pytest.fixture
def analyst_user(db: Session) -> User:
    user = create_user(
        db,
        email=ANALYST_EMAIL,
        password=TEST_PASSWORD,
        full_name="Test Analyst",
        role=UserRole.ANALYST,
    )
    db.commit()
    return user


def _login(client: TestClient, email: str) -> dict[str, str]:
    response = client.post(
        f"{get_settings().api_v1_prefix}/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def admin_headers(client: TestClient, admin_user: User) -> dict[str, str]:
    return _login(client, admin_user.email)


@pytest.fixture
def analyst_headers(client: TestClient, analyst_user: User) -> dict[str, str]:
    return _login(client, analyst_user.email)


@pytest.fixture
def api(client: TestClient) -> str:
    """Convenience: the versioned API prefix."""
    return get_settings().api_v1_prefix


@pytest.fixture
def unique_email() -> str:
    return f"user-{uuid.uuid4().hex[:8]}@example.com"
