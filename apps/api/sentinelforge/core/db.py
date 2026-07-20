"""Database engine, session management, and dialect portability.

SentinelForge uses **synchronous** SQLAlchemy. Detection runs are CPU-bound (regex
evaluation over event batches), so an async driver would buy nothing while making the
data layer harder to type. FastAPI executes sync path operations in a threadpool, which
is the right shape for this workload.

The two `TypeDecorator`s below let the identical model definitions run on PostgreSQL
(deployment) and SQLite (hermetic tests) without forking the schema.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Generator
from typing import Any, ClassVar, cast

from sqlalchemy import CHAR, DateTime, Engine, TypeDecorator, create_engine, event, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import JSON, TypeEngine

from sentinelforge.core.config import get_settings


class GUID(TypeDecorator[uuid.UUID]):
    """UUID column: native `uuid` on PostgreSQL, 32-char hex on everything else."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> TypeEngine[Any]:
        if dialect.name == "postgresql":
            return cast(TypeEngine[Any], dialect.type_descriptor(PGUUID(as_uuid=True)))
        return cast(TypeEngine[Any], dialect.type_descriptor(CHAR(32)))

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, uuid.UUID):
            value = uuid.UUID(str(value))
        if dialect.name == "postgresql":
            return value
        return value.hex

    def process_result_value(self, value: Any, dialect: Any) -> uuid.UUID | None:
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class JSONBType(TypeDecorator[Any]):
    """JSON column: `JSONB` on PostgreSQL, generic `JSON` elsewhere."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> TypeEngine[Any]:
        if dialect.name == "postgresql":
            return cast(TypeEngine[Any], dialect.type_descriptor(JSONB()))
        return cast(TypeEngine[Any], dialect.type_descriptor(JSON()))


class Base(DeclarativeBase):
    """Declarative base with a shared type map."""

    type_annotation_map: ClassVar[dict[Any, Any]] = {
        uuid.UUID: GUID,
        dict[str, Any]: JSONBType,
        list[Any]: JSONBType,
        list[str]: JSONBType,
    }


class UUIDPrimaryKeyMixin:
    """UUID primary keys — identifiers must not be enumerable."""

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


def _is_memory_sqlite(url: str) -> bool:
    """True for `sqlite://` and `sqlite:///:memory:`.

    The bare `sqlite://` form is in-memory too — a naive `":memory:" in url` check
    misses it and hands every connection its own empty database.
    """
    if not url.startswith("sqlite"):
        return False
    path = url.split("://", 1)[1] if "://" in url else ""
    return path in ("", "/") or ":memory:" in path


def build_engine(url: str | None = None, *, echo: bool | None = None) -> Engine:
    settings = get_settings()
    url = url or settings.database_url
    echo = settings.database_echo if echo is None else echo

    if url.startswith("sqlite"):
        engine = create_engine(
            url,
            echo=echo,
            future=True,
            connect_args={"check_same_thread": False},
            # In-memory SQLite must reuse one connection or each session sees a fresh,
            # empty database.
            poolclass=StaticPool if _is_memory_sqlite(url) else None,
        )

        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
            """SQLite ignores foreign keys unless asked.

            Without this, `ON DELETE CASCADE`/`SET NULL` silently do nothing and the
            test suite would happily pass on referential behaviour that PostgreSQL
            actually enforces in production.
            """
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    return create_engine(url, echo=echo, future=True, pool_pre_ping=True)


_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = build_engine()
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)
    return _SessionFactory


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a session that always closes."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def reset_engine_for_tests(engine: Engine) -> None:
    """Point the module-level engine at a test database."""
    global _engine, _SessionFactory
    _engine = engine
    _SessionFactory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
