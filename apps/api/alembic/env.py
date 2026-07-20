"""Alembic environment.

`render_item` is the important part. SentinelForge's `GUID` and `JSONBType` are
`TypeDecorator`s that resolve differently per dialect. Left alone, autogenerate would
freeze whatever the *generating* database happened to use — so a migration generated
against SQLite would hard-code `CHAR(32)` and then create the wrong column type on
PostgreSQL. Rendering the decorators by name keeps a single migration correct on both.
"""

from __future__ import annotations

from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import engine_from_config, pool

from sentinelforge.core.config import get_settings
from sentinelforge.core.db import GUID, JSONBType
from sentinelforge.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", get_settings().database_url)

target_metadata = Base.metadata


def render_item(type_: str, obj: Any, autogen_context: Any) -> str | bool:
    if type_ == "type":
        if isinstance(obj, GUID):
            autogen_context.imports.add("import sentinelforge.core.db")
            return "sentinelforge.core.db.GUID()"
        if isinstance(obj, JSONBType):
            autogen_context.imports.add("import sentinelforge.core.db")
            return "sentinelforge.core.db.JSONBType()"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_item=render_item,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_item=render_item,
            compare_type=True,
            # SQLite cannot ALTER most things; batch mode rewrites the table instead.
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
