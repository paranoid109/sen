"""SQLAlchemy 2.0 Async Dual-Database Engine & Session Management.

Guarantees dual-database compatibility across SQLite and PostgreSQL 16 (ADR 0002),
enforcing timezone-aware UTC datetimes via custom UTCDateTime TypeDecorator.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import event, types
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from backend.app.core.config import settings


class UTCDateTime(types.TypeDecorator):
    """Custom SQLAlchemy type ensuring datetimes are strictly UTC and offset-aware across engines.

    Prevents SQLite naive/aware comparison crashes and normalizes all timestamp representations.
    """

    impl = types.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if not isinstance(value, datetime):
            raise TypeError(f"Expected datetime object or ISO string, got {type(value)}")
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(AsyncAttrs, DeclarativeBase):
    """Declarative Base class for all SentinelX SQLAlchemy 2.0 models."""

    pass


# Engine & Session Maker Factory
def create_engine_and_session(
    database_url: str,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    is_sqlite = "sqlite" in database_url.lower()

    connect_args: dict[str, Any] = {}
    if is_sqlite:
        connect_args["check_same_thread"] = False

    engine = create_async_engine(
        database_url,
        echo=settings.DEBUG,
        connect_args=connect_args,
        future=True,
    )

    if is_sqlite:
        # Enforce foreign key constraints on SQLite connections only
        @event.listens_for(engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
            if "sqlite" in type(dbapi_connection).__module__:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    return engine, session_factory


engine, async_session_factory = create_engine_and_session(settings.DATABASE_URL)


async def get_db() -> AsyncGenerator[AsyncSession]:
    """FastAPI dependency yielding an isolated async database session."""
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db(target_engine: AsyncEngine | None = None) -> None:
    """Create all tables in the target database."""
    eng = target_engine or engine
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db(target_engine: AsyncEngine | None = None) -> None:
    """Dispose of database engine connections on shutdown."""
    eng = target_engine or engine
    await eng.dispose()
