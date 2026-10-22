"""Global Pytest Fixtures and Async Test Harness.

Configures an isolated in-memory SQLite database with StaticPool for async tests,
provides test sessions, and sets up test HTTP clients.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.app.core.database import Base, get_db
from backend.app.core.dispatcher import dispatcher
from backend.app.main import app

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def test_engine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AsyncGenerator[AsyncEngine]:
    """Creates an isolated database engine (PostgreSQL if TEST_DATABASE_URL set, else SQLite with WAL)."""
    test_db_url = os.getenv("TEST_DATABASE_URL")
    is_postgres = bool(test_db_url and "postgres" in test_db_url.lower())

    if is_postgres:
        engine = create_async_engine(test_db_url)
    else:
        db_file = tmp_path / "test.db"
        db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
        engine = create_async_engine(
            db_url,
            connect_args={"check_same_thread": False, "timeout": 30},
        )

        @event.listens_for(engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
            if "sqlite" in type(dbapi_connection).__module__:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.close()

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    monkeypatch.setattr("backend.app.core.database.engine", engine)
    monkeypatch.setattr("backend.app.core.database.async_session_factory", session_factory)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        if is_postgres:
            # PostgreSQL: truncate all tables restarting identity cascade
            tables = [f'"{table.name}"' for table in Base.metadata.sorted_tables]
            if tables:
                await conn.execute(text(f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE"))
        else:
            await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(test_engine: AsyncEngine) -> AsyncGenerator[AsyncSession]:
    """Yields a transactional test session, cleaned up after each test."""
    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client(test_engine: AsyncEngine) -> AsyncGenerator[AsyncClient]:
    """Test HTTP client with overridden database dependency."""
    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )

    async def override_get_db() -> AsyncGenerator[AsyncSession]:
        async with session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
async def clean_dispatcher() -> AsyncGenerator[None]:
    """Ensures the event dispatcher state and service locks are reset before and after every test."""
    dispatcher.clear()
    from backend.app.services.audit_service import audit_service
    from backend.app.services.detection_service import detection_service

    detection_service._lock = None
    audit_service._lock = None
    dispatcher.subscribe("*", detection_service.handle_event)
    yield
    await dispatcher.drain(timeout=5.0)
    dispatcher.clear()
    detection_service._lock = None
    audit_service._lock = None
