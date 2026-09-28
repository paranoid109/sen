# ADR 0002: Dual-Database Strategy and Fail-Closed Production Configuration

## Status
Accepted

## Context
A major operational requirement for SentinelX is enabling immediate, zero-configuration local development and standalone test suite execution on any workstation without requiring an active PostgreSQL container, while simultaneously guaranteeing full enterprise PostgreSQL 16 compatibility in production Docker deployments.

Historically, dual-database architectures suffer from subtle divergence:
1. **Datetime Timezone Divergence**: SQLite lacks native timezone-aware DATETIME types, storing naive timestamps or ISO strings. Comparing naive and aware datetimes in Python triggers fatal `TypeError` exceptions.
2. **Interval SQL Syntax Incompatibility**: PostgreSQL supports `NOW() - INTERVAL '60 SECONDS'`, which raises syntax errors in SQLite.
3. **Accidental SQLite in Production**: Misconfigured production deployments could silently default to local SQLite files, risking data loss in container restarts.

## Decision
We implement a **Dual-Database Persistence Layer** using SQLAlchemy 2.0 with asynchronous drivers:
1. **Engine Drivers**:
   * Local Dev / Standalone Tests: `sqlite+aiosqlite:///./sentinelx_dev.db` (or `:memory:` with `StaticPool`).
   * Production: `postgresql+asyncpg://...` (PostgreSQL 16 in Docker).
2. **Fail-Closed Production Policy**:
   * When `APP_ENV=production`, `backend/app/core/config.py` strictly mandates that `DATABASE_URL` starts with `postgresql` and `JWT_SECRET` is not the default development string. If either check fails, the application raises `RuntimeError` and terminates immediately.
3. **Offset-Aware UTC DateTime Enforcement**:
   * All datetime columns use a custom SQLAlchemy `UTCDateTime` TypeDecorator. It normalizes bound parameters to UTC and re-attaches `timezone.utc` to loaded SQLite values, ensuring every loaded datetime is offset-aware.
4. **Dialect-Agnostic Querying**:
   * All sliding-window detection queries compute time boundaries in Python using `timedelta` and bind standard parameters (`WHERE event_time >= :window_start`). Native SQL interval expressions are prohibited.
5. **Test Isolation**:
   * PostgreSQL test suites truncate tables (`TRUNCATE TABLE ... RESTART IDENTITY CASCADE`) between tests.
   * SQLite test suites re-create or truncate tables between tests, ensuring clean state despite independent subscriber sessions.

## Consequences
* **Positive**: Developers can run unit tests and benchmarks instantly on any machine with zero external services; production runs on hardened PostgreSQL with automated health checks.
* **Negative**: Requires discipline to avoid engine-specific SQL features in application code.
